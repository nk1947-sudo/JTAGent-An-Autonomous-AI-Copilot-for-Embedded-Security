import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Protocol

from fixtures.synthetic import segments


class BackendError(Exception):
    def __init__(self, code, uncertain=False):
        self.code, self.uncertain = code, uncertain
        super().__init__(code)


class Backend(Protocol):
    mode: str
    generation: int

    async def status(self) -> str: ...
    async def read(self, address: int, length: int, space: str) -> bytes: ...
    async def registers(self, names: list[str]) -> dict[str, int]: ...
    async def control(self, operation: str): ...
    async def write(self, address: int, data: bytes): ...


class MockBackend:
    mode = "mock"

    def __init__(self, variant="demo"):
        self.memory = segments(variant)
        self.state, self.generation = "running", 0
        self.regs = {"pc": 0x80000000, "lr": 0x80000008, "sp": 0x800011F0, "cpsr": 0x13}

    async def status(self):
        return self.state

    async def read(self, address, length, space):
        for start, data in self.memory.items():
            if start <= address < start + len(data):
                return bytes(data[address - start : address - start + length])
        raise BackendError("unreadable")

    async def registers(self, names):
        if any(n not in self.regs for n in names):
            raise BackendError("register_unavailable")
        return {n: self.regs[n] for n in names}

    async def control(self, operation):
        if operation == "step":
            if self.state != "halted":
                raise BackendError("target_not_halted")
            self.regs["pc"] += 4
        self.state = "running" if operation == "resume" else "halted"
        self.generation += 1

    async def write(self, address, data):
        for start, content in self.memory.items():
            if start <= address and address + len(data) <= start + len(content):
                content[address - start : address - start + len(data)] = data
                self.generation += 1
                return
        raise BackendError("unreadable")


class ReplayBackend(MockBackend):
    mode = "replay"

    def __init__(self, manifest_path):
        manifest = json.loads(Path(manifest_path).read_text())
        if not {"provenance", "captured_at", "segments", "registers", "profile"} <= manifest.keys():
            raise ValueError("Replay manifest missing capture attribution")
        self.manifest, self.memory = manifest, {}
        for segment in manifest["segments"]:
            data = bytes.fromhex(segment["hex"])
            if hashlib.sha256(data).hexdigest() != segment["sha256"]:
                raise ValueError("Replay hash mismatch")
            start = segment["address"]
            if type(start) is not int or start < 0 or start + len(data) > 2**32:
                raise ValueError("Invalid replay range")
            if any(start < s + len(d) and s < start + len(data) for s, d in self.memory.items()):
                raise ValueError("Overlapping replay segments")
            self.memory[start] = bytearray(data)
        self.regs = manifest["registers"]
        if any(type(v) is not int or not 0 <= v < 2**32 for v in self.regs.values()):
            raise ValueError("Invalid replay register")
        self.state, self.generation = "captured", 0

    async def control(self, operation):
        raise BackendError("replay_read_only")

    async def write(self, address, data):
        raise BackendError("replay_read_only")


class TclRPC:
    """Serial command channel with bounded frames; unsolicited frames fail closed."""

    def __init__(self, host="127.0.0.1", port=6666, timeout=2):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("MVP debugger transport must use loopback")
        self.host, self.port, self.timeout = host, port, timeout
        self.reader = self.writer = None
        self.buffer = b""
        self.lock = asyncio.Lock()

    async def close(self):
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except OSError:
                pass
        self.reader = self.writer = None
        self.buffer = b""

    async def command(self, command, changing=False):
        async with self.lock:
            try:
                async with asyncio.timeout(self.timeout):
                    if self.writer is None:
                        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
                    if self.buffer:
                        raise BackendError("unexpected_rpc_frame", changing)
                    self.writer.write(command.encode("ascii") + b"\x1a")
                    await self.writer.drain()
                    while b"\x1a" not in self.buffer:
                        packet = await self.reader.read(8192)
                        if not packet:
                            raise BackendError("rpc_disconnected", changing)
                        self.buffer += packet
                        if len(self.buffer) > 65536:
                            raise BackendError("rpc_reply_too_large", changing)
                    frame, self.buffer = self.buffer.split(b"\x1a", 1)
                    if self.buffer:
                        raise BackendError("unexpected_rpc_frame", changing)
                    response = frame.decode("ascii").strip()
                    if response.startswith(("Error", "error", "invalid command", "wrong #")):
                        raise BackendError("debugger_command_failed", changing)
                    return response
            except asyncio.CancelledError:
                await self.close()
                raise
            except (OSError, TimeoutError, UnicodeError, BackendError) as exc:
                await self.close()
                if isinstance(exc, BackendError):
                    raise
                raise BackendError("rpc_unavailable", changing) from None


class OpenOCDBackend:
    mode = "openocd"

    def __init__(self, rpc, target, version_prefix):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", target):
            raise ValueError("Invalid configured target")
        if not version_prefix:
            raise ValueError("OPENOCD_VERSION_PREFIX required after local command review")
        self.rpc, self.target, self.version_prefix = rpc, target, version_prefix
        self.generation, self.ready = 0, False

    async def status(self):
        if not self.ready:
            version = await self.rpc.command("version")
            if not version.startswith(self.version_prefix):
                raise BackendError("openocd_version_mismatch")
            await self.rpc.command("tcl notifications off")
            await self.rpc.command("tcl trace off")
            self.ready = True
        state = await self.rpc.command(f"{self.target} curstate")
        if state not in ("running", "halted", "reset", "unknown"):
            raise BackendError("malformed_target_state")
        return state

    async def read(self, address, length, space):
        suffix = " phys" if space == "physical" else ""
        reply = await self.rpc.command(f"{self.target} read_memory {address} 8 {length}{suffix}")
        try:
            numbers = [int(n, 0) for n in reply.split()]
            if len(numbers) > length:
                raise ValueError()
            return bytes(numbers)
        except ValueError:
            raise BackendError("malformed_memory_reply") from None

    async def registers(self, names):
        if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", n) for n in names):
            raise BackendError("invalid_register")
        reply = await self.rpc.command(f"{self.target} get_reg -force {{{' '.join(names)}}}")
        try:
            parts = reply.split()
            values = {parts[i]: int(parts[i + 1], 0) for i in range(0, len(parts), 2)}
            if set(values) != set(names) or any(not 0 <= v < 2**32 for v in values.values()):
                raise ValueError()
            return values
        except (ValueError, IndexError):
            raise BackendError("malformed_register_reply") from None

    async def control(self, operation):
        if operation not in ("halt", "resume", "step"):
            raise BackendError("unsupported_operation")
        self.generation += 1
        await self.rpc.command(f"{self.target} {operation}", changing=True)
        state = await self.status()
        if state != ("running" if operation == "resume" else "halted"):
            raise BackendError("control_state_uncertain", True)

    async def write(self, address, data):
        raise BackendError("live_write_disabled")
