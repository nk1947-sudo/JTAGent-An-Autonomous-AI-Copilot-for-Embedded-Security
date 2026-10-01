"""FIXTURE ONLY: a scripted OpenOCD Tcl RPC server. It stands in for the debugger in rehearsals.

It models what was observed on the real AM335x through the app (2026-09-29): memory and register reads
fail with plain text while the core runs and succeed while halted; ``halt``/``resume`` change state.
Every command received is recorded so tests can prove which verbs were (and were never) sent.
Nothing here says anything about real hardware.
"""

import asyncio

# Vector-table-shaped fixture bytes: b #0x402f0444 ; ldr pc,[pc,#0x14] x3 ; then zeroes.
FIXTURE = bytes.fromhex("0f0000ea" + "14f09fe5" * 3) + bytes(48)
BASE = 0x402F0400
FORBIDDEN_VERBS = (
    "reset",
    "mww",
    "mwh",
    "mwb",
    "write_memory",
    "load_image",
    "flash",
    "bp ",
    "rbp",
    "wp ",
    "step",
    "poll off",
)


class FakeOpenOCD:
    def __init__(self, state="running", version="xPack Open On-Chip Debugger 0.12.0+dev-fixture"):
        self.state, self.version = state, version
        self.commands = []
        self.refuse_resume = False  # resume "succeeds" but the core stays halted
        self.die_after_halt = False  # answer halt, then vanish: close the socket and stop listening
        self.delay = {}  # substring -> seconds to stall before answering
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    def answer(self, command):
        if command == "version":
            return self.version
        if command == "am335x.cpu curstate":
            return self.state
        if command == "targets am335x.cpu; halt 1000":
            self.state = "halted"
            return ""
        if command == "targets am335x.cpu; resume":
            self.state = "halted" if self.refuse_resume else "running"
            return ""
        if command.startswith("am335x.cpu read_memory "):
            _, _, address, width, count, *rest = command.split()
            if self.state != "halted":
                return "read_memory: failed to read memory"
            start, length = int(address) - BASE, int(count)
            if width != "8" or rest != ["phys"] or not 0 <= start or start + length > len(FIXTURE):
                return "read_memory: failed to read memory"
            return " ".join(f"0x{b:02x}" for b in FIXTURE[start : start + length])
        if command.startswith("am335x.cpu get_reg"):
            if self.state != "halted":
                return "failed to read register 'pc'"
            return "pc 0xc0017006 lr 0xc000d263 sp 0xc084dfa8 cpsr 0x600000b3"
        return "Error unsupported"

    async def handle(self, reader, writer):
        try:
            while True:
                command = (await reader.readuntil(b"\x1a"))[:-1].decode()
                self.commands.append(command)
                for needle, seconds in self.delay.items():
                    if needle in command:
                        await asyncio.sleep(seconds)
                writer.write(self.answer(command).encode() + b"\x1a")
                await writer.drain()
                if self.die_after_halt and command.endswith("halt 1000"):
                    self.server.close()
                    writer.close()
                    return
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    def sent_forbidden(self):
        return [c for c in self.commands if any(v in c for v in FORBIDDEN_VERBS)]
