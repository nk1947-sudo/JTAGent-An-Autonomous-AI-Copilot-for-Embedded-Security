import asyncio
import hashlib
import json

import httpx
import pytest

from contracts.models import ReadProposal
from edge.backends import BackendError, OpenOCDBackend, ReplayBackend, TclRPC
from fixtures.synthetic import segments
from orchestrator.inference import InferenceError, NebiusInference


@pytest.mark.parametrize("reply,expected", [(b"0x01 0x02\x1a", "0x01 0x02")])
async def test_split_frames_and_reuse(reply, expected):
    async def handler(reader, writer):
        try:
            for _ in range(2):
                await reader.readuntil(b"\x1a")
                for chunk in (reply[:2], reply[2:-1], reply[-1:]):
                    writer.write(chunk)
                    await writer.drain()
                    await asyncio.sleep(0.005)
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    rpc = TclRPC(port=server.sockets[0].getsockname()[1])
    async with server:
        assert await rpc.command("version") == expected
        assert await rpc.command("version") == expected
        await rpc.close()


@pytest.mark.parametrize(
    "reply,code",
    [
        (b"bad\x1aextra\x1a", "unexpected_rpc_frame"),
        (b"incomplete", "rpc_disconnected"),
        (b"invalid command name", "rpc_disconnected"),
        (b"Error target failed\x1a", "debugger_command_failed"),
    ],
)
async def test_bad_frames(reply, code):
    async def handler(reader, writer):
        await reader.readuntil(b"\x1a")
        writer.write(reply)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    rpc = TclRPC(port=server.sockets[0].getsockname()[1])
    async with server:
        with pytest.raises(BackendError) as error:
            await rpc.command("step", changing=True)
        assert error.value.code == code and error.value.uncertain
        assert rpc.writer is None


async def test_timeout_and_reconnect_without_replaying_change():
    commands = []
    handlers = []

    async def handler(reader, writer):
        handlers.append(asyncio.current_task())
        try:
            command = await reader.readuntil(b"\x1a")
            commands.append(command)
            if command == b"step\x1a":
                await asyncio.sleep(0.2)
            else:
                writer.write(b"halted\x1a")
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    rpc = TclRPC(port=server.sockets[0].getsockname()[1], timeout=0.04)
    async with server:
        with pytest.raises(BackendError) as error:
            await rpc.command("step", changing=True)
        assert error.value.uncertain
        assert await rpc.command("cpu curstate") == "halted"
        assert commands.count(b"step\x1a") == 1
        await rpc.close()
    await asyncio.gather(*handlers)


async def test_openocd_templates_registers_and_lifecycle():
    state = "running"
    commands = []

    async def handler(reader, writer):
        nonlocal state
        try:
            while True:
                cmd = (await reader.readuntil(b"\x1a"))[:-1].decode()
                commands.append(cmd)
                if cmd == "version":
                    result = "Open On-Chip Debugger 0.12.0-test"
                elif cmd == "am335x.cpu curstate":
                    result = state
                elif cmd == "targets am335x.cpu; halt 1000":
                    state, result = "halted", ""
                elif cmd == "targets am335x.cpu; resume":
                    state, result = "running", ""
                elif cmd == "am335x.cpu read_memory 2147483648 8 4":
                    result = "0x00 0x00 0xa0 0xe3"
                elif cmd == "am335x.cpu get_reg -force {pc sp}":
                    result = "pc 0x80000000 sp 0x800011f0"
                else:
                    result = "Error unsupported"
                writer.write(result.encode() + b"\x1a")
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    rpc = TclRPC(port=server.sockets[0].getsockname()[1])
    backend = OpenOCDBackend(rpc, "am335x.cpu", "Open On-Chip Debugger 0.12.")
    async with server:
        assert await backend.status() == "running"
        await backend.control("halt")
        assert await backend.read(0x80000000, 4, "virtual") == bytes.fromhex("0000a0e3")
        assert (await backend.registers(["pc", "sp"]))["pc"] == 0x80000000
        await backend.control("resume")
        assert state == "running"
        with pytest.raises(BackendError, match="live_write_disabled"):
            await backend.write(0x80000000, b"x")
        await rpc.close()
    assert not any("reset" in c for c in commands)
    assert not any(c.startswith("tcl ") for c in commands)


@pytest.mark.parametrize("reply", ["1 999", "nonsense", "0x01 0x02 0x03"])
async def test_malformed_memory(reply):
    class FakeRPC:
        async def command(self, *args, **kwargs):
            return reply

    backend = OpenOCDBackend(FakeRPC(), "cpu", "reviewed")
    with pytest.raises(BackendError, match="malformed"):
        await backend.read(0, 2, "virtual")


def manifest(profile):
    return {
        "provenance": "Synthetic replay, not hardware",
        "captured_at": "2026-09-22T00:00:00+00:00",
        "profile": profile.model_dump(),
        "registers": {"pc": 0x80000000, "lr": 0x80000008, "sp": 0x800011F0, "cpsr": 19},
        "segments": [
            {"address": a, "hex": bytes(d).hex(), "sha256": hashlib.sha256(d).hexdigest()}
            for a, d in segments().items()
        ],
    }


async def test_replay_hashes_and_readonly(tmp_path, profile):
    path = tmp_path / "manifest.json"
    data = manifest(profile)
    path.write_text(json.dumps(data))
    backend = ReplayBackend(path)
    assert len(await backend.read(0x80000000, 256, "virtual")) == 256
    with pytest.raises(BackendError, match="read_only"):
        await backend.control("halt")
    data["segments"][0]["sha256"] = "bad"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="hash"):
        ReplayBackend(path)


@pytest.fixture
def nebius_env(monkeypatch):
    for key, value in {
        "NEBIUS_BASE_URL": "https://api.tokenfactory.nebius.com/v1",
        "NEBIUS_MODEL": "nvidia/test-model",
        "NEBIUS_API_KEY": "synthetic-provider-key",
        "NEBIUS_VERIFIED_CONTEXT_TOKENS": "32768",
    }.items():
        monkeypatch.setenv(key, value)


async def test_provider_visibility_tool_schema_and_usage(nebius_env):
    calls = []

    def handler(req):
        calls.append(req)
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "nvidia/test-model"}]})
        body = json.loads(req.content)
        assert body["tools"][0]["function"]["name"] == "inspect_memory"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "inspect_memory",
                                        "arguments": json.dumps(
                                            {
                                                "address": 0x80000000,
                                                "length": 256,
                                                "reason": "Inspect approved region",
                                            }
                                        ),
                                    }
                                }
                            ]
                        },
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = NebiusInference(client)
        assert (await provider.preflight())["inference_verified"] is False
        result = await provider.tool("inspect_memory", ReadProposal.model_json_schema(), {})
        assert ReadProposal.model_validate(result).address == 0x80000000
        assert provider.usage == [{"prompt_tokens": 12, "completion_tokens": 20}]
        assert len(provider.latencies) == 2


@pytest.mark.parametrize(
    "status,payload",
    [(401, {}), (200, {"choices": [{"message": {"content": "run shell"}}]}), (200, {"choices": []})],
)
async def test_provider_fails_closed(nebius_env, status, payload):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(status, json=payload))
    ) as client:
        with pytest.raises(InferenceError):
            await NebiusInference(client).tool("inspect_memory", ReadProposal.model_json_schema(), {})


async def test_provider_bounded_retry(nebius_env):
    count = 0

    def handler(req):
        nonlocal count
        count += 1
        return httpx.Response(503, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(InferenceError):
            await NebiusInference(client).preflight()
    assert count == 2


def test_live_config_has_no_fallback(monkeypatch):
    from edge.app import configured_service
    from orchestrator.inference import configured_inference

    monkeypatch.setenv("TARGET_BACKEND", "openocd")
    monkeypatch.delenv("TARGET_PROFILE", raising=False)
    with pytest.raises(ValueError, match="verified"):
        configured_service()
    monkeypatch.setenv("INFERENCE_BACKEND", "nebius")
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    with pytest.raises(InferenceError):
        configured_inference()


def test_report_redaction_preserves_json_types():
    from analysis.evidence import sanitize_data

    assert sanitize_data({"value": "password=test", "count": 2}) == {"value": "[REDACTED]", "count": 2}
