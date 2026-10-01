"""The browser-test stack must be isolated from live configuration and clean up after itself."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from scripts.test_stack import FORBIDDEN_PORTS, MARKER, free_port, isolated_env

ROOT = Path(__file__).resolve().parents[1]
HOSTILE = {
    "TARGET_BACKEND": "openocd",
    "TARGET_PROFILE": "/live/profile.json",
    "OPENOCD_PORT": "6666",
    "OPENOCD_TARGET": "am335x.cpu",
    "OPENOCD_VERSION_PREFIX": "xPack",
    "ARM_SNAPSHOTS": "1",
    "ATTACK_LAB_LIVE_JTAG": "1",
    "UART_AUDIT_ENABLED": "1",
    "UART_PORT": "COM12",
    "UART_AUDIT_PASSWORD": "not-a-real-password",
    "INFERENCE_BACKEND": "nebius",
    "NEBIUS_API_KEY": "not-a-real-key",
    "REPLAY_MANIFEST": "/live/replay.json",
}


def test_isolated_env_drops_every_live_setting(monkeypatch):
    for key, value in HOSTILE.items():
        monkeypatch.setenv(key, value)
    env = isolated_env({"EDGE_API_KEY": "k" * 20})
    assert env["TARGET_BACKEND"] == "mock" and env["INFERENCE_BACKEND"] == "scripted"
    assert env["ATTACK_LAB_LIVE_JTAG"] == "0"
    for leaked in (
        "TARGET_PROFILE",
        "OPENOCD_PORT",
        "OPENOCD_TARGET",
        "ARM_SNAPSHOTS",
        "UART_AUDIT_ENABLED",
        "UART_PORT",
        "UART_AUDIT_PASSWORD",
        "NEBIUS_API_KEY",
        "REPLAY_MANIFEST",
    ):
        assert leaked not in env


def test_free_ports_never_include_live_ports():
    assert all(free_port() not in FORBIDDEN_PORTS for _ in range(50))


def alive(pid):
    if os.name == "nt":
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False
        ).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def listening(port):
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def test_real_stack_is_mock_scripted_hardware_free_and_cleans_up(tmp_path, monkeypatch):
    env = {**os.environ, **HOSTILE}  # a parent shell configured for live hardware and a cloud model
    stack = subprocess.Popen(
        [sys.executable, "scripts/test_stack.py"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = next(iter(stack.stdout))
        assert line.startswith(MARKER), line
        info = json.loads(line[len(MARKER) :])
        ports = [
            int(info[k].rsplit(":", 1)[1])
            for k in ("orchestrator", "edge", "legacy_orchestrator", "legacy_edge")
        ]
        assert not set(ports) & FORBIDDEN_PORTS and len(set(ports)) == 4
        assert info["modes"] == {"target": "mock", "inference": "scripted"}

        def session(base):
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            login = urllib.request.Request(
                base + "/api/login",
                data=json.dumps({"password": info["password"]}).encode(),
                headers={"Content-Type": "application/json"},
            )
            opener.open(login, timeout=5)
            return json.load(opener.open(base + "/api/config", timeout=10))

        config = session(info["orchestrator"])
        assert config["target"]["target_backend"] == "mock" and config["inference_backend"] == "scripted"
        assert config["uart"]["enabled"] is False and config["attack_lab"]["live_jtag_enabled"] is False
        assert (
            config["readiness"]["compatible"]
            and config["readiness"]["run_ready"]
            and not config["readiness"]["live_ready"]
        )
        assert config["readiness"]["debugger"]["applicable"] is False  # nothing can reach OpenOCD
        legacy = session(info["legacy_orchestrator"])
        assert legacy["readiness"]["edge"] == "incompatible" and not legacy["readiness"]["run_ready"]
        # The retained-evidence checkpoint script works against a real authenticated service.
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        opener.open(
            urllib.request.Request(
                info["orchestrator"] + "/api/login",
                data=json.dumps({"password": info["password"]}).encode(),
                headers={"Content-Type": "application/json"},
            ),
            timeout=5,
        )
        body = {
            "target_id": config["profile"]["target_id"],
            "purpose": "bootloader inspection",
            "region_names": ["demo-code"],
        }
        run = json.load(
            opener.open(
                urllib.request.Request(
                    info["orchestrator"] + "/api/runs",
                    data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                ),
                timeout=10,
            )
        )
        for _ in range(100):
            if json.load(opener.open(info["orchestrator"] + "/api/runs/" + run["run_id"], timeout=5))[
                "status"
            ] not in ("queued", "running"):
                break
            time.sleep(0.1)
        from scripts import export_retained_evidence

        monkeypatch.setenv("JTAGENT_DASHBOARD_PASSWORD", info["password"])
        assert (
            export_retained_evidence.main(["--base-url", info["orchestrator"], "--out", str(tmp_path)]) == 0
        )
        checkpoint = json.loads(next(tmp_path.glob("*/manifest.json")).read_text())
        assert checkpoint["runs"] == 1 and "cannot restore the bytes" in checkpoint["limitation"]
        first = next(
            f for f in checkpoint["files"] if f["path"].startswith("runs/") and f["path"].endswith(".json")
        )
        saved = (next(tmp_path.glob("*")) / first["path"]).read_bytes()
        assert hashlib.sha256(saved).hexdigest() == first["sha256"]
        assert info["password"].encode() not in b"".join(
            p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
        )
        pids = info["pids"]
        assert all(alive(pid) for pid in pids)
    finally:
        stack.stdin.close()  # the same signal Playwright's teardown (or a crashed parent) delivers
        stack.wait(timeout=20)
    time.sleep(0.5)
    assert not any(alive(pid) for pid in pids), "test-owned services must not outlive the launcher"
    assert not any(listening(p) for p in ports)


@pytest.fixture(autouse=True)
def _no_live_env(monkeypatch):
    for key in HOSTILE:
        monkeypatch.delenv(key, raising=False)
