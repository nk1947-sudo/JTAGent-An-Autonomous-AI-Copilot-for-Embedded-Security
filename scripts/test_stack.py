"""Isolated mock/scripted service stack for browser tests. Never uses live ports or hardware.

Starts, on freshly allocated loopback ports:
  * an edge on the MOCK backend (no OpenOCD, no UART, nothing armed for physical operations),
  * an orchestrator with SCRIPTED inference pointed at that edge,
  * a "legacy" edge speaking the old flat status, and an orchestrator pointed at it.
It prints one line ``JTAGENT_TEST_STACK {json}`` when everything answers, then runs until stdin
closes (or SIGTERM) and terminates ONLY the processes it started.

The environment is built from a small whitelist, so OPENOCD_*, UART_*, NEBIUS_*, ARM_SNAPSHOTS,
TARGET_PROFILE and any other live configuration in the parent shell cannot leak into the services.
The live ports (8000/8001 and the OpenOCD listeners) are never allocated.
"""

import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PORTS = {8000, 8001, 6666, 3333, 3334, 4444}
KEEP = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SystemRoot",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
)
MARKER = "JTAGENT_TEST_STACK"


def isolated_env(extra):
    """A fresh environment: whitelisted basics plus explicit test-only settings."""
    env = {k: os.environ[k] for k in KEEP if k in os.environ}
    env.update(
        TARGET_BACKEND="mock",
        INFERENCE_BACKEND="scripted",
        ATTACK_LAB_LIVE_JTAG="0",
        COOKIE_SECURE="0",
        LANGSMITH_TRACING="false",
        LANGCHAIN_TRACING_V2="false",
        PYTHONUNBUFFERED="1",
    )
    env.update(extra)
    return env


def free_port():
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in FORBIDDEN_PORTS:
            return port


def http_ok(url):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return response.status == 200
    except OSError:
        return False


class Stack:
    def __init__(self):
        self.children = []
        self.log_dir = Path(tempfile.mkdtemp(prefix="jtagent-test-stack-"))
        self.key = secrets.token_urlsafe(32)
        self.password = secrets.token_urlsafe(18)

    def start(self, name, module, extra_env):
        """Start one service on a free port, retrying if another process wins the port race."""
        for _ in range(8):
            port = free_port()
            env = isolated_env({**extra_env, "PUBLIC_ORIGIN": f"http://127.0.0.1:{port}"})
            args = [
                sys.executable,
                "-m",
                "uvicorn",
                module,
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--workers",
                "1",
                "--no-access-log",
            ]
            with open(self.log_dir / f"{name}.log", "wb") as log:
                child = subprocess.Popen(args, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            self.children.append(child)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    break  # exited: most likely the port was taken between allocation and bind
                if http_ok(f"http://127.0.0.1:{port}/healthz"):
                    return port, child
                time.sleep(0.15)
            if child.poll() is None:
                raise RuntimeError(f"{name} did not become ready; see {self.log_dir / (name + '.log')}")
            self.children.remove(child)
        raise RuntimeError(f"could not start {name} after several port attempts")

    def stop(self):
        """Terminate exactly the processes this launcher started."""
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 8
        for child in self.children:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def main():
    stack = Stack()
    export_dir = stack.log_dir / "exports"
    try:
        common = {
            "EDGE_API_KEY": stack.key,
            "DASHBOARD_PASSWORD": stack.password,
            "EXPORT_DIR": str(export_dir),
        }
        edge_port, edge = stack.start("edge", "edge.app:create_app", {**common, "RETAIN_RAW_LOCAL": "1"})
        orch_port, orch = stack.start(
            "orchestrator",
            "orchestrator.app:create_app",
            {**common, "EDGE_API_URL": f"http://127.0.0.1:{edge_port}"},
        )
        legacy_port, legacy = stack.start("legacy-edge", "scripts.legacy_edge_stub:create_app", common)
        legacy_orch_port, legacy_orch = stack.start(
            "legacy-orchestrator",
            "orchestrator.app:create_app",
            {**common, "EDGE_API_URL": f"http://127.0.0.1:{legacy_port}"},
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{edge_port}/api/v1/target/status",
            headers={"Authorization": "Bearer " + stack.key},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            status = json.load(response)
        assert status["target_backend"] == "mock" and status["debugger"]["applicable"] is False
        payload = {
            "orchestrator": f"http://127.0.0.1:{orch_port}",
            "edge": f"http://127.0.0.1:{edge_port}",
            "legacy_orchestrator": f"http://127.0.0.1:{legacy_orch_port}",
            "legacy_edge": f"http://127.0.0.1:{legacy_port}",
            "password": stack.password,
            "export_dir": str(export_dir),
            "log_dir": str(stack.log_dir),
            "modes": {"target": status["target_backend"], "inference": "scripted"},
            "pids": [edge.pid, orch.pid, legacy.pid, legacy_orch.pid],
        }
        print(f"{MARKER} {json.dumps(payload)}", flush=True)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        sys.stdin.read()  # blocks until the parent closes the pipe or exits
    finally:
        stack.stop()


if __name__ == "__main__":
    main()
