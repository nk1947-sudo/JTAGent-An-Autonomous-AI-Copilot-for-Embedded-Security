"""One-command local demo. Does not launch OpenOCD or create external resources."""

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def demo_env(edge_port=8001, orchestrator_port=8000):
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(("OPENOCD_", "UART_", "NEBIUS_", "OLLAMA_")) or key in (
            "TARGET_PROFILE",
            "REPLAY_MANIFEST",
            "ARM_SNAPSHOTS",
            "RETAIN_RAW_LOCAL",
            "EXPORT_DIR",
            "MAX_READ_BYTES",
            "TAVILY_API_KEY",
            "LANGSMITH_API_KEY",
        ):
            env.pop(key)
    env.update(
        {
            "TARGET_BACKEND": "mock",
            "MOCK_VARIANT": "demo",
            "INFERENCE_BACKEND": "scripted",
            "ATTACK_LAB_LIVE_JTAG": "0",
            "EDGE_API_URL": f"http://127.0.0.1:{edge_port}",
            "MAX_READ_BYTES": "4096",
            "RETAIN_RAW_LOCAL": "0",
            "PUBLIC_ORIGIN": f"http://127.0.0.1:{orchestrator_port}",
            "COOKIE_SECURE": "0",
            "EDGE_API_KEY": secrets.token_urlsafe(32),
            "DASHBOARD_PASSWORD": secrets.token_urlsafe(18),
            "LANGSMITH_TRACING": "false",
            "LANGCHAIN_TRACING_V2": "false",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def wait_ready(url, processes):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("A service exited; inspect its startup error")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("Service readiness timed out")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--edge-port", type=int, default=8001)
    parser.add_argument("--orchestrator-port", type=int, default=8000)
    parser.add_argument("--export-dir")
    args = parser.parse_args()
    for port in (args.edge_port, args.orchestrator_port):
        if not 1 <= port <= 65535:
            parser.error("service ports must be between 1 and 65535")
    if args.edge_port == args.orchestrator_port:
        parser.error("edge and orchestrator ports must differ")
    os.chdir(ROOT)
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not args.skip_build:
        subprocess.run([npm, "ci", "--no-fund", "--no-audit"], cwd=ROOT / "web", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "web", check=True)
    env = demo_env(args.edge_port, args.orchestrator_port)
    if args.export_dir:
        env["EXPORT_DIR"] = str(Path(args.export_dir).resolve())
    children = []
    try:
        for module, port in (
            ("edge.app:create_app", args.edge_port),
            ("orchestrator.app:create_app", args.orchestrator_port),
        ):
            children.append(
                subprocess.Popen(
                    [
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
                    ],
                    env=env,
                    cwd=ROOT,
                )
            )
            wait_ready(f"http://127.0.0.1:{port}/healthz", children)
        print(f"\nSiliconSentinel: http://127.0.0.1:{args.orchestrator_port}", flush=True)
        print("Operator password: " + env["DASHBOARD_PASSWORD"], flush=True)
        print(
            "Modes: "
            + env["TARGET_BACKEND"]
            + " + "
            + env["INFERENCE_BACKEND"]
            + "; Ctrl+C stops both services",
            flush=True,
        )
        while all(p.poll() is None for p in children):
            time.sleep(0.5)
    finally:
        for p in children:
            p.terminate()
        for p in children:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
