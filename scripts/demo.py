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
    args = parser.parse_args()
    os.chdir(ROOT)
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not args.skip_build:
        subprocess.run([npm, "ci", "--no-fund", "--no-audit"], cwd=ROOT / "web", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "web", check=True)
    env = os.environ.copy()
    env.setdefault("TARGET_BACKEND", "mock")
    env.setdefault("INFERENCE_BACKEND", "scripted")
    env.setdefault("EDGE_API_KEY", secrets.token_urlsafe(32))
    env.setdefault("DASHBOARD_PASSWORD", secrets.token_urlsafe(18))
    env["LANGSMITH_TRACING"] = "false"
    env["LANGCHAIN_TRACING_V2"] = "false"
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("EDGE_API_URL", "http://127.0.0.1:8001")
    children = []
    try:
        for module, port in (("edge.app:create_app", 8001), ("orchestrator.app:create_app", 8000)):
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
        print("\nSiliconSentinel: http://127.0.0.1:8000", flush=True)
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
