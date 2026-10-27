"""Run the live Playwright operator harness with the current launcher's password."""

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from contracts.build import source_fingerprint

url = "http://127.0.0.1:8000/healthz"
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=5) as response:
    health = json.load(response)
build = health.get("build") or {}
if (
    health.get("status") != "ok"
    or build.get("component") != "orchestrator"
    or build.get("source_fingerprint") != source_fingerprint()
):
    raise SystemExit("Current loopback service is not the JTAGent orchestrator")
pid = build.get("pid")
if not isinstance(pid, int) or not psutil.pid_exists(pid):
    raise SystemExit("Current orchestrator process cannot be verified")
process = psutil.Process(pid)
command = " ".join(process.cmdline())
if "uvicorn" not in command or "orchestrator.app:create_app" not in command:
    raise SystemExit("Current listener PID is not the JTAGent orchestrator process")
password = process.environ().get("DASHBOARD_PASSWORD")
if not password:
    raise SystemExit("Current orchestrator credential is unavailable")
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=5) as response:
    if json.load(response).get("build", {}).get("pid") != pid:
        raise SystemExit("Current orchestrator process changed during credential lookup")
env = os.environ.copy()
env["JTAGENT_DASHBOARD_PASSWORD"] = password
raise SystemExit(
    subprocess.call(
        ["node", str(ROOT / "web" / "scripts" / "live-operator.mjs"), *sys.argv[1:]],
        cwd=ROOT,
        env=env,
    )
)
