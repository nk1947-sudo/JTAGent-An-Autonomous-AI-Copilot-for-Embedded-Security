"""Run the reviewed BeagleBone JTAG path locally, without Docker."""

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts.models import TargetProfile
from orchestrator.inference import InferenceError, NebiusInference
from scripts.demo import wait_ready

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config" / "beaglebone-black-live.json"


def _handle_ctrl_break(_signum, _frame):
    raise KeyboardInterrupt


def register_ctrl_break_handler():
    if os.name == "nt" and hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _handle_ctrl_break)


def port_open(port):
    with socket.socket() as connection:
        connection.settimeout(0.25)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def wait_openocd(process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                "OpenOCD exited. Check the JTAG adapter, board power and OpenOCD configuration."
            )
        if port_open(6666):
            return
        time.sleep(0.2)
    raise RuntimeError("OpenOCD did not open its local Tcl port within 15 seconds.")


def target_status(key):
    request = urllib.request.Request(
        "http://127.0.0.1:8001/api/v1/target/status",
        headers={"Authorization": "Bearer " + key},
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description="Connect a BeagleBone Black through a C232HM JTAG adapter")
    parser.add_argument("--openocd", default=os.getenv("OPENOCD_EXE") or shutil.which("openocd"))
    parser.add_argument("--use-running-openocd", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument(
        "--arm-snapshots", action="store_true", help="Allow a brief halt/read/restore on a running CPU"
    )
    parser.add_argument(
        "--retain-raw-local", action="store_true", help="Keep bounded raw bytes for local bundle export"
    )
    parser.add_argument("--inference", choices=("nebius", "scripted"), default="nebius")
    args = parser.parse_args()

    if any(port_open(port) for port in (8000, 8001)):
        parser.error("Port 8000 or 8001 is in use. Stop the existing services first.")
    if port_open(6666) and not args.use_running_openocd:
        parser.error(
            "OpenOCD already listens on port 6666. Pass --use-running-openocd to verify and reuse it."
        )
    if not port_open(6666) and (args.use_running_openocd or not args.openocd):
        parser.error("OpenOCD is not available. Install it or set OPENOCD_EXE to its executable path.")
    profile = TargetProfile.model_validate_json(PROFILE.read_text())
    if not profile.verified_for_live or profile.target_id != "beaglebone-black-am335x":
        parser.error("The reviewed BeagleBone live profile is required.")
    if args.inference == "nebius":
        try:
            NebiusInference()  # Validate credentials, endpoint, model and hosted context before touching hardware.
        except (InferenceError, ValueError) as exc:
            parser.error(
                f"Nebius is not configured: {exc}. Supply NEBIUS_* environment values or use --inference scripted without provider calls; hardware access remains live."
            )

    os.chdir(ROOT)
    if not args.skip_build:
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not npm:
            parser.error(
                "Node.js/npm is required to build the dashboard. Install it or use --skip-build with an existing web/dist."
            )
        subprocess.run([npm, "ci", "--no-fund", "--no-audit"], cwd=ROOT / "web", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "web", check=True)
    elif not (ROOT / "web" / "dist" / "index.html").is_file():
        parser.error("web/dist is missing; run once without --skip-build.")

    env = os.environ.copy()
    env.update(
        TARGET_BACKEND="openocd",
        TARGET_PROFILE=str(PROFILE),
        OPENOCD_TARGET="am335x.cpu",
        OPENOCD_PORT="6666",
        OPENOCD_VERSION_PREFIX="xPack Open On-Chip Debugger 0.12.0",
        ARM_SNAPSHOTS="1" if args.arm_snapshots else "0",
        RETAIN_RAW_LOCAL="1" if args.retain_raw_local else "0",
        ATTACK_LAB_LIVE_JTAG="0",
        INFERENCE_BACKEND=args.inference,
        EDGE_API_URL="http://127.0.0.1:8001",
        PUBLIC_ORIGIN="http://127.0.0.1:8000",
        COOKIE_SECURE="0",
        LANGSMITH_TRACING="false",
        LANGCHAIN_TRACING_V2="false",
        PYTHONUNBUFFERED="1",
    )
    env["EDGE_API_KEY"] = env.get("EDGE_API_KEY") or secrets.token_urlsafe(32)
    env["DASHBOARD_PASSWORD"] = env.get("DASHBOARD_PASSWORD") or secrets.token_urlsafe(18)
    children = []
    owned_openocd = None
    child_options = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    try:
        if not args.use_running_openocd:
            owned_openocd = subprocess.Popen(
                [
                    args.openocd,
                    "-f",
                    "interface/ftdi/c232hm.cfg",
                    "-c",
                    "ftdi layout_signal nTRST -data 0x0040 -oe 0x0040; reset_config trst_only; adapter speed 100; bindto 127.0.0.1",
                    "-f",
                    "target/am335x.cfg",
                    "-c",
                    "init",
                ],
                cwd=ROOT,
                **child_options,
            )
            wait_openocd(owned_openocd)
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
                    **child_options,
                )
            )
            wait_ready(f"http://127.0.0.1:{port}/healthz", children)

        print("\nSiliconSentinel: http://127.0.0.1:8000", flush=True)
        print("Operator password: " + env["DASHBOARD_PASSWORD"], flush=True)
        try:
            status = target_status(env["EDGE_API_KEY"])
        except Exception:  # noqa: BLE001 -- dashboard still shows a degraded connection
            print(
                "Target status is unavailable. Open the dashboard to inspect the connection blocker.",
                flush=True,
            )
        else:
            print("Target state: " + str(status["target"]["execution_state"]), flush=True)
            if not status["live_operations"]["allowed"]:
                print("Connection blockers: " + ", ".join(status["live_operations"]["blockers"]), flush=True)
        print("Inference: " + args.inference + "; snapshots armed: " + env["ARM_SNAPSHOTS"], flush=True)
        print(
            "Open the dashboard, sign in, select the approved region, and start an audit. Ctrl+C stops this stack.",
            flush=True,
        )
        while all(child.poll() is None for child in children) and (
            owned_openocd is None or owned_openocd.poll() is None
        ):
            time.sleep(0.5)
        raise RuntimeError("A service exited unexpectedly; check the output above.")
    finally:
        # Stop new agent requests first. The edge remains alive to finish or restore any in-flight snapshot.
        if len(children) > 1 and children[1].poll() is None:
            children[1].terminate()
            try:
                children[1].wait(timeout=5)
            except subprocess.TimeoutExpired:
                children[1].kill()
        safe_to_stop = True
        if children and children[0].poll() is None:
            try:
                current = target_status(env["EDGE_API_KEY"])
            except Exception:  # noqa: BLE001 -- an unreachable edge cannot prove the target is safe to release
                current = None
            if (
                current is None
                or current["target"]["execution_state"] not in ("running", "captured")
                or current["recovery_required"]
            ):
                print(
                    "Target state is halted or unknown, or recovery is required. Leaving the edge and "
                    "OpenOCD running; reconcile the CPU locally before stopping them. "
                    f"Edge PID: {children[0].pid}, OpenOCD: {owned_openocd.pid if owned_openocd else 'pre-existing'}.",
                    flush=True,
                )
                safe_to_stop = False
        if safe_to_stop:
            if children and children[0].poll() is None:
                children[0].terminate()
            for child in children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
            if owned_openocd is not None and owned_openocd.poll() is None:
                owned_openocd.terminate()
                try:
                    owned_openocd.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owned_openocd.kill()


if __name__ == "__main__":
    register_ctrl_break_handler()
    try:
        main()
    except KeyboardInterrupt:
        pass
