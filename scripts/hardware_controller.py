"""Own a local JTAGent launcher, capture its credentials privately, and verify its API."""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.bundle_verify import verify_bundle

PROTECTED_PORTS = {8000, 8001, 3333, 3334, 4444, 6666}


class ControllerError(RuntimeError):
    pass


class ApplicationController:
    def __init__(self, command, expected_target, expected_backend, expected_inference, output=print):
        self.command = list(command)
        self.expected_target = expected_target
        self.expected_backend = expected_backend
        self.expected_inference = expected_inference
        self.output = output
        self.process = None
        self.client = None
        self._password = None
        self._base_url = None
        self._started = threading.Event()
        self._reader = None

    def start(self, timeout=45):
        if self.process is not None:
            raise ControllerError("this controller already owns a launcher")
        options = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            if os.name == "nt"
            else {"start_new_session": True}
        )
        self.process = subprocess.Popen(
            self.command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            **options,
        )
        self._reader = threading.Thread(target=self._read_output, name="jtagent-launcher-output", daemon=True)
        self._reader.start()
        if not self._started.wait(timeout):
            self.stop()
            raise ControllerError("launcher did not publish its local URL and password before timeout")
        return self

    def _read_output(self):
        for raw_line in self.process.stdout:
            line = raw_line.rstrip("\r\n")
            prefix = "Operator password:"
            if line.startswith(prefix):
                self._password = line[len(prefix) :].strip()
                if self._password and self._base_url:
                    self._started.set()
                continue
            if line.startswith("SiliconSentinel: "):
                candidate = line.partition(": ")[2].strip()
                parsed = urlsplit(candidate)
                if parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port:
                    self._base_url = candidate.rstrip("/")
                    if self._password:
                        self._started.set()
                continue
            try:
                self.output(line)
            except Exception:  # noqa: BLE001 -- keep draining even if the display sink fails
                self.output = lambda _line: None

    def _wait_for_start(self, timeout=15):
        if not self._started.wait(timeout):
            if self.process is not None and self.process.poll() is not None:
                raise ControllerError("launcher exited before publishing its local sign-in details")
            raise ControllerError("launcher sign-in details are not available")
        if self.client is None:
            self.client = httpx.Client(base_url=self._base_url, timeout=8, trust_env=False)

    def _response_json(self, response, action):
        if response.status_code != 200:
            raise ControllerError(f"{action} returned HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError:
            raise ControllerError(f"{action} returned invalid JSON") from None

    def verify(self):
        """Login with the captured credential and confirm target, inference, and readiness."""
        self._wait_for_start()
        self.client.cookies.clear()
        try:
            login = self.client.post(
                "/api/login",
                json={"password": self._password},
                headers={"Origin": self._base_url},
            )
            self._response_json(login, "local sign-in")
        except Exception as exc:
            self.client.cookies.clear()
            if isinstance(exc, ControllerError):
                raise
            raise ControllerError(f"local sign-in request failed ({type(exc).__name__})") from None
        try:
            readiness = self._response_json(self.client.get("/api/readiness"), "readiness check")
            config = self._response_json(self.client.get("/api/config"), "configuration check")
        except Exception as exc:
            self.client.cookies.clear()
            if isinstance(exc, ControllerError):
                raise
            raise ControllerError(f"local readiness check failed ({type(exc).__name__})") from None

        profile = config.get("profile") or {}
        target = readiness.get("target") or {}
        target_state = target.get("execution_state")
        try:
            if profile.get("target_id") != self.expected_target:
                raise ControllerError("configured target identity does not match the selected launcher")
            if readiness.get("target_backend") != self.expected_backend:
                raise ControllerError("target backend does not match the selected launcher")
            if config.get("inference_backend") != self.expected_inference:
                raise ControllerError("inference backend does not match the selected launcher")
            if readiness.get("recovery_required") is not False:
                raise ControllerError("target recovery state is required or unknown")
            if target_state not in ("running", "halted", "captured"):
                raise ControllerError("target execution state is unknown")
            ready = (
                readiness.get("live_ready")
                if self.expected_backend == "openocd"
                else readiness.get("run_ready")
            )
            if not ready:
                raise ControllerError("application is running but target readiness is blocked")
        except Exception:
            self.client.cookies.clear()
            raise
        return {
            "target_id": profile["target_id"],
            "target_backend": self.expected_backend,
            "inference_backend": config["inference_backend"],
            "model_id": config.get("model_id"),
            "target_state": target_state,
            "recovery_required": readiness["recovery_required"],
            "run_ready": readiness.get("run_ready"),
            "live_ready": readiness.get("live_ready"),
        }

    def synthetic_audit_export(self, timeout=60):
        if self.expected_backend != "mock" or self.expected_inference != "scripted":
            raise ControllerError("synthetic workflow is restricted to mock target + scripted inference")
        self._wait_for_start()
        config = self._response_json(self.client.get("/api/config"), "configuration check")
        profile = config.get("profile") or {}
        regions = [region["name"] for region in profile.get("regions", []) if region.get("approved", True)]
        scope = "demo-code" if "demo-code" in regions else (regions[0] if regions else None)
        if profile.get("target_id") != self.expected_target or not scope:
            raise ControllerError("mock profile has no expected target or approved scope")
        try:
            created = self._response_json(
                self.client.post(
                    "/api/runs",
                    json={
                        "target_id": self.expected_target,
                        "purpose": "bootloader inspection",
                        "region_names": [scope],
                        "byte_budget": 1024,
                        "collection_limit": 2,
                        "iteration_limit": 2,
                        "deadline_seconds": min(timeout, 60),
                    },
                ),
                "synthetic audit start",
            )
        except Exception as exc:
            if isinstance(exc, ControllerError):
                raise
            raise ControllerError(f"synthetic audit start failed ({type(exc).__name__})") from None
        run_id = created.get("run_id")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            run = self._response_json(self.client.get(f"/api/runs/{run_id}"), "synthetic audit status")
            if run.get("status") not in ("queued", "running"):
                break
            time.sleep(0.2)
        else:
            raise ControllerError("synthetic audit exceeded its local deadline")
        if run.get("status") != "completed":
            raise ControllerError(
                f"synthetic audit ended with status={run.get('status')} reason={run.get('termination_reason')}"
            )
        report_json = self._response_json(
            self.client.get(f"/api/runs/{run_id}/report.json"), "JSON report export"
        )
        report_md = self.client.get(f"/api/runs/{run_id}/report.md")
        if report_md.status_code != 200:
            raise ControllerError(f"Markdown report export returned HTTP {report_md.status_code}")
        bundle = self._response_json(
            self.client.post(f"/api/runs/{run_id}/bundle", json={"include_raw": False}),
            "evidence bundle export",
        )
        verification = verify_bundle(bundle["path"])
        if verification.status not in ("VERIFIED", "INCOMPLETE"):
            raise ControllerError(f"local bundle verification returned {verification.status}")
        return {
            "run_id": run_id,
            "status": run["status"],
            "capture_count": len(report_json.get("captures", [])),
            "report_json": True,
            "report_markdown": True,
            "bundle_status": verification.status,
            "bundle_path": bundle["path"],
        }

    def stop(self, timeout=20):
        """Ask only the owned launcher to handle its normal interrupt/finally path."""
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                if os.name == "nt":
                    self.process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    os.killpg(self.process.pid, signal.SIGINT)
            except OSError as exc:
                raise ControllerError(
                    f"could not signal owned launcher ({type(exc).__name__}); it remains running"
                ) from None
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                raise ControllerError("owned launcher did not exit gracefully; it remains running") from None
        if self._reader is not None:
            self._reader.join(timeout=2)
        if self.client is not None:
            self.client.close()
            self.client = None
        self._password = None
        self._base_url = None


def free_loopback_port(excluded=()):
    for _ in range(16):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in PROTECTED_PORTS and port not in excluded:
            return port
    raise ControllerError("could not select an isolated loopback port")


def demo_command(edge_port=None, orchestrator_port=None, export_dir=None):
    edge_port = edge_port if edge_port is not None else free_loopback_port()
    orchestrator_port = (
        orchestrator_port if orchestrator_port is not None else free_loopback_port({edge_port})
    )
    if edge_port in PROTECTED_PORTS or orchestrator_port in PROTECTED_PORTS:
        raise ControllerError("demo mode cannot use protected hardware service ports")
    if not 1 <= edge_port <= 65535 or not 1 <= orchestrator_port <= 65535:
        raise ControllerError("demo ports must be between 1 and 65535")
    if edge_port == orchestrator_port:
        raise ControllerError("demo edge and orchestrator ports must differ")
    command = [
        sys.executable,
        str(ROOT / "scripts" / "demo.py"),
        "--skip-build",
        "--edge-port",
        str(edge_port),
        "--orchestrator-port",
        str(orchestrator_port),
    ]
    if export_dir is not None:
        command.extend(("--export-dir", str(export_dir)))
    return command


def hardware_command(openocd=None, use_running_openocd=False, arm_snapshots=True):
    command = [
        sys.executable,
        str(ROOT / "scripts" / "run_hardware.py"),
        "--inference",
        "scripted",
        "--arm-snapshots",
    ]
    if openocd:
        command.extend(("--openocd", openocd))
    if use_running_openocd:
        command.append("--use-running-openocd")
    if arm_snapshots is False:
        command.remove("--arm-snapshots")
    return command


def main():
    parser = argparse.ArgumentParser(description="Own and verify a local JTAGent launcher")
    parser.add_argument("mode", choices=("demo", "hardware"))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--openocd")
    parser.add_argument("--use-running-openocd", action="store_true")
    snapshots = parser.add_mutually_exclusive_group()
    snapshots.add_argument("--arm-snapshots", dest="arm_snapshots", action="store_true")
    snapshots.add_argument("--no-arm-snapshots", dest="arm_snapshots", action="store_false")
    parser.set_defaults(arm_snapshots=True)
    parser.add_argument("--edge-port", type=int)
    parser.add_argument("--orchestrator-port", type=int)
    parser.add_argument("--export-dir")
    args = parser.parse_args()
    if args.mode == "demo":
        command = demo_command(args.edge_port, args.orchestrator_port, args.export_dir)
        if not args.skip_build:
            command.remove("--skip-build")
        controller = ApplicationController(command, "synthetic-am335x", "mock", "scripted")
    else:
        command = hardware_command(args.openocd, args.use_running_openocd, args.arm_snapshots)
        if args.skip_build:
            command.append("--skip-build")
        controller = ApplicationController(command, "beaglebone-black-am335x", "openocd", "scripted")
    controller.start()
    try:
        print(json.dumps(controller.verify(), sort_keys=True), flush=True)
        if args.mode == "demo":
            print(json.dumps(controller.synthetic_audit_export(), sort_keys=True), flush=True)
        print("Controller is monitoring the owned launcher. Press Ctrl+C for graceful shutdown.", flush=True)
        while controller.process.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
