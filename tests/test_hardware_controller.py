import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.hardware_controller import (
    PROTECTED_PORTS,
    ApplicationController,
    ControllerError,
    demo_command,
)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def port_open(port):
    with socket.socket() as connection:
        connection.settimeout(0.1)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def test_demo_command_defaults_to_isolated_loopback_ports():
    command = demo_command()
    edge_port = int(command[command.index("--edge-port") + 1])
    app_port = int(command[command.index("--orchestrator-port") + 1])
    if edge_port in PROTECTED_PORTS or app_port in PROTECTED_PORTS or edge_port == app_port:
        pytest.fail("default demo command selected a protected or duplicate port")
    assert not port_open(edge_port) and not port_open(app_port)


def test_demo_command_rejects_hardware_service_ports():
    with pytest.raises(ControllerError, match="protected hardware service ports"):
        demo_command(8001, 8000)


def test_controller_recovers_after_helper_failure_and_exports_mock_workflow(tmp_path):
    edge_port, app_port = free_port(), free_port()
    while edge_port == app_port:
        app_port = free_port()
    assert not {edge_port, app_port} & {8000, 8001, 3333, 3334, 4444, 6666}
    output = []
    controller = ApplicationController(
        demo_command(edge_port, app_port, tmp_path / "exports"),
        "synthetic-am335x",
        "mock",
        "scripted",
        output=output.append,
    )
    try:
        controller.start()
        assert controller._base_url == f"http://127.0.0.1:{app_port}"
        password = controller._password
        if not password or password in "\n".join(output):
            pytest.fail("launcher password capture or suppression failed")
        if len(password) != 24 or not all(character.isalnum() or character in "-_" for character in password):
            pytest.fail("captured launcher password format was unexpected")
        if any("Operator password:" in line for line in output):
            pytest.fail("launcher password line was logged")
        initial_readiness = controller.verify()
        assert initial_readiness["target_backend"] == "mock"
        old_cookie = controller.client.cookies.get("operator")
        if not old_cookie:
            pytest.fail("authenticated session cookie was not established")

        original_post = controller.client.post
        failed = False

        def fail_first_login(*args, **kwargs):
            nonlocal failed
            if not failed:
                failed = True
                raise RuntimeError("helper quoting failure")
            return original_post(*args, **kwargs)

        controller.client.post = fail_first_login
        with pytest.raises(ControllerError, match="local sign-in request failed"):
            controller.verify()
        if controller._password != password:
            pytest.fail("captured password was discarded after verifier failure")
        if controller.client.cookies.get("operator") is not None:
            pytest.fail("stale session cookie survived verifier failure")
        controller.client.post = original_post

        readiness = controller.verify()
        assert readiness["target_id"] == "synthetic-am335x"
        assert readiness["target_backend"] == "mock"
        assert readiness["inference_backend"] == "scripted"
        assert readiness["run_ready"] is True
        assert readiness["target_state"] == "running"
        assert readiness["recovery_required"] is False
        if controller.client.cookies.get("operator") == old_cookie:
            pytest.fail("sign-in retry did not establish a fresh session cookie")

        workflow = controller.synthetic_audit_export()
        assert workflow["status"] == "completed"
        assert workflow["capture_count"] > 0
        assert workflow["report_json"] and workflow["report_markdown"]
        assert workflow["bundle_status"] == "INCOMPLETE"
        assert (tmp_path / "exports").is_dir()
    finally:
        controller.stop(timeout=30)

    assert controller.process.poll() is not None
    if controller._password is not None:
        pytest.fail("password remained in memory after launcher shutdown")
    assert controller.client is None
    assert not port_open(edge_port)
    assert not port_open(app_port)


@pytest.mark.skipif(os.name != "nt", reason="Windows console control event regression")
def test_hardware_launcher_ctrl_break_enters_finally(tmp_path):
    marker = tmp_path / "finally-ran.txt"
    child = tmp_path / "ctrl_break_probe.py"
    child.write_text(
        "from pathlib import Path\n"
        "import sys, time\n"
        "sys.path.insert(0, str(Path.cwd()))\n"
        "from scripts.run_hardware import register_ctrl_break_handler\n"
        "register_ctrl_break_handler()\n"
        "print('ready', flush=True)\n"
        "try:\n"
        "    try:\n"
        "        while True: time.sleep(0.05)\n"
        "    except KeyboardInterrupt:\n"
        "        pass\n"
        "finally:\n"
        "    Path(sys.argv[1]).write_text('finally ran', encoding='utf-8')\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, str(child), str(marker)],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    try:
        assert process.stdout.readline().strip() == b"ready"
        process.send_signal(signal.CTRL_BREAK_EVENT)
        assert process.wait(timeout=8) == 0
        assert marker.read_text(encoding="utf-8") == "finally ran"
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)
