from fastapi.testclient import TestClient

from contracts.models import UartAuditRequest
from edge.app import create_app
from edge.uart import UartAuditor


class FakeSerial:
    def __init__(self, initial, mode):
        self.buffer = bytearray(initial)
        self.mode = mode
        self.closed = False
        self.writes = []

    @property
    def in_waiting(self):
        return len(self.buffer)

    def read(self, count):
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

    def write(self, data):
        self.writes.append(data)
        if self.mode == "credential" and data == b"\r":
            self.buffer.extend(b"beaglebone login: ")
        if self.mode == "interrupt" and data == b" ":
            self.buffer.extend(b"\r\n=> ")
        elif self.mode == "credential":
            if data == b"debian\r":
                self.buffer.extend(b"Password: ")
            elif data == b"configured-secret\r":
                self.buffer.extend(b"debian@beaglebone:~$ ")
            elif data.startswith(b"id;"):
                self.buffer.extend(
                    b"uid=1000(debian) gid=1000(debian)\r\n3.8.13-bone80\r\n"
                    b"uid=0(root) gid=0(root) groups=0(root)\r\n"
                )
            elif data == b"exit\r":
                self.buffer.extend(b"logout\r\n")
        return len(data)

    def reset_input_buffer(self):
        pass

    def close(self):
        self.closed = True


async def test_uart_interrupt_is_one_fixed_character():
    fake = FakeSerial(b"U-Boot 2019.04-test\r\nPress SPACE to abort autoboot in 2 seconds\r\n", "interrupt")
    auditor = UartAuditor("COM12", serial_factory=lambda: fake)
    result = await auditor.run(UartAuditRequest(mode="interrupt", timeout_seconds=10))
    assert result.status == "completed"
    assert result.autoboot_interrupt_window and result.uboot_prompt_obtained
    assert fake.writes == [b" "]
    assert fake.closed


async def test_uart_configured_login_redacts_and_checks_root():
    fake = FakeSerial(b"beaglebone login: ", "credential")
    auditor = UartAuditor(
        "COM12",
        username="debian",
        password="configured-secret",
        serial_factory=lambda: fake,
    )
    result = await auditor.run(UartAuditRequest(mode="credential_check", timeout_seconds=10))
    assert result.configured_login_attempted and result.configured_login_succeeded
    assert result.root_without_additional_prompt
    assert "configured-secret" not in result.transcript_excerpt
    assert fake.writes == [
        b"\r",
        b"debian\r",
        b"configured-secret\r",
        b"id; uname -r; sudo -n id\r",
        b"exit\r",
    ]


def test_uart_api_is_authenticated_and_explicitly_enabled(service):
    fake = FakeSerial(b"U-Boot test\r\nStarting kernel\r\nbeaglebone login: ", "observe")
    auditor = UartAuditor("COM12", serial_factory=lambda: fake)
    with TestClient(create_app(service, "test-edge-key-123456", auditor)) as client:
        assert client.get("/api/v1/uart/status").status_code == 401
        client.headers["Authorization"] = "Bearer test-edge-key-123456"
        assert client.get("/api/v1/uart/status").json() == {
            "enabled": True,
            "port": "COM12",
            "baud": 115200,
        }
        result = client.post("/api/v1/uart/audit", json={"mode": "observe", "timeout_seconds": 10})
        assert result.status_code == 200
        assert result.json()["boot_observed"]
