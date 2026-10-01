"""Bounded local UART security checks with no arbitrary command execution."""

import asyncio
import hashlib
import os
import re
import time
from contextlib import suppress

from analysis.evidence import sanitize
from contracts.models import UartAuditRequest, UartAuditResult, now


class UartAuditError(Exception):
    pass


def configured_uart_auditor():
    if os.getenv("UART_AUDIT_ENABLED") != "1":
        return None
    port = os.getenv("UART_PORT", "")
    if not re.fullmatch(r"(?:COM\d+|/dev/[A-Za-z0-9._/-]+)", port):
        raise ValueError("UART_PORT must be an explicit serial device")
    return UartAuditor(
        port=port,
        baud=int(os.getenv("UART_BAUD", "115200")),
        username=os.getenv("UART_AUDIT_USERNAME"),
        password=os.getenv("UART_AUDIT_PASSWORD"),
    )


class UartAuditor:
    def __init__(self, port, baud=115200, username=None, password=None, serial_factory=None):
        if baud != 115200:
            raise ValueError("Only the reviewed 115200 baud profile is supported")
        self.port, self.baud = port, baud
        self.username, self.password = username, password
        self.serial_factory = serial_factory or self._serial
        self.lock = asyncio.Lock()

    def _serial(self):
        import serial

        return serial.Serial(
            self.port,
            self.baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.1,
            write_timeout=1,
            rtscts=False,
            dsrdtr=False,
            xonxoff=False,
        )

    @staticmethod
    def _safe_transcript(data, password=None):
        text = data.decode("utf-8", "replace").replace("\x1b", "")
        text = re.sub(r"(?i)(default username:password is \[)[^]]+(\])", r"\1REDACTED\2", text)
        if password:
            text = text.replace(password, "[REDACTED]")
        return sanitize(text)[-16384:]

    @staticmethod
    def _read_available(serial_port, transcript):
        waiting = getattr(serial_port, "in_waiting", 0)
        if waiting:
            transcript.extend(serial_port.read(min(waiting, 4096)))

    def _run_sync(self, request):
        started = now()
        transcript = bytearray()
        errors = []
        sent_interrupt = login_sent = password_sent = checks_sent = logout_sent = False
        deadline = time.monotonic() + request.timeout_seconds
        try:
            serial_port = self.serial_factory()
        except Exception as exc:
            raise UartAuditError("uart_unavailable") from exc
        try:
            reset_input = getattr(serial_port, "reset_input_buffer", None)
            if reset_input:
                reset_input()
            if request.mode == "credential_check":
                serial_port.write(b"\r")
            while time.monotonic() < deadline:
                self._read_available(serial_port, transcript)
                if len(transcript) > 65536:
                    errors.append("transcript_limit_reached")
                    break
                text = transcript.decode("utf-8", "replace")
                if (
                    request.mode == "interrupt"
                    and not sent_interrupt
                    and "Press SPACE to abort autoboot" in text
                ):
                    serial_port.write(b" ")
                    sent_interrupt = True
                if request.mode == "interrupt" and sent_interrupt and re.search(r"(?m)^=>\s*$", text):
                    break
                if request.mode == "credential_check":
                    if not self.username or not self.password:
                        errors.append("configured_credentials_missing")
                        break
                    if not login_sent and re.search(r"login:\s*$", text):
                        serial_port.write(self.username.encode("utf-8") + b"\r")
                        login_sent = True
                    elif login_sent and not password_sent and re.search(r"Password:\s*$", text):
                        serial_port.write(self.password.encode("utf-8") + b"\r")
                        password_sent = True
                    elif password_sent and not checks_sent and re.search(r"(?m)[$#>]\s*$", text):
                        serial_port.write(b"id; uname -r; sudo -n id\r")
                        checks_sent = True
                    elif checks_sent and not logout_sent and "uid=0(root)" in text:
                        serial_port.write(b"exit\r")
                        logout_sent = True
                    if logout_sent and "logout" in text:
                        break
                if request.mode == "observe" and "login:" in text:
                    break
                time.sleep(0.02)
            self._read_available(serial_port, transcript)
        except Exception:  # noqa: BLE001 -- never expose serial driver details
            errors.append("uart_io_failed")
        finally:
            with suppress(Exception):
                serial_port.close()

        raw = bytes(transcript)
        if not raw and "no_uart_data_received" not in errors:
            errors.append("no_uart_data_received")
        text = raw.decode("utf-8", "replace")
        uboot = re.search(r"U-Boot\s+([^\r\n]+)", text)
        kernel = re.search(r"Linux\s+\S+\s+([^\s]+)", text)
        login_succeeded = bool(re.search(r"uid=\d+\([^)]+\)", text))
        observations = []
        if "Press SPACE to abort autoboot" in text:
            observations.append("U-Boot advertises an unauthenticated autoboot interruption window")
        if "default username:password" in text.lower():
            observations.append("Boot console advertises vendor-default credentials")
        if login_succeeded:
            observations.append("Configured UART account authenticated successfully")
        if "uid=0(root)" in text:
            observations.append("Configured account obtained non-interactive root identity")
        if re.search(r"(?m)^=>\s*$", text):
            observations.append("U-Boot command prompt obtained by a single Space character")
        status = "failed" if not raw else "partial" if errors else "completed"
        return UartAuditResult(
            mode=request.mode,
            status=status,
            port=self.port,
            baud=self.baud,
            started_at=started,
            transcript_hash=hashlib.sha256(raw).hexdigest(),
            transcript_bytes=len(raw),
            transcript_excerpt=self._safe_transcript(raw, self.password),
            uboot_version=uboot.group(1) if uboot else None,
            kernel_version=kernel.group(1) if kernel else None,
            boot_observed="U-Boot" in text and "Starting kernel" in text,
            autoboot_interrupt_window="Press SPACE to abort autoboot" in text,
            uboot_prompt_obtained=bool(re.search(r"(?m)^=>\s*$", text)),
            default_credentials_advertised="default username:password" in text.lower(),
            configured_login_attempted=login_sent,
            configured_login_succeeded=login_succeeded,
            root_without_additional_prompt="uid=0(root)" in text,
            observations=observations,
            errors=errors,
        )

    async def run(self, request: UartAuditRequest):
        if self.lock.locked():
            raise UartAuditError("uart_audit_in_progress")
        async with self.lock:
            return await asyncio.to_thread(self._run_sync, request)
