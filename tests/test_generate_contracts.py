"""Contract generation must be reproducible without live configuration or hardware."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from scripts import generate_contracts

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def poisoned_live_environment(monkeypatch):
    monkeypatch.setenv("TARGET_BACKEND", "openocd")
    monkeypatch.setenv("TARGET_PROFILE", str(ROOT / "config/__missing_contract_profile__.json"))
    monkeypatch.setenv("UART_AUDIT_ENABLED", "1")
    monkeypatch.setenv("UART_PORT", "invalid-port")
    monkeypatch.setenv("INFERENCE_BACKEND", "nebius")
    for name in ("EDGE_API_KEY", "DASHBOARD_PASSWORD", "NEBIUS_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_checked_in_contract_is_current_without_live_configuration(poisoned_live_environment):
    path = ROOT / "contracts/openapi.json"
    before = path.read_bytes(), path.stat().st_mtime_ns
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "scripts/generate_contracts.py"), "--check"],
        cwd=ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_contract_generation_and_drift_check_are_isolated(monkeypatch, poisoned_live_environment):
    with tempfile.TemporaryDirectory(prefix="contract-test-", dir=ROOT / "tmp") as directory:
        isolated_root = Path(directory)
        (isolated_root / "contracts").mkdir()
        monkeypatch.setattr(generate_contracts, "root", isolated_root)
        path = isolated_root / "contracts/openapi.json"

        generate_contracts.main([])
        generated = path.read_bytes()
        operation = json.loads(generated)["paths"]["/api/v1/memory/read"]["post"]
        assert any(p["name"] == "authorization" and p["in"] == "header" for p in operation["parameters"])
        generate_contracts.main(["--check"])
        assert path.read_bytes() == generated

        path.write_text("{}\n", encoding="utf-8")
        before = path.read_bytes(), path.stat().st_mtime_ns
        with pytest.raises(SystemExit, match="out of date"):
            generate_contracts.main(["--check"])
        assert (path.read_bytes(), path.stat().st_mtime_ns) == before
