"""Evidence bundles and the offline verifier. Fixture bytes only: no live evidence is invented."""

import asyncio
import json
import shutil

import httpx
import pytest

from analysis.bundle_verify import exit_code, verify_bundle
from edge.backends import MockBackend
from edge.service import EdgeService
from orchestrator.app import create_app as dashboard_app
from orchestrator.inference import ScriptedInference
from orchestrator.workflow import Workflow
from scripts.verify_bundle import main as verify_cli
from tests.test_status import PASSWORD, live
from tests.test_workflow import LocalEdge, run_state


@pytest.fixture
def raw_service(profile):
    return EdgeService(MockBackend(), profile, arm_snapshots=True, retain_raw=True)


@pytest.fixture(autouse=True)
def export_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))
    return tmp_path / "exports"


async def client_for(edge):
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dashboard_app(edge, ScriptedInference, PASSWORD)),
        base_url="http://test",
    )
    assert (await client.post("/api/login", json={"password": PASSWORD})).status_code == 200
    return client


async def finished_run(client, profile):
    body = {
        "target_id": profile.target_id,
        "purpose": "bootloader inspection",
        "region_names": ["demo-code", "demo-log"],
    }
    run = (await client.post("/api/runs", json=body)).json()
    for _ in range(100):
        state = (await client.get(f"/api/runs/{run['run_id']}")).json()
        if state["status"] not in ("queued", "running"):
            return state
        await asyncio.sleep(0.05)
    raise AssertionError("run did not finish")


async def export(client, path, include_raw):
    response = await client.post(path, json={"include_raw": include_raw})
    assert response.status_code == 200, response.text
    return response.json()


def bundle_path(result):
    from pathlib import Path

    return Path(result["path"])


async def test_fixture_bundle_exports_and_verifies_offline(raw_service, profile):
    client = await client_for(LocalEdge(raw_service))
    run = await finished_run(client, profile)
    result = await export(client, f"/api/runs/{run['run_id']}/bundle", True)
    assert result["verification"] == "VERIFIED", result["failed_checks"]
    assert result["raw_included"] == result["captures"] == 2
    path = bundle_path(result)
    verdict = verify_bundle(path)
    assert verdict.status == "VERIFIED" and not verdict.failures and not verdict.unverifiable
    assert verify_cli([str(path)]) == 0
    manifest = json.loads((path / "manifest.json").read_text())
    assert (
        manifest["hash_policy"]["algorithm"] == "sha256"
        and "not_proof_of_authenticity" in manifest["hash_policy"]
    )
    assert manifest["subject"] == {"kind": "run", "id": run["run_id"]}
    assert {c["raw_artifact"] for c in manifest["captures"]} == {
        f"captures/{c['evidence_id']}.bin" for c in run["captures"]
    }
    assert all(c["acquisition"]["initial_state"] == "running" for c in manifest["captures"])
    assert all(
        r["atomic_with_memory"] is False and r["paired_capture_evidence_id"] for r in manifest["registers"]
    )
    # JSON, Markdown and manifest agree.
    report = json.loads((path / "report.json").read_text())
    markdown = (path / "report.md").read_text()
    for capture in manifest["captures"]:
        assert capture["evidence_id"] in markdown and capture["content_hash"] in markdown
        assert capture["raw_artifact"] in markdown
        assert {c["evidence_id"]: c["content_hash"] for c in report["captures"]}[
            capture["evidence_id"]
        ] == capture["content_hash"]
    assert "## Register snapshots" in markdown and "pc = 0x" in markdown and "Acquisition:" in markdown
    assert "not proof" in markdown.lower() or "does not prove" in markdown


async def test_altered_bytes_and_artifacts_fail_verification(raw_service, profile, tmp_path):
    client = await client_for(LocalEdge(raw_service))
    run = await finished_run(client, profile)
    original = bundle_path(await export(client, f"/api/runs/{run['run_id']}/bundle", True))

    def variant(name):
        target = tmp_path / name
        shutil.copytree(original, target)
        return target

    flipped = variant("flipped")
    raw_file = next((flipped / "captures").glob("*.bin"))
    data = bytearray(raw_file.read_bytes())
    data[0] ^= 0xFF
    raw_file.write_bytes(bytes(data))
    result = verify_bundle(flipped)
    assert result.status == "FAILED" and any(
        "modified" in c.detail or "sha256" in c.detail for c in result.failures
    )
    assert verify_cli([str(flipped)]) == 1

    edited_report = variant("report")
    (edited_report / "report.md").write_text("tampered\n")
    assert verify_bundle(edited_report).status == "FAILED"

    swapped_hash = variant("hash")
    manifest = json.loads((swapped_hash / "manifest.json").read_text())
    manifest["captures"][0]["content_hash"] = "0" * 64
    (swapped_hash / "manifest.json").write_text(json.dumps(manifest))
    names = {c.name for c in verify_bundle(swapped_hash).failures}
    assert any(n.endswith(":hash") for n in names) and "report_json_captures" in names

    forged = variant("instructions")
    manifest = json.loads((forged / "manifest.json").read_text())
    code = next(c for c in manifest["captures"] if c["instructions"])
    code["instructions"][0]["mnemonic"] = "nop"
    (forged / "manifest.json").write_text(json.dumps(manifest))
    assert any(c.name.endswith(":instructions") for c in verify_bundle(forged).failures)

    short = variant("length")
    manifest = json.loads((short / "manifest.json").read_text())
    manifest["captures"][0]["returned_length"] += 1
    (short / "manifest.json").write_text(json.dumps(manifest))
    assert verify_bundle(short).status == "FAILED"

    outside = variant("range")
    manifest = json.loads((outside / "manifest.json").read_text())
    manifest["captures"][0]["base_address"] += 0x100000
    (outside / "manifest.json").write_text(json.dumps(manifest))
    assert any(c.name.endswith(":range") for c in verify_bundle(outside).failures)

    missing = variant("missing")
    next((missing / "captures").glob("*.bin")).unlink()
    assert verify_bundle(missing).status == "FAILED"

    traversal = variant("traversal")
    manifest = json.loads((traversal / "manifest.json").read_text())
    manifest["artifacts"][0]["path"] = "../outside.bin"
    (traversal / "manifest.json").write_text(json.dumps(manifest))
    assert any("unsafe" in c.detail for c in verify_bundle(traversal).failures)


async def test_unsupported_format_is_reported_not_verified(raw_service, profile, tmp_path):
    client = await client_for(LocalEdge(raw_service))
    run = await finished_run(client, profile)
    original = bundle_path(await export(client, f"/api/runs/{run['run_id']}/bundle", True))
    for change in ({"format": "something-else"}, {"format_version": 99}):
        target = tmp_path / ("unsupported-" + next(iter(change)))
        shutil.copytree(original, target)
        manifest = json.loads((target / "manifest.json").read_text())
        manifest.update(change)
        (target / "manifest.json").write_text(json.dumps(manifest))
        result = verify_bundle(target)
        assert result.status == "UNSUPPORTED" and exit_code(result) == 3
    assert verify_bundle(tmp_path / "does-not-exist").status == "UNSUPPORTED"


async def test_metadata_only_bundle_is_incomplete_and_says_so(profile):
    edge_without_retention = EdgeService(MockBackend(), profile, arm_snapshots=True)
    client = await client_for(LocalEdge(edge_without_retention))
    run = await finished_run(client, profile)
    result = await export(client, f"/api/runs/{run['run_id']}/bundle", False)
    assert result["verification"] == "INCOMPLETE" and result["raw_included"] == 0
    path = bundle_path(result)
    manifest = json.loads((path / "manifest.json").read_text())
    assert manifest["verification_claim"]["independent_hash_and_decode_verification"] == "unavailable"
    assert "NO raw bytes" in manifest["verification_claim"]["statement"]
    assert not list((path / "captures").glob("*.bin"))
    assert "metadata-only" in (path / "report.md").read_text()
    verdict = verify_bundle(path)
    assert verdict.status == "INCOMPLETE" and verdict.unverifiable and not verdict.failures
    assert verify_cli([str(path)]) == 2  # never reported as verified


async def test_raw_requested_but_not_retained_is_honestly_partial_or_unavailable(profile):
    client = await client_for(LocalEdge(EdgeService(MockBackend(), profile, arm_snapshots=True)))
    run = await finished_run(client, profile)
    result = await export(client, f"/api/runs/{run['run_id']}/bundle", True)
    manifest = json.loads((bundle_path(result) / "manifest.json").read_text())
    withheld = [c for c in manifest["captures"] if c["raw_status"] != "included"]
    assert withheld and all("cannot be recovered" in c["raw_note"] for c in withheld)
    assert result["verification"] == "INCOMPLETE"


async def test_bundles_survive_an_application_restart(raw_service, profile):
    edge = LocalEdge(raw_service)
    first = await client_for(edge)
    run = await finished_run(first, profile)
    result = await export(first, f"/api/runs/{run['run_id']}/bundle", True)
    restarted = await client_for(LocalEdge(EdgeService(MockBackend(), profile, arm_snapshots=True)))
    assert (await restarted.get(f"/api/runs/{run['run_id']}")).status_code == 404  # process memory is gone
    listed = (await restarted.get("/api/exports")).json()
    assert [b["bundle_id"] for b in listed] == [bundle_path(result).name]
    assert listed[0]["verification"] == "VERIFIED" and listed[0]["raw_included"] == 2
    manifest = await restarted.get(f"/api/exports/{listed[0]['bundle_id']}/manifest.json")
    assert manifest.status_code == 200 and manifest.json()["subject"]["id"] == run["run_id"]
    assert (await restarted.get(f"/api/exports/{listed[0]['bundle_id']}/../secret")).status_code == 404
    assert (await restarted.get(f"/api/exports/{listed[0]['bundle_id']}/captures")).status_code == 404


async def test_raw_bytes_stay_out_of_run_state_reports_and_inference_input(raw_service, profile):
    client = await client_for(LocalEdge(raw_service))
    run = await finished_run(client, profile)
    result = await export(client, f"/api/runs/{run['run_id']}/bundle", True)
    withheld = next(c for c in run["captures"] if c["evidence"]["withheld_reason"])
    raw = next((bundle_path(result) / "captures").glob(f"{withheld['evidence_id']}.bin")).read_bytes()
    assert raw and hashlib_hex(raw) == withheld["content_hash"]
    report_texts = [
        json.dumps(run),
        (await client.get(f"/api/runs/{run['run_id']}/report.md")).text,
        (await client.get(f"/api/runs/{run['run_id']}/report.json")).text,
    ]
    assert b"synthetic-secret" in raw  # the local export holds the real bytes ...
    assert all(
        raw.hex() not in text and "synthetic-secret" not in text for text in report_texts
    )  # ... nothing else does
    # The raw route is authenticated at the edge and only serves what was retained.
    assert (await LocalEdge(raw_service).client.get("/api/v1/evidence/not-an-id/raw")).status_code == 404
    unauthenticated = httpx.AsyncClient(
        transport=LocalEdge(raw_service).client._transport, base_url="http://edge"
    )
    assert (await unauthenticated.get(f"/api/v1/evidence/{withheld['evidence_id']}/raw")).status_code == 401


def hashlib_hex(data):
    import hashlib

    return hashlib.sha256(data).hexdigest()


async def test_historical_capture_without_acquisition_metadata_is_unknown(raw_service, profile, tmp_path):
    run = run_state(profile)
    await Workflow(run, LocalEdge(raw_service), ScriptedInference(), asyncio.Event(), "b").execute()
    run.acquisitions = []  # as if captured before acquisition metadata existed
    from orchestrator.bundle import build_bundle
    from orchestrator.report import markdown, report_data

    path, manifest = build_bundle(
        kind="run",
        subject=run,
        profile=profile,
        report_json=report_data(run),
        report_md=markdown(run),
        builds={"exporter_orchestrator": None, "edge_at_export": None},
        raw_by_id={},
        out_root=tmp_path,
        inference={"backend": "scripted"},
    )
    assert all(c["acquisition"]["status"] == "unknown" for c in manifest["captures"])
    assert all(r["pairing_basis"] == "index_order_assumed" for r in manifest["registers"])
    assert "unknown (captured before acquisition metadata was recorded)" in (path / "report.md").read_text()
    assert verify_bundle(path).status == "INCOMPLETE"
    assert not list(tmp_path.glob("*.partial"))  # atomic write leaves no partial directory


async def test_attack_plan_markdown_and_bundle_carry_the_capture_detail(raw_service, profile, monkeypatch):
    monkeypatch.setenv("ATTACK_LAB_LIVE_JTAG", "1")

    class PhysicalShapedEdge(LocalEdge):
        async def get(self, path):
            result = await super().get(path)
            if path == "/api/v1/target/status":
                live(result)
            return result

    client = await client_for(PhysicalShapedEdge(raw_service))
    plan = (
        await client.post(
            "/api/attack-lab/plans",
            json={
                "target_id": profile.target_id,
                "module_id": "jtag-debug-lock-audit",
                "objective": "Assess JTAG exposure",
                "authorization_acknowledged": True,
            },
        )
    ).json()
    pid = plan["plan_id"]
    for _ in range(2):
        plan = (await client.post(f"/api/attack-lab/plans/{pid}/execute-next")).json()
    await client.post(
        f"/api/attack-lab/plans/{pid}/steps/{plan['steps'][2]['step_id']}/decision",
        json={"decision": "approve", "note": "fixture"},
    )
    done = (await client.post(f"/api/attack-lab/plans/{pid}/execute-next")).json()
    assert done["status"] == "completed", done
    markdown = (await client.get(f"/api/attack-lab/plans/{pid}/report.md")).text
    capture, registers = done["captures"][0], done["registers"][0]
    # F-03: the Markdown export now carries what JSON always had.
    assert capture["content_hash"] in markdown and capture["evidence_id"] in markdown
    assert "## Register snapshots" in markdown and f"pc = 0x{registers['values']['pc']:08x}" in markdown
    assert "CPU state at capture: halted" in markdown and "restoration=running" in markdown
    assert f"0x{capture['evidence']['instructions'][0]['address']:08x}" in markdown
    result = await export(client, f"/api/attack-lab/plans/{pid}/bundle", True)
    assert result["verification"] == "VERIFIED" and result["subject_kind"] == "attack_plan"
    manifest = json.loads((bundle_path(result) / "manifest.json").read_text())
    assert manifest["captures"][0]["acquisition"]["restoration"] == "running"
    assert manifest["subject"]["id"] == pid
