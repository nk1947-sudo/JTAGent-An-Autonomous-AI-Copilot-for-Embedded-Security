"""Opt-in paid provider gate. Sends a synthetic bounded task, never live bytes."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contracts.models import AuditRequest, TargetProfile
from edge.service import containing
from scripts.hosted_observation import ObservedNebius


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-paid-inference", action="store_true")
    args = parser.parse_args()
    if not args.allow_paid_inference:
        parser.error("--allow-paid-inference is required; ordinary tests never call the provider")
    provider = ObservedNebius(max_completions=1)
    try:
        print(json.dumps(await provider.preflight()))
        profile = TargetProfile.model_validate_json(Path("config/demo.json").read_text())
        request = AuditRequest(
            target_id=profile.target_id, purpose="firmware triage", region_names=["demo-code"]
        )
        proposals = await provider.plan(profile, request)
        for p in proposals:
            containing([profile.regions[0]], p.address, p.length, p.address_space)
        print(
            json.dumps(
                {
                    "tool_call_schema_valid": True,
                    **provider.observation(),
                    "note": "Tool-call smoke only; full evidence analysis gate requires a nebius audit",
                }
            )
        )
    finally:
        print(json.dumps({"request_observation": provider.observation()}))
        await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
