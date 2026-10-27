import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts.models import TargetProfile
from edge.app import create_app as edge_app
from edge.backends import MockBackend
from edge.service import EdgeService
from orchestrator.app import EdgeClient
from orchestrator.app import create_app as orchestrator_app

root = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate the combined OpenAPI contract")
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in contract differs")
    args = parser.parse_args(argv)

    profile = TargetProfile.model_validate_json(
        (Path(__file__).resolve().parents[1] / "config/demo.json").read_text(encoding="utf-8")
    )
    service = EdgeService(MockBackend(), profile)
    schema = orchestrator_app(
        edge=EdgeClient("http://127.0.0.1:8001", "schema-only-not-a-real-key"),
        password="schema-only-password",
    ).openapi()
    edge = edge_app(service=service, api_key="schema-only-not-a-real-key", uart_auditor=None).openapi()
    schema["paths"].update(edge["paths"])
    schema["components"]["schemas"].update(edge["components"]["schemas"])
    generated = json.dumps(schema, indent=2) + "\n"
    path = root / "contracts/openapi.json"
    if args.check:
        if not path.is_file() or path.read_text(encoding="utf-8") != generated:
            raise SystemExit("contracts/openapi.json is out of date; run scripts/generate_contracts.py")
    else:
        path.write_text(generated, encoding="utf-8")


if __name__ == "__main__":
    main()
