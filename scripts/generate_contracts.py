import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("EDGE_API_KEY", "schema-only-not-a-real-key")
os.environ.setdefault("DASHBOARD_PASSWORD", "schema-only-password")
from edge.app import create_app as edge_app
from orchestrator.app import create_app as orchestrator_app

root = Path(__file__).resolve().parents[1]
schema = orchestrator_app().openapi()
edge = edge_app().openapi()
schema["paths"].update(edge["paths"])
schema["components"]["schemas"].update(edge["components"]["schemas"])
(root / "contracts/openapi.json").write_text(json.dumps(schema, indent=2) + "\n")
