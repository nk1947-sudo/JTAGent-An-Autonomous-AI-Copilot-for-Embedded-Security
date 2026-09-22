"""Local ELF metadata inspection; never loads or executes the supplied file."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis.evidence import elf_metadata

parser = argparse.ArgumentParser()
parser.add_argument("path", type=Path)
args = parser.parse_args()
if args.path.stat().st_size > 16 * 1024 * 1024:
    parser.error("ELF exceeds 16 MiB input limit")
print(json.dumps(elf_metadata(args.path.read_bytes()), indent=2))
