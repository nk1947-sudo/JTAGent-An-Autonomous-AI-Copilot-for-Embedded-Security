# Synthetic fixtures
synthetic.py deterministically constructs two little-endian ARM-profile RAM segments.
All data is invented; the addresses do not establish the location of U-Boot on any board.

The code block begins with ARM mov/add/bx instructions and then zero padding. The data block includes
a synthetic U-Boot label, text environment candidates, harmless shell documentation, a prompt injection
string and a synthetic password. MOCK_VARIANT=clean substitutes a clean control data block.
Expected observations are asserted in tests and are not supplied to inference.

Run uv run python scripts/make_replay.py to regenerate replay.json. Its fixed date is fixture
metadata, not a physical capture timestamp. Each segment includes its address, exact hex and SHA256;
the manifest includes the profile, register values and provenance. A hash mismatch fails startup.
Replay is read-only and cannot silently replace an unavailable OpenOCD backend.

Live captures must not be committed here. Raw target bytes are transient on the edge and are withheld
from the cloud by default. There is no raw live-export API in this MVP; deliberate capture import
uses an operator-produced replay manifest from a separate, trusted local capture procedure.
