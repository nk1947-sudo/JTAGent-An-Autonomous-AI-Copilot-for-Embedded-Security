"""Non-secret build identity for a running process.

Semantics (documented in docs/status-and-evidence.md):

* ``source_fingerprint`` is a SHA-256 over the relative path and content hash of the Python
  source files of this project, computed ONCE when the process builds its identity (in
  ``create_app``) and then cached. It describes the files as read at that moment. A file that is
  edited afterwards changes ``current_source_fingerprint`` but never the loaded identity.
* ``commit``/``dirty`` come from ``git`` at that same moment. A dirty tree means the commit alone
  does not describe the loaded code; the fingerprint does.
* ``source_drift`` compares the cached fingerprint with a freshly computed one, so an operator can
  see that the files on disk have moved on while the process still runs the older code.
* Python imports modules before ``create_app`` runs; a file edited in that short window could be
  loaded from the old content yet fingerprinted from the new one. Restart to reload.
"""

import hashlib
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from contracts.models import BuildIdentity

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("analysis", "contracts", "edge", "fixtures", "orchestrator")
VERSION = "0.1.0"
_cache: dict[str, BuildIdentity] = {}


def source_fingerprint(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _git(*args, root: Path = ROOT) -> str | None:
    try:
        done = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def load_build(component: str, root: Path = ROOT) -> BuildIdentity:
    """Return this process's identity, computing it exactly once per component."""
    if component not in _cache:
        commit = _git("rev-parse", "HEAD", root=root)
        porcelain = _git("status", "--porcelain", "--untracked-files=no", root=root)
        dirty = None if porcelain is None else bool(porcelain)
        fingerprint = source_fingerprint(root)
        label = (commit[:7] if commit else "nogit") + ("+dirty" if dirty else "")
        _cache[component] = BuildIdentity(
            component=component,
            version=VERSION,
            commit=commit,
            dirty=dirty,
            source_fingerprint=fingerprint,
            build_id=f"{label}:{fingerprint[:12]}",
            process_started_at=datetime.now(UTC).isoformat(),
            pid=os.getpid(),
            python=".".join(map(str, sys.version_info[:3])),
        )
    return _cache[component]


def source_drift(identity: BuildIdentity, root: Path = ROOT) -> bool:
    """True when files on disk no longer match the fingerprint this process loaded."""
    return source_fingerprint(root) != identity.source_fingerprint
