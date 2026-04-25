"""
Day 1 ingress: a local file path.

Validates that the path exists, is a regular file, and has a supported
extension. Returns an absolute, resolved ``Path``.
"""

from __future__ import annotations

from pathlib import Path

SUPPORTED_EXTENSIONS = {".py", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}


def ingest_local(source: Path) -> Path:
    p = Path(source).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Source file does not exist: {p}")
    if not p.is_file():
        raise IsADirectoryError(f"Source path is not a regular file: {p}")
    if p.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension {p.suffix!r}. "
            f"Supported: {sorted(SUPPORTED_EXTENSIONS)}"
        )
    return p
