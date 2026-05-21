"""
Ingress: raw bytes from a browser file upload.

Saves the uploaded bytes to run_dir/source/<filename> and returns the path.
"""

from __future__ import annotations

from pathlib import Path

from guardianloop.ingress.local import SUPPORTED_EXTENSIONS


def ingest_upload(file_bytes: bytes, filename: str, run_dir: Path) -> Path:
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported extension {ext!r}. Supported: {sorted(SUPPORTED_EXTENSIONS)}"
        )
    source_dir = run_dir / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    dest = source_dir / Path(filename).name
    dest.write_bytes(file_bytes)
    return dest
