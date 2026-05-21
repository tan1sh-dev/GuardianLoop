"""
Ingress: code pasted directly into the dashboard textarea.

Auto-detects language if no filename is given, saves to run_dir/source/<filename>.
"""

from __future__ import annotations

from pathlib import Path

from guardianloop.ingress.local import SUPPORTED_EXTENSIONS

_CPP_HINTS = {"#include", "int main(", "::"}


def _detect_filename(code: str) -> str:
    if any(hint in code for hint in _CPP_HINTS):
        return "pasted.cpp"
    return "pasted.py"


def ingest_paste(code: str, filename: str, run_dir: Path) -> Path:
    if not filename:
        filename = _detect_filename(code)
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        filename = _detect_filename(code)
    source_dir = run_dir / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    dest = source_dir / filename
    dest.write_text(code, encoding="utf-8")
    return dest
