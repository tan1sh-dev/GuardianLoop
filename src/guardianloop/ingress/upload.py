"""
Day 2 ingress: Streamlit file upload.

Not implemented yet. Will accept a Streamlit ``UploadedFile`` from
``ui/streamlit_app.py``, persist it under ``runs/<ts>/uploaded/<name>``, and
return the resolved path for the pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def ingest_upload(uploaded_file: Any, run_dir: Path) -> Path:
    """DAY 2 — not yet implemented.

    Signature is frozen so `ui/streamlit_app.py` can import it.
    """
    raise NotImplementedError(
        "ingress.upload.ingest_upload is a Day 2 deliverable — see CLAUDE.md for scope."
    )
