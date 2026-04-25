"""
Minimal read-only Streamlit viewer + one 'Run scan' button.

Pages:
  - Run scan          trigger the pipeline on a local file path
  - Upload file       Day 2 placeholder
  - View latest run   JSON dump of the selected run's artifacts
  - Audit report      rendered report.md for the selected run

Per CLAUDE.md, per-agent LangGraph state-trace view is explicitly out of scope.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import streamlit as st

from guardianloop.config import load_config

st.set_page_config(page_title="GuardianLoop", layout="wide")
st.title("GuardianLoop")
st.caption("Autonomous multi-agent security pipeline for C++ and Python")

cfg = load_config()
runs_root = Path(cfg.runs_dir)

page = st.sidebar.radio(
    "Page",
    ["Run scan", "Upload file", "View latest run", "Audit report"],
)


def _list_runs() -> list[Path]:
    if not runs_root.exists():
        return []
    return sorted((p for p in runs_root.iterdir() if p.is_dir()), reverse=True)


def _run_selector(label: str = "Select run") -> Path | None:
    runs = _list_runs()
    if not runs:
        st.info("No runs yet. Trigger one via 'Run scan' or `make demo`.")
        return None
    return st.selectbox(label, runs, format_func=lambda p: p.name)


if page == "Run scan":
    st.header("Run scan on a local file")
    path_str = st.text_input("Source file path", value="samples/demo_cwe121.cpp")
    if st.button("Run pipeline", type="primary"):
        source = Path(path_str)
        if not source.exists():
            st.error(f"File not found: {source}")
        else:
            st.info("Running pipeline — this may take a minute.")
            with st.spinner("Scanning, classifying, fixing, verifying..."):
                result = subprocess.run(
                    [sys.executable, "-m", "guardianloop.cli", str(source)],
                    capture_output=True,
                    text=True,
                )
            if result.returncode == 0:
                st.success("Pipeline complete.")
            else:
                st.error(f"Pipeline exited with code {result.returncode}.")
            if result.stdout:
                st.text("stdout")
                st.code(result.stdout)
            if result.stderr:
                st.text("stderr")
                st.code(result.stderr)

elif page == "Upload file":
    st.header("Upload file")
    st.warning(
        "File upload is a Day 2 deliverable. See `ingress/upload.py` and CLAUDE.md."
    )

elif page == "View latest run":
    st.header("Run results")
    run = _run_selector()
    if run is not None:
        summary_path = run / "run_summary.json"
        if summary_path.exists():
            st.subheader("Summary")
            st.json(json.loads(summary_path.read_text(encoding="utf-8")))
        else:
            st.warning(f"No run_summary.json in {run}.")

        enriched_path = run / "enriched_findings.json"
        if enriched_path.exists():
            st.subheader("Enriched findings")
            st.json(json.loads(enriched_path.read_text(encoding="utf-8")))

        verif_path = run / "verifications.json"
        if verif_path.exists():
            st.subheader("Verifications")
            st.json(json.loads(verif_path.read_text(encoding="utf-8")))

elif page == "Audit report":
    st.header("Audit report")
    run = _run_selector()
    if run is not None:
        report_path = run / "report.md"
        if report_path.exists():
            st.markdown(report_path.read_text(encoding="utf-8"))
        else:
            st.warning(f"No report.md in {run}.")
