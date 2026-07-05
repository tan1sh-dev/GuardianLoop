"""
SARIF artifact writer. Emits report.sarif (OASIS SARIF 2.1.0 standard).
Allows importing scan results directly into GitHub Code Scanning Security Alerts.
"""

from __future__ import annotations

import json
from pathlib import Path

from guardianloop.state import PipelineState

_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def write_sarif_artifact(state: PipelineState) -> Path:
    run_dir = state.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)

    rules = []
    results = []
    rule_ids = set()

    for ef in state.enriched_findings:
        f = ef.finding
        rule_id = f.rule_id
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f"Rule {rule_id}"},
                "fullDescription": {"text": f.message},
                "help": {"text": f"CWE: {f.cwe_id or 'N/A'}\nMessage: {f.message}"},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(f.severity, "warning")
                }
            })

        results.append({
            "ruleId": rule_id,
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line_start,
                            "endLine": f.line_end,
                        }
                    }
                }
            ]
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardianLoop",
                        "semanticVersion": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ]
    }

    sarif_path = run_dir / "report.sarif"
    sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
    return sarif_path
