"""JSON report generator for programmatic consumption."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..db import FactStore


def generate_json_report(store: FactStore, output_path: Path,
                         profile_name: str = "") -> dict:
    """Generate a JSON export of the boundary mapping."""
    stats = store.stats()
    surfaces = store.get_surfaces()
    findings = store.get_findings(limit=500)

    report = {
        "meta": {
            "generated": datetime.now().isoformat(),
            "profile": profile_name,
            "version": "0.1.0",
        },
        "stats": stats,
        "surfaces": [
            {
                "id": s.id,
                "name": s.name,
                "type": s.boundary_type.value,
                "status": s.status.value,
                "kernel_entrypoint": s.kernel_entrypoint,
                "handler": s.handler,
                "userspace_producer": s.userspace_producer,
                "shared_contract": s.shared_contract,
                "dispatch_key": s.dispatch_key,
                "response_path": s.response_path,
                "description": s.description,
                "properties": s.properties,
                "evidence": [
                    {
                        "file": ev.file_path,
                        "line": ev.line_start,
                        "symbol": ev.symbol,
                        "method": ev.method.value,
                        "confidence": ev.confidence.value,
                        "note": ev.note,
                    }
                    for ev in s.evidence
                ],
            }
            for s in surfaces
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category,
                "status": f.status.value,
                "recommendation": f.recommendation,
                "evidence": [
                    {
                        "file": ev.file_path,
                        "line": ev.line_start,
                        "symbol": ev.symbol,
                        "method": ev.method.value,
                        "confidence": ev.confidence.value,
                    }
                    for ev in f.evidence
                ],
            }
            for f in findings
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fp:
        json.dump(report, fp, indent=2)
    return report
