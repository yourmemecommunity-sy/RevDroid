"""The one Finding shape shared by every analyzer, the scorer, the UI and the PDF."""
from __future__ import annotations

from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def finding(*, id: str, title: str, severity: str, category: str, description: str,
            recommendation: str, source: str, evidence: str | None = None,
            locations: list[dict[str, Any]] | None = None, cwe: str | None = None,
            masvs: str | None = None, occurrences: int | None = None) -> dict[str, Any]:
    if severity not in SEVERITIES:
        raise ValueError(f"bad severity {severity}")
    locations = locations or []
    return {
        "id": id, "title": title, "severity": severity, "category": category,
        "description": description, "recommendation": recommendation,
        "source": source,            # manifest | code | signing
        "evidence": evidence,        # short, already-masked text
        "locations": locations,      # [{file, line, snippet}] - capped
        "occurrences": occurrences if occurrences is not None else max(1, len(locations)),
        "cwe": cwe, "masvs": masvs,
    }


def sort_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(items, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["category"], f["title"]))
