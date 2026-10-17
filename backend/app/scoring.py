"""Explainable risk score.

In plain words:
1. Every distinct issue earns points by severity: critical 25, high 12,
   medium 5, low 1, info 0. The same issue found in 40 files counts once,
   plus a small "spread" bonus (+1 per extra 5 occurrences, at most +3),
   so one noisy rule cannot dominate the score.
2. Points are grouped by category and each category has a cap. This keeps
   the score balanced: 20 weak-hash calls cannot outweigh a leaked AWS key.
3. Each dangerous permission adds 1 point (cap 8); signature-level
   permissions add 2 each.
4. The total is clamped to 0..100. Higher means riskier.
5. Grade: A 0-10, B 11-25, C 26-45, D 46-65, F 66-100.
   Any critical finding forces at least a D.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
CATEGORY_CAPS = {
    "secrets": 45, "network": 30, "components": 30, "crypto": 20, "configuration": 25,
    "webview": 15, "storage": 15, "injection": 15, "logging": 8, "signing": 15, "permissions": 10,
}
DEFAULT_CAP = 15
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (100, "F")]


def grade_for(score: int) -> str:
    return next(g for limit, g in GRADES if score <= limit)


def score(findings: list[dict[str, Any]], permissions: list[dict[str, Any]]) -> dict[str, Any]:
    per_category: dict[str, float] = defaultdict(float)
    for f in findings:
        spread = min(3, max(0, (f.get("occurrences", 1) - 1) // 5))
        per_category[f["category"]] += WEIGHTS[f["severity"]] + (spread if WEIGHTS[f["severity"]] else 0)

    dangerous = sum(1 for p in permissions if p["protection_level"] == "dangerous")
    signature = sum(1 for p in permissions if p["protection_level"] == "signature")
    perm_points = min(8, dangerous) + 2 * signature
    per_category["permissions"] += perm_points

    breakdown = []
    for cat, raw in sorted(per_category.items(), key=lambda kv: -kv[1]):
        cap = CATEGORY_CAPS.get(cat, DEFAULT_CAP)
        breakdown.append({"category": cat, "raw_points": round(raw), "cap": cap, "points": round(min(raw, cap))})

    total = max(0, min(100, sum(b["points"] for b in breakdown)))
    grade = grade_for(total)
    severities = {s: sum(1 for f in findings if f["severity"] == s) for s in WEIGHTS}
    if severities["critical"] and grade in ("A", "B", "C"):
        grade = "D"
    return {
        "score": total, "grade": grade, "breakdown": breakdown, "severity_counts": severities,
        "permission_counts": {"dangerous": dangerous, "signature": signature,
                              "total": len(permissions)},
        "explanation": "Each distinct issue adds points by severity (critical 25, high 12, medium 5, low 1); "
                       "points are capped per category and the total is clamped to 0-100. "
                       "Higher is riskier. Grades: A <=10, B <=25, C <=45, D <=65, F >65; "
                       "any critical issue means at least a D.",
    }
