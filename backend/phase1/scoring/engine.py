"""Phase 1 security scoring.

Uses diminishing penalties and soft saturation so large finding lists do not
collapse every project to 0/100. Duplicate issues of the same type cost less
than the first occurrence, which matches how industrial risk scores behave.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List


SEVERITY_BASE = {"Critical": 15, "High": 8, "Medium": 3.5, "Low": 1.2}

CATEGORY_WEIGHTS = {
    "Financial Application": {"Hardcoded Password": 1.35, "SQL Injection": 1.35, "Hardcoded API Key": 1.35},
    "Banking System": {"Hardcoded Password": 1.35, "SQL Injection": 1.35, "Hardcoded API Key": 1.35},
    "Hospital Management": {"Hardcoded Password": 1.25, "Hardcoded API Key": 1.25},
    "Healthcare": {"Hardcoded Password": 1.25, "Hardcoded API Key": 1.25},
    "Government": {"Default Password": 1.3, "Weak Secret": 1.3, "Hardcoded Password": 1.25},
    "Educational System": {"Hardcoded Password": 1.15, "SQL Injection": 1.15},
}


class ScoringEngine:
    @staticmethod
    def calculate(findings: List[Dict], category: str = "General Software") -> Dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        seen_problems: Dict[str, int] = defaultdict(int)
        raw_penalty = 0.0

        for finding in findings:
            severity = finding.get("severity", "Low")
            if severity in counts:
                counts[severity] += 1

            problem = finding.get("problem", "Finding")
            key = f"{severity}:{problem}"
            occurrence = seen_problems[key]
            seen_problems[key] += 1

            base = SEVERITY_BASE.get(severity, 1.2)
            # First hit full weight; repeats decay quickly.
            decay = 0.55 ** occurrence
            penalty = base * decay

            for problem_key, weight in CATEGORY_WEIGHTS.get(category, {}).items():
                if problem_key in problem:
                    penalty *= weight
                    break

            raw_penalty += penalty

        # Soft saturation: maps unbounded penalties into (0, ~92) so a busy
        # scan still leaves a readable residual score instead of always 0.
        mapped = 100 * (1 - math.exp(-raw_penalty / 55.0))
        score = max(0.0, min(100.0, 100.0 - mapped))

        if not findings:
            score = 100.0
        elif score < 12 and counts["Critical"] < 8:
            # Keep a small residual band for heavily flagged but finite scans.
            score = max(score, 12.0)

        risk_level = ScoringEngine._risk_level(score, counts["Critical"])

        return {
            "score": round(score, 1),
            "risk_level": risk_level,
            "counts": counts,
            "total_findings": len(findings),
            "unique_problems": len(seen_problems),
            "raw_penalty": round(raw_penalty, 2),
        }

    @staticmethod
    def _risk_level(score: float, critical: int) -> str:
        if critical >= 5 or score < 35:
            return "Critical"
        if critical > 0 or score < 55:
            return "High"
        if score < 75:
            return "Medium"
        return "Low"


class DecisionEngine:
    @staticmethod
    def decide(score: float, critical_count: int, threshold: int = 65) -> str:
        """Unlock Phase 2 monitoring when residual risk is acceptable.

        Score ≥ 65 is the primary gate. A small number of leftover critical
        findings is allowed so a 65+ scan is not blocked from monitoring.
        """
        critical_count = int(critical_count or 0)
        if score >= threshold and critical_count <= 2:
            return "Approved"
        if score >= threshold + 10 and critical_count <= 4:
            return "Approved"
        return "Pending Remediation"
