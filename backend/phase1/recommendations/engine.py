from typing import List, Dict


class RecommendationEngine:
    @staticmethod
    def generate(findings: List[Dict], score: float, category: str) -> str:
        if not findings:
            return "No security issues detected. Project meets security standards."

        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(findings, key=lambda x: priority_order.get(x.get("severity", "Low"), 3))

        lines = [f"Security Assessment for {category} project (Score: {score}/100)", ""]
        lines.append("Priority Remediation Steps:")

        seen = set()
        step = 1
        for f in sorted_findings[:15]:
            key = f.get("problem", "")
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"{step}. [{f.get('severity')}] {f.get('problem')}")
            lines.append(f"   Fix: {f.get('solution', 'Review and remediate')}")
            step += 1

        if score < 65:
            lines.append("")
            lines.append("Project requires remediation before monitoring can be enabled.")
            lines.append("Address all Critical issues first, then re-upload for rescan.")
        else:
            lines.append("")
            lines.append("Project approved for cloud security monitoring (Phase 2).")

        return "\n".join(lines)

    @staticmethod
    def top_risks(findings: List[Dict], limit: int = 5) -> List[Dict]:
        priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_f = sorted(findings, key=lambda x: priority.get(x.get("severity", "Low"), 3))
        return sorted_f[:limit]
