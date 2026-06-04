from typing import List, Dict, Any


class ComplianceScorer:
    """Calculates granular risk metrics based on regulatory findings density."""

    @staticmethod
    def calculate_metrics(findings: List[str], total_resources: int) -> Dict[str, Any]:
        if total_resources == 0:
            return {
                "compliance_score": 100,
                "critical_count": 0,
                "warning_count": 0,
                "info_count": 0,
                "risk_rating": "SECURE"
            }

        critical_count = 0
        warning_count = 0
        info_count = 0

        for finding in findings:
            finding_lower = finding.lower()
            if "violation" in finding_lower or "critical" in finding_lower:
                critical_count += 1
            elif "warning" in finding_lower or "unencrypted" in finding_lower:
                warning_count += 1
            else:
                info_count += 1

        # Score calculations: penalize and cap score
        base_penalty = (critical_count * 25) + (warning_count * 10) + (info_count * 2)
        score = max(0, min(100, 100 - base_penalty))

        # Risk band mapping
        if score >= 90:
            risk_rating = "LOW"
        elif score >= 70:
            risk_rating = "MEDIUM"
        else:
            risk_rating = "HIGH"

        return {
            "compliance_score": int(score),
            "critical_count": critical_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "risk_rating": risk_rating
        }
