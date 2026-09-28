"""Explainable 0-100 risk scoring engine based on explicit cyber defense metrics."""

from typing import Any, Dict, List, Tuple


class RiskScoringEngine:
    """Calculates deterministic, fully explainable risk scores without black-box AI.
    
    Formula components:
    1. Base severity points (0-35)
    2. Frequency / occurrence multiplier (0-20)
    3. Detection confidence (0-15)
    4. Asset & user context criticality (0-15)
    5. Correlation cluster size (0-15)
    """

    SEVERITY_WEIGHTS = {
        "INFORMATIONAL": 5,
        "LOW": 15,
        "MEDIUM": 25,
        "HIGH": 35,
        "CRITICAL": 45,
    }

    MITRE_TACTIC_WEIGHTS = {
        "Discovery": 5,
        "Execution": 15,
        "Persistence": 15,
        "Privilege Escalation": 20,
        "Credential Access": 20,
        "Initial Access": 20,
        "Impact": 25,
    }

    @classmethod
    def score_detection(
        cls,
        severity: str,
        confidence: int,
        event_count: int = 1,
        asset_criticality: str = "medium",  # low, medium, high, critical
        user_is_privileged: bool = False,
        mitre_tactic: str = "",
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        """Compute transparent 0-100 score with line-item factor breakdown."""
        factors: List[Dict[str, Any]] = []

        # 1. Base Severity Points
        sev_pts = cls.SEVERITY_WEIGHTS.get(severity.upper(), 15)
        factors.append({"factor": f"Base severity ({severity})", "points": sev_pts})

        # 2. Event frequency & burst volume
        freq_pts = min(20, int(min(event_count, 20) * 1.0))
        factors.append({"factor": f"Event volume ({event_count} telemetry events)", "points": freq_pts})

        # 3. Detection rule confidence
        conf_pts = min(15, int(max(0, confidence) * 0.15))
        factors.append({"factor": f"Rule confidence ({confidence}%)", "points": conf_pts})

        # 4. Asset Context & Privileged Account
        asset_pts = 5
        if asset_criticality == "critical":
            asset_pts = 12
        elif asset_criticality == "high":
            asset_pts = 9
        elif asset_criticality == "low":
            asset_pts = 2
        factors.append({"factor": f"Asset criticality ({asset_criticality})", "points": asset_pts})

        if user_is_privileged:
            factors.append({"factor": "Privileged user targeted / involved", "points": 10})

        # 5. MITRE Tactic Weighting
        if mitre_tactic and mitre_tactic in cls.MITRE_TACTIC_WEIGHTS:
            tac_pts = cls.MITRE_TACTIC_WEIGHTS[mitre_tactic]
            factors.append({"factor": f"MITRE Tactic ({mitre_tactic})", "points": tac_pts})

        score, calculated_sev = cls.calculate_score(factors)
        # If the calling detection rule is inherently CRITICAL, preserve CRITICAL severity
        final_sev = severity.upper() if severity.upper() == "CRITICAL" else calculated_sev
        return score, final_sev, factors

    @staticmethod
    def calculate_score(factors: List[Dict[str, Any]]) -> Tuple[int, str]:
        """Aggregate factor points into a clamped 0-100 risk score with severity."""
        total = sum(f.get("points", 0) for f in factors)
        score = max(0, min(100, total))

        if score >= 90:
            severity = "CRITICAL"
        elif score >= 75:
            severity = "HIGH"
        elif score >= 50:
            severity = "MEDIUM"
        elif score >= 25:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        return score, severity
