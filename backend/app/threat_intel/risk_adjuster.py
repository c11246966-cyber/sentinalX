"""Deterministic risk scoring adjustment based on threat intelligence telemetry."""

from typing import Any, Dict, List, Optional, Tuple


class ThreatIntelRiskAdjuster:
    """Calculates deterministic, fully explainable risk score adjustments.
    
    Guarantees:
    - Bounded within [0, 100]
    - Single provider cannot blindly turn every alert to CRITICAL
    - Full transparency and line-item adjustment explanation
    """

    @classmethod
    def adjust_risk(
        cls,
        base_score: int,
        base_severity: str,
        intel: Dict[str, Any],
    ) -> Tuple[int, str, str, List[Dict[str, Any]]]:
        """Adjust an alert's risk score and severity using threat intelligence context.
        
        Returns:
            (adjusted_score, adjusted_severity, reason_str, adjustment_factors)
        """
        reputation = (intel.get("reputation") or "unknown").lower()
        confidence = int(intel.get("confidence") or 0)
        provider = intel.get("provider") or "threat_intel"
        tags = [str(t).lower() for t in intel.get("tags") or []]
        providers_reporting = intel.get("providers_reporting") or [provider]

        adjustment_points = 0
        factors: List[Dict[str, Any]] = []

        if reputation == "malicious":
            # 1. Base malicious points scaled by confidence (15 to 25 pts)
            rep_pts = max(15, min(25, int(confidence * 0.25)))
            adjustment_points += rep_pts
            factors.append({
                "factor": f"Threat intel malicious reputation ({provider}, conf: {confidence}%)",
                "points": rep_pts,
            })

            # 2. Provider consensus bonus (+10 pts if >= 2 providers confirm)
            if len(providers_reporting) >= 2:
                adjustment_points += 10
                factors.append({
                    "factor": f"Multi-provider consensus ({len(providers_reporting)} providers confirmed threat)",
                    "points": 10,
                })

            # 3. High-impact IOC tags bonus (+5 pts)
            high_risk_tags = {"c2", "ransomware", "botnet", "tor_exit_node", "exploit", "ddos_botnet"}
            matched_tags = high_risk_tags.intersection(tags)
            if matched_tags:
                adjustment_points += 5
                factors.append({
                    "factor": f"High-impact threat tags: {', '.join(sorted(matched_tags))}",
                    "points": 5,
                })

        elif reputation == "suspicious":
            # Suspicious points (5 to 12 pts)
            susp_pts = max(5, min(12, int(confidence * 0.15)))
            adjustment_points += susp_pts
            factors.append({
                "factor": f"Threat intel suspicious reputation ({provider}, conf: {confidence}%)",
                "points": susp_pts,
            })

        elif reputation == "clean" and confidence >= 80:
            # Benign verified reduction (-5 pts) only if not inherently high/critical
            if base_severity.upper() not in ("CRITICAL", "HIGH"):
                adjustment_points -= 5
                factors.append({
                    "factor": f"Verified benign/clean indicator ({provider}, conf: {confidence}%)",
                    "points": -5,
                })

        # Calculate final clamped score
        new_score = max(0, min(100, base_score + adjustment_points))

        # Determine adjusted severity:
        # Avoid blindly making low alerts CRITICAL unless score actually reaches 90+
        if new_score >= 90:
            new_severity = "CRITICAL"
        elif new_score >= 75:
            new_severity = "HIGH"
        elif new_score >= 50:
            new_severity = "MEDIUM"
        elif new_score >= 25:
            new_severity = "LOW"
        else:
            new_severity = "INFORMATIONAL"

        # Build clear explainable reason string
        sign = f"+{adjustment_points}" if adjustment_points >= 0 else f"{adjustment_points}"
        reason = (
            f"Risk adjusted from {base_score} to {new_score} ({sign} pts): "
            f"Indicator {intel.get('indicator', '')} evaluated as {reputation.upper()} "
            f"(confidence {confidence}%) by {provider}."
        )
        if factors:
            reason += " Factors: " + "; ".join(f"{f['factor']} ({f['points']} pts)" for f in factors)

        return new_score, new_severity, reason, factors
