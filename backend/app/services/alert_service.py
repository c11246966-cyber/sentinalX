"""Alert generation, triage, and state management service."""

from typing import Any, Dict, List


class AlertService:
    """Handles alert creation, risk score updating, and analyst status updates."""

    @staticmethod
    def create_alert_from_rule(rule_match: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "title": rule_match.get("title", "Detection Rule Alert"),
            "severity": rule_match.get("severity", "MEDIUM"),
            "risk_score": rule_match.get("risk_score", 50),
            "status": "NEW",
        }
