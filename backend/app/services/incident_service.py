"""Incident aggregation and lifecycle service."""

from typing import Any, Dict, List


class IncidentService:
    """Manages multi-alert incidents and analyst assignments."""

    @staticmethod
    def aggregate_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "title": f"Aggregated Incident ({len(alerts)} alerts)",
            "status": "NEW",
            "risk_score": 75,
        }
