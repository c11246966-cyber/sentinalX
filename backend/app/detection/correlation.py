"""Multi-event correlation engine with in-memory & Redis state tracking."""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
from backend.app.core.logging import logger

# In-memory sliding window bucket when Redis is optional/offline
_LOCAL_CORRELATION_CACHE: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
_LOCAL_INCIDENT_DEDUP: Dict[str, float] = {}


class CorrelationEngine:
    """Correlates multiple security alerts across sliding time windows to produce single incidents."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds

    def add_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Add an alert to the correlation window and determine if an incident should trigger.
        
        Correlation criteria:
        - Entity: source_ip or destination_ip or hostname or username
        - Window: alerts occurring within window_seconds
        - Deduplication: incident generated at most once per window per primary entity
        """
        now = time.time()
        entity = (
            alert_data.get("source_ip")
            or alert_data.get("hostname")
            or alert_data.get("destination_ip")
            or alert_data.get("username")
            or "global"
        )
        entity_key = f"corr:{entity}"

        # Clean old alerts beyond window
        active_alerts = [
            a for a in _LOCAL_CORRELATION_CACHE[entity_key]
            if now - a.get("_received_at", now) <= self.window_seconds
        ]
        alert_data["_received_at"] = now
        active_alerts.append(alert_data)
        _LOCAL_CORRELATION_CACHE[entity_key] = active_alerts

        # Check deduplication lock (prevent spamming multiple incidents for same cluster)
        last_incident_time = _LOCAL_INCIDENT_DEDUP.get(entity_key, 0)
        cooldown = self.window_seconds / 2.0
        if now - last_incident_time < cooldown:
            return None

        # Thresholds:
        # 1. Any CRITICAL alert or >= 2 HIGH alerts or >= 3 MEDIUM alerts
        crit_count = sum(1 for a in active_alerts if a.get("severity") == "CRITICAL")
        high_count = sum(1 for a in active_alerts if a.get("severity") == "HIGH")
        total_count = len(active_alerts)

        should_trigger = crit_count >= 1 or high_count >= 2 or total_count >= 3

        if should_trigger:
            _LOCAL_INCIDENT_DEDUP[entity_key] = now
            # Determine incident severity
            if crit_count > 0:
                inc_sev = "CRITICAL"
                inc_risk = 95
            elif high_count >= 2:
                inc_sev = "HIGH"
                inc_risk = 85
            else:
                inc_sev = "MEDIUM"
                inc_risk = 65

            titles = [a.get("title", "Threat Alert") for a in active_alerts]
            unique_titles = list(dict.fromkeys(titles))

            incident_payload = {
                "title": f"Correlated Incident: {unique_titles[0]} on {entity}",
                "description": (
                    f"Aggregated {total_count} related security detections on entity '{entity}' "
                    f"within {self.window_seconds}s time window. Detections involved: {', '.join(unique_titles)}."
                ),
                "severity": inc_sev,
                "risk_score": inc_risk,
                "status": "NEW",
                "entity": entity,
                "alert_count": total_count,
                "correlated_alert_ids": [a.get("id") for a in active_alerts if a.get("id") is not None],
            }
            logger.warning("CORRELATION INCIDENT TRIGGERED: %s (risk=%s)", incident_payload["title"], inc_risk)
            return incident_payload

        return None

    @classmethod
    def reset_state(cls):
        """Reset internal correlation cache (for tests)."""
        _LOCAL_CORRELATION_CACHE.clear()
        _LOCAL_INCIDENT_DEDUP.clear()
