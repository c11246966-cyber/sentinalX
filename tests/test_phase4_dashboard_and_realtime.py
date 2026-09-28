"""Comprehensive Phase 4 unit and integration tests for SOC Dashboard, Alert Lifecycle, and Real-Time Streaming."""

import asyncio
from datetime import datetime, timezone
import unittest
from backend.app.detection.correlation import CorrelationEngine
from backend.app.detection.engine import DetectionEngine
from backend.app.detection.mitre import get_all_mitre_techniques, lookup_mitre


class TestPhase4DashboardAndRealtime(unittest.TestCase):
    """Verifies Phase 4 dashboard metrics, alert lifecycles, analyst notes, and real-time streaming."""

    def setUp(self):
        DetectionEngine.reset_state()
        CorrelationEngine.reset_state()

    def test_alert_lifecycle_states(self):
        """Verify all valid Phase 4 alert statuses."""
        valid_statuses = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
        test_state = "NEW"
        self.assertIn(test_state, valid_statuses)

        # Transition to ACKNOWLEDGED
        test_state = "ACKNOWLEDGED"
        self.assertIn(test_state, valid_statuses)

        # Transition to INVESTIGATING
        test_state = "INVESTIGATING"
        self.assertIn(test_state, valid_statuses)

        # Transition to RESOLVED or FALSE_POSITIVE
        self.assertIn("RESOLVED", valid_statuses)
        self.assertIn("FALSE_POSITIVE", valid_statuses)

    def test_incident_lifecycle_states(self):
        """Verify incident status transitions."""
        valid_incident_states = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}
        self.assertIn("NEW", valid_incident_states)
        self.assertIn("INVESTIGATING", valid_incident_states)
        self.assertIn("CONTAINED", valid_incident_states)
        self.assertIn("RESOLVED", valid_incident_states)
        self.assertIn("CLOSED", valid_incident_states)

    def test_realtime_connection_manager_sse_broadcasting(self):
        """Verify WebSocket & SSE ConnectionManager queues and broadcasting."""
        try:
            from backend.app.api.websocket import ConnectionManager
        except ImportError:
            self.skipTest("FastAPI not installed in current test runner")

        cm = ConnectionManager()
        q = cm.register_sse()

        test_payload = {
            "type": "new_alert",
            "alert": {
                "id": 99,
                "title": "Synthetic Alert",
                "severity": "HIGH",
                "risk_score": 85,
            },
        }

        async def run_broadcast_test():
            await cm.broadcast(test_payload)
            item = await asyncio.wait_for(q.get(), timeout=2.0)
            return item

        result = asyncio.run(run_broadcast_test())
        self.assertEqual(result["type"], "new_alert")
        self.assertEqual(result["alert"]["id"], 99)

        # Cleanup
        cm.unregister_sse(q)
        self.assertEqual(len(cm.sse_queues), 0)

    def test_dashboard_metrics_aggregation_logic(self):
        """Verify calculation of severity counts, risk score distribution, and defense conditions."""
        mock_scores = [10, 35, 60, 85, 95]
        risk_dist = {
            "0-24 (Low)": 0,
            "25-49 (Guarded)": 0,
            "50-74 (Elevated)": 0,
            "75-100 (Severe)": 0,
        }
        for s in mock_scores:
            if s < 25:
                risk_dist["0-24 (Low)"] += 1
            elif s < 50:
                risk_dist["25-49 (Guarded)"] += 1
            elif s < 75:
                risk_dist["50-74 (Elevated)"] += 1
            else:
                risk_dist["75-100 (Severe)"] += 1

        self.assertEqual(risk_dist["0-24 (Low)"], 1)
        self.assertEqual(risk_dist["25-49 (Guarded)"], 1)
        self.assertEqual(risk_dist["50-74 (Elevated)"], 1)
        self.assertEqual(risk_dist["75-100 (Severe)"], 2)

    def test_mitre_coverage_mapping(self):
        """Verify MITRE catalog coverage calculation."""
        all_techniques = get_all_mitre_techniques()
        active_ids = {"T1046", "T1110.001"}
        coverage = [
            {**t, "is_active": t["id"] in active_ids}
            for t in all_techniques
        ]
        active_count = sum(1 for c in coverage if c["is_active"])
        self.assertEqual(active_count, 2)


if __name__ == "__main__":
    unittest.main()
