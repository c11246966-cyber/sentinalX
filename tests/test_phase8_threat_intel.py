"""Unit and integration test suite for SentinelX Phase 8: Local Threat Intelligence & IOC Enrichment."""

import asyncio
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app.threat_intel.indicator import (
    IndicatorType,
    classify_indicator,
    extract_indicators,
    get_specific_hash_type,
    is_private_or_reserved_ip,
    is_ssrf_risk,
    is_valid_domain,
    is_valid_hash,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_md5,
    is_valid_sha1,
    is_valid_sha256,
    is_valid_url,
    validate_indicator,
)
from backend.app.threat_intel.providers.internal import InternalIntelProvider
from backend.app.threat_intel.risk_adjuster import ThreatIntelRiskAdjuster
from backend.app.threat_intel.service import ThreatIntelManager
from backend.app.threat_intel.cache import ThreatIntelCache
from backend.app.api.websocket import manager as ws_manager


class MockWebSocket:
    """Mock WebSocket client for integration testing."""

    def __init__(self):
        self.accepted = False
        self.closed = False
        self.sent_messages = []

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=None):
        self.closed = True

    async def send_json(self, data):
        self.sent_messages.append(data)


class TestPhase8LocalThreatIntelligence(unittest.TestCase):
    """Phase 8 Local Threat Intelligence & IOC Enrichment Test Suite."""

    def setUp(self):
        self.internal_provider = InternalIntelProvider()
        # Reset memory cache before tests
        ThreatIntelCache._memory_cache.clear()
        ThreatIntelCache._memory_expiry.clear()

    # --------------------------------------------------------------------------
    # 1. Indicator Types & Validation Tests
    # --------------------------------------------------------------------------

    def test_ipv4_validation_and_enrichment(self):
        """Verify IPv4 validation, classification, and internal enrichment."""
        # Malicious synthetic lab adversary
        valid, can, ind_type = validate_indicator("198.51.100.23", "ipv4")
        self.assertTrue(valid)
        self.assertEqual(ind_type, "ipv4")

        result = asyncio.run(self.internal_provider.enrich("198.51.100.23", "ipv4"))
        self.assertIsNotNone(result)
        self.assertTrue(result["known"])
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["threat_category"], "Brute Force / SSH Attack")
        self.assertEqual(result["source"], "internal")
        self.assertEqual(result["confidence"], 90)
        self.assertIn("matching_reason", result)

        # Benign trusted DNS
        res_clean = asyncio.run(self.internal_provider.enrich("8.8.8.8", "ipv4"))
        self.assertTrue(res_clean["known"])
        self.assertEqual(res_clean["reputation"], "clean")
        self.assertEqual(res_clean["threat_category"], "Benign / Trusted DNS")

    def test_ipv6_validation_and_enrichment(self):
        """Verify IPv6 validation and enrichment."""
        self.assertTrue(is_valid_ipv6("2001:db8::dead:beef"))
        self.assertTrue(is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertFalse(is_valid_ipv6("not-an-ipv6"))

        result = asyncio.run(self.internal_provider.enrich("2001:db8::dead:beef", "ipv6"))
        self.assertTrue(result["known"])
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["threat_category"], "IPv6 Adversary / C2")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["confidence"], 90)

    def test_domain_validation_and_enrichment(self):
        """Verify domain validation and local IOC lookup."""
        self.assertTrue(is_valid_domain("malware-c2-test.internal"))
        self.assertTrue(is_valid_domain("phishing-test.lab"))
        self.assertFalse(is_valid_domain("invalid domain with spaces.com"))

        c2_res = asyncio.run(self.internal_provider.enrich("malware-c2-test.internal", "domain"))
        self.assertTrue(c2_res["known"])
        self.assertEqual(c2_res["reputation"], "malicious")
        self.assertEqual(c2_res["threat_category"], "Command & Control (C2)")
        self.assertEqual(c2_res["severity"], "CRITICAL")
        self.assertEqual(c2_res["confidence"], 95)

        phish_res = asyncio.run(self.internal_provider.enrich("phishing-test.lab", "domain"))
        self.assertTrue(phish_res["known"])
        self.assertEqual(phish_res["reputation"], "malicious")
        self.assertEqual(phish_res["threat_category"], "Credential Harvesting / Phishing")

    def test_url_validation_and_enrichment(self):
        """Verify URL validation, SSRF checks, and enrichment."""
        # Valid URLs
        self.assertTrue(is_valid_url("http://malware-c2-test.internal/beacon"))
        self.assertTrue(is_valid_url("https://phishing-test.lab/login/verify.php"))
        # Invalid / dangerous schemes
        self.assertFalse(is_valid_url("javascript:alert(1)"))
        self.assertFalse(is_valid_url("file:///etc/passwd"))
        self.assertFalse(is_valid_url("data:text/html;base64,PHNjcmlwdD4="))
        self.assertFalse(is_valid_url("not-a-url"))

        res = asyncio.run(self.internal_provider.enrich("http://malware-c2-test.internal/beacon", "url"))
        self.assertTrue(res["known"])
        self.assertEqual(res["reputation"], "malicious")
        self.assertEqual(res["threat_category"], "Command & Control (C2)")
        self.assertEqual(res["severity"], "CRITICAL")

    def test_hash_enrichment_md5_sha1_sha256(self):
        """Verify individual MD5, SHA1, and SHA256 validation and enrichment."""
        # MD5: 32 hex chars
        md5_eicar = "44d88612fea8a8f36de82e1278abb02f"
        self.assertTrue(is_valid_md5(md5_eicar))
        self.assertEqual(get_specific_hash_type(md5_eicar), IndicatorType.MD5)
        md5_res = asyncio.run(self.internal_provider.enrich(md5_eicar, "md5"))
        self.assertTrue(md5_res["known"])
        self.assertEqual(md5_res["reputation"], "malicious")
        self.assertEqual(md5_res["severity"], "CRITICAL")
        self.assertEqual(md5_res["threat_category"], "Malware / Antivirus Test")

        # SHA1: 40 hex chars
        sha1_eicar = "3395856ce81f2b7382dee72602f798b642f14140"
        self.assertTrue(is_valid_sha1(sha1_eicar))
        self.assertEqual(get_specific_hash_type(sha1_eicar), IndicatorType.SHA1)
        sha1_res = asyncio.run(self.internal_provider.enrich(sha1_eicar, "sha1"))
        self.assertTrue(sha1_res["known"])
        self.assertEqual(sha1_res["reputation"], "malicious")

        # SHA256: 64 hex chars
        sha256_eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        self.assertTrue(is_valid_sha256(sha256_eicar))
        self.assertEqual(get_specific_hash_type(sha256_eicar), IndicatorType.SHA256)
        sha256_res = asyncio.run(self.internal_provider.enrich(sha256_eicar, "sha256"))
        self.assertTrue(sha256_res["known"])
        self.assertEqual(sha256_res["reputation"], "malicious")

        # Benign zero-byte hash
        sha256_clean = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        clean_res = asyncio.run(self.internal_provider.enrich(sha256_clean, "sha256"))
        self.assertTrue(clean_res["known"])
        self.assertEqual(clean_res["reputation"], "clean")
        self.assertEqual(clean_res["threat_category"], "Benign / Zero Byte")

    # --------------------------------------------------------------------------
    # 2. Private / Reserved Address Handling (SSRF Safety)
    # --------------------------------------------------------------------------

    def test_private_and_reserved_address_handling(self):
        """Verify private and reserved addresses are classified internally as clean/internal."""
        private_ips = [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.5.20",
            "172.31.255.255",
            "192.168.1.1",
            "192.168.100.50",
            "127.0.0.1",
            "169.254.169.254",
        ]
        for ip in private_ips:
            self.assertTrue(is_private_or_reserved_ip(ip), f"{ip} must be identified as private/reserved")
            res = asyncio.run(self.internal_provider.enrich(ip, "ipv4"))
            self.assertTrue(res["known"])
            self.assertEqual(res["reputation"], "clean", f"{ip} must be clean")
            self.assertEqual(res["severity"], "INFORMATIONAL")
            self.assertEqual(res["threat_category"], "Internal Infrastructure")
            self.assertEqual(res["confidence"], 100)
            self.assertEqual(res["source"], "internal")

        # Localhost and cloud metadata
        self.assertTrue(is_ssrf_risk("127.0.0.1", "ipv4"))
        self.assertTrue(is_ssrf_risk("metadata.google.internal", "domain"))
        self.assertTrue(is_ssrf_risk("http://169.254.169.254/latest/meta-data/", "url"))

    # --------------------------------------------------------------------------
    # 3. Unknown Indicators Behavior
    # --------------------------------------------------------------------------

    def test_unknown_indicator_handling(self):
        """Verify non-cataloged indicators return known=False, reputation=unknown, source=internal."""
        unknown_ip = "198.51.100.199"
        res = asyncio.run(self.internal_provider.enrich(unknown_ip, "ipv4"))
        self.assertFalse(res["known"])
        self.assertEqual(res["reputation"], "unknown")
        self.assertEqual(res["severity"], "LOW")
        self.assertEqual(res["confidence"], 0)
        self.assertEqual(res["threat_category"], "Uncategorized")
        self.assertEqual(res["source"], "internal")
        self.assertIn("No internal IOC match", res["matching_reason"])

    # --------------------------------------------------------------------------
    # 4. Indicator Extraction from Security Events
    # --------------------------------------------------------------------------

    def test_indicator_extraction_from_events(self):
        """Verify automated indicator extraction from normalized security events."""
        event = {
            "source_ip": "198.51.100.23",
            "destination_ip": "10.0.0.15",
            "hostname": "bastion-auth.internal",
            "command_line": "powershell -enc ... -url http://malware-c2-test.internal/beacon",
            "message": "Detected EICAR test signature 44d88612fea8a8f36de82e1278abb02f in temp folder",
        }
        extracted = extract_indicators(event)
        extracted_indicators = [e["indicator"] for e in extracted]

        self.assertIn("198.51.100.23", extracted_indicators)
        self.assertIn("10.0.0.15", extracted_indicators)
        self.assertIn("bastion-auth.internal", extracted_indicators)
        self.assertIn("http://malware-c2-test.internal/beacon", extracted_indicators)
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", extracted_indicators)

    # --------------------------------------------------------------------------
    # 5. Deterministic Risk-Scoring Integration
    # --------------------------------------------------------------------------

    def test_risk_score_adjustments(self):
        """Verify deterministic bounded risk adjustment based on IOC enrichment."""
        # 1. Malicious IOC increases risk
        malicious_intel = {
            "indicator": "198.51.100.23",
            "reputation": "malicious",
            "confidence": 90,
            "provider": "internal",
            "tags": ["known_scanner", "ssh_bruteforce"],
            "threat_category": "Brute Force / SSH Attack",
        }
        base_score = 60
        new_score, new_sev, reason, factors = ThreatIntelRiskAdjuster.adjust_risk(
            base_score=base_score,
            base_severity="MEDIUM",
            intel=malicious_intel,
        )
        self.assertGreater(new_score, base_score)
        self.assertLessEqual(new_score, 100)
        self.assertIn("Risk adjusted", reason)
        self.assertIn("MALICIOUS", reason)
        self.assertTrue(len(factors) > 0)

        # 2. High-impact tags bonus (c2, ransomware)
        c2_intel = {
            "indicator": "malware-c2-test.internal",
            "reputation": "malicious",
            "confidence": 95,
            "provider": "internal",
            "tags": ["c2", "ransomware", "trojan_dropper"],
            "threat_category": "Command & Control (C2)",
        }
        score_c2, sev_c2, reason_c2, factors_c2 = ThreatIntelRiskAdjuster.adjust_risk(
            base_score=75,
            base_severity="HIGH",
            intel=c2_intel,
        )
        self.assertGreaterEqual(score_c2, 90)
        self.assertEqual(sev_c2, "CRITICAL")
        self.assertTrue(any("High-impact threat tags" in f["factor"] for f in factors_c2))

        # 3. Benign verified reduction
        clean_intel = {
            "indicator": "10.0.0.10",
            "reputation": "clean",
            "confidence": 100,
            "provider": "internal",
            "tags": ["rfc1918_private"],
            "threat_category": "Internal Infrastructure",
        }
        score_clean, sev_clean, reason_clean, factors_clean = ThreatIntelRiskAdjuster.adjust_risk(
            base_score=50,
            base_severity="MEDIUM",
            intel=clean_intel,
        )
        self.assertEqual(score_clean, 45)  # -5 pts
        self.assertTrue(any("benign" in f["factor"].lower() for f in factors_clean))

        # 4. Strict clamping bounds [0, 100]
        score_max, _, _, _ = ThreatIntelRiskAdjuster.adjust_risk(base_score=95, base_severity="CRITICAL", intel=c2_intel)
        self.assertEqual(score_max, 100)

        score_min, _, _, _ = ThreatIntelRiskAdjuster.adjust_risk(base_score=2, base_severity="LOW", intel=clean_intel)
        self.assertGreaterEqual(score_min, 0)

    # --------------------------------------------------------------------------
    # 6. Provider Status & Offline Behavior (No External Calls)
    # --------------------------------------------------------------------------

    def test_provider_status_and_offline_guarantee(self):
        """Verify internal provider reports operational and external providers report unconfigured without keys."""
        statuses = ThreatIntelManager.get_provider_status()
        self.assertTrue(len(statuses) >= 4)

        internal_status = next((s for s in statuses if s["name"] == "Internal Curated Feed" or s.get("provider_id") == "internal"), None)
        self.assertIsNotNone(internal_status)
        self.assertTrue(internal_status["configured"])
        self.assertFalse(internal_status["external"])
        self.assertEqual(internal_status["status"], "operational")

        # External providers without API keys must be unconfigured
        for s in statuses:
            if s.get("provider_id") in ("virustotal", "abuseipdb", "alienvault_otx"):
                self.assertFalse(s["configured"])
                self.assertTrue(s["external"])
                self.assertEqual(s["status"], "unconfigured")

    # --------------------------------------------------------------------------
    # 7. Redis Unavailable Fallback & Caching
    # --------------------------------------------------------------------------

    def test_redis_unavailable_in_memory_caching(self):
        """Verify caching and enrichment operate smoothly using in-memory store when Redis is unavailable."""
        async def run_cache_test():
            # Inject simulated Redis failure
            with patch("backend.app.threat_intel.cache.get_redis", side_effect=ConnectionError("Redis connection refused")):
                indicator = "198.51.100.23"
                # 1. First lookup triggers internal provider query
                result1 = await ThreatIntelManager.enrich_indicator(indicator, indicator_type="ipv4", force_refresh=True)
                self.assertEqual(result1["reputation"], "malicious")

                # 2. In-memory cache should contain the entry
                key = ThreatIntelCache._make_key(indicator, "ipv4")
                self.assertIn(key, ThreatIntelCache._memory_cache)

                # 3. Second lookup retrieves from in-memory cache without errors
                result2 = await ThreatIntelManager.enrich_indicator(indicator, indicator_type="ipv4", force_refresh=False)
                self.assertEqual(result2["reputation"], "malicious")
                self.assertEqual(result2["indicator"], indicator)

        asyncio.run(run_cache_test())

    # --------------------------------------------------------------------------
    # 8. End-to-End Pipeline Integration Test
    # --------------------------------------------------------------------------

    def test_end_to_end_security_event_to_dashboard_pipeline(self):
        """Verify Security Event -> Extraction -> Local IOC Lookup -> Risk Adjustment -> Alert -> WebSocket broadcast."""
        async def run_pipeline():
            # Mock WebSocket client
            mock_ws = MockWebSocket()
            await ws_manager.connect(mock_ws, user_info={"sub": "soc_analyst", "role": "analyst"})

            # 1. Synthetic Security Event containing malicious test IOC
            raw_event = {
                "event_type": "ssh_login_failure",
                "source": "bastion-telemetry",
                "source_ip": "198.51.100.23",
                "destination_ip": "10.0.0.1",
                "destination_port": 22,
                "message": "Repeated invalid credentials from 198.51.100.23",
                "severity": "HIGH",
            }

            # 2. Indicator extraction
            indicators = extract_indicators(raw_event)
            self.assertTrue(len(indicators) >= 2)
            src_ioc = next(i for i in indicators if i["indicator"] == "198.51.100.23")
            self.assertEqual(src_ioc["indicator_type"], "ipv4")

            # 3. Local IOC lookup and enrichment
            enriched = await ThreatIntelManager.enrich_indicator(
                indicator=src_ioc["indicator"],
                indicator_type=src_ioc["indicator_type"],
            )
            self.assertTrue(enriched["known"])
            self.assertEqual(enriched["reputation"], "malicious")
            self.assertEqual(enriched["threat_category"], "Brute Force / SSH Attack")

            # 4. Risk score adjustment
            base_score = 65
            adjusted_score, adjusted_sev, reason, factors = ThreatIntelRiskAdjuster.adjust_risk(
                base_score=base_score,
                base_severity=raw_event["severity"],
                intel=enriched,
            )
            self.assertGreater(adjusted_score, base_score)
            self.assertIn("Risk adjusted", reason)

            # 5. Create alert
            alert = {
                "id": 1001,
                "title": f"Detection: SSH Brute Force from {src_ioc['indicator']}",
                "severity": adjusted_sev,
                "risk_score": adjusted_score,
                "threat_intel_context": enriched,
                "risk_adjustment_reason": reason,
                "source_ip": src_ioc["indicator"],
                "destination_ip": raw_event["destination_ip"],
            }

            # 6. Broadcast over WebSocket
            await ws_manager.broadcast_alert(alert, is_new=True)

            # 7. Verify WebSocket received structured alert.created message
            self.assertEqual(len(mock_ws.sent_messages), 1)
            sent_msg = mock_ws.sent_messages[0]
            self.assertEqual(sent_msg["type"], "alert.created")
            self.assertEqual(sent_msg["data"]["id"], 1001)
            self.assertEqual(sent_msg["data"]["risk_score"], adjusted_score)
            self.assertEqual(sent_msg["data"]["threat_intel_context"]["threat_category"], "Brute Force / SSH Attack")

            # Clean up
            ws_manager.disconnect(mock_ws)

        asyncio.run(run_pipeline())


if __name__ == "__main__":
    unittest.main()
