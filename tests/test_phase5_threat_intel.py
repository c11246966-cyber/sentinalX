"""Comprehensive Phase 5 tests for Threat Intelligence, Indicator Enrichment, and Risk Adjustment."""

import asyncio
from datetime import datetime, timezone
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from backend.app.threat_intel.cache import ThreatIntelCache
from backend.app.threat_intel.indicator import (
    IndicatorType,
    classify_indicator,
    extract_indicators,
    is_private_or_reserved_ip,
    is_ssrf_risk,
    validate_indicator,
)
from backend.app.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from backend.app.threat_intel.providers.internal import InternalIntelProvider
from backend.app.threat_intel.providers.otx import AlienVaultOTXProvider
from backend.app.threat_intel.providers.virustotal import VirusTotalProvider
from backend.app.threat_intel.risk_adjuster import ThreatIntelRiskAdjuster
from backend.app.threat_intel.service import ThreatIntelManager


class TestPhase5ThreatIntelligence(unittest.TestCase):
    """Verifies Phase 5 Threat Intelligence, caching, risk adjustment, and provider safety."""

    def setUp(self):
        ThreatIntelCache.clear_memory_cache()

    def test_provider_configuration_and_missing_keys(self):
        """Verify providers gracefully disable themselves when API keys are absent."""
        with patch.dict("os.environ", {}, clear=True):
            vt = VirusTotalProvider()
            abuse = AbuseIPDBProvider()
            otx = AlienVaultOTXProvider()
            internal = InternalIntelProvider()

            self.assertFalse(vt.is_configured())
            self.assertFalse(vt.is_available())
            self.assertFalse(abuse.is_configured())
            self.assertFalse(abuse.is_available())
            self.assertFalse(otx.is_configured())
            self.assertFalse(otx.is_available())

            # Internal provider is always configured
            self.assertTrue(internal.is_configured())
            self.assertTrue(internal.is_available())

            # Safe metadata never exposes credentials
            vt_meta = vt.safe_metadata()
            self.assertEqual(vt_meta["name"], "virustotal")
            self.assertFalse(vt_meta["configured"])
            self.assertNotIn("api_key", vt_meta)
            self.assertNotIn("key", vt_meta)

    def test_indicator_validation_and_classification(self):
        """Verify strict indicator validation and classification."""
        # Valid IPv4
        valid, can, ind_type = validate_indicator("198.51.100.23")
        self.assertTrue(valid)
        self.assertEqual(ind_type, IndicatorType.IPV4.value)
        self.assertEqual(can, "198.51.100.23")

        # Valid IPv6
        valid, can, ind_type = validate_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertTrue(valid)
        self.assertEqual(ind_type, IndicatorType.IPV6.value)

        # Valid Domain
        valid, can, ind_type = validate_indicator("malware-c2-test.internal")
        self.assertTrue(valid)
        self.assertEqual(ind_type, IndicatorType.DOMAIN.value)

        # Valid URL
        valid, can, ind_type = validate_indicator("https://phishing-test.lab/login?id=1")
        self.assertTrue(valid)
        self.assertEqual(ind_type, IndicatorType.URL.value)

        # Valid Hash (SHA256)
        valid, can, ind_type = validate_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertTrue(valid)
        self.assertEqual(ind_type, IndicatorType.HASH.value)

        # Invalid Indicators
        self.assertFalse(validate_indicator("not-an-ip-or-domain")[0])
        self.assertFalse(validate_indicator("999.999.999.999")[0])
        self.assertFalse(validate_indicator("javascript:alert(1)")[0])
        self.assertFalse(validate_indicator("")[0])

    def test_ssrf_safety_and_private_ip_isolation(self):
        """Verify SSRF risk detection for private, loopback, and cloud metadata addresses."""
        self.assertTrue(is_private_or_reserved_ip("127.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("10.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("192.168.1.100"))
        self.assertTrue(is_private_or_reserved_ip("172.16.0.5"))
        self.assertTrue(is_private_or_reserved_ip("169.254.169.254"))

        # Public IP is not SSRF risk
        self.assertFalse(is_private_or_reserved_ip("198.51.100.23"))

        # URL SSRF check
        self.assertTrue(is_ssrf_risk("http://127.0.0.1:8000/internal", "url"))
        self.assertTrue(is_ssrf_risk("http://metadata.google.internal/computeMetadata/v1", "url"))
        self.assertFalse(is_ssrf_risk("https://example.com/api", "url"))

    def test_indicator_extraction_from_events(self):
        """Verify automated indicator extraction from telemetry events."""
        event = {
            "source_ip": "198.51.100.50",
            "destination_ip": "10.0.0.10",
            "hostname": "prod-auth-01.company.local",
            "command_line": "powershell.exe -enc http://bad-domain.com/malware.exe",
            "message": "File downloaded hash 44d88612fea8a8f36de82e1278abb02f",
        }
        indicators = extract_indicators(event)
        extracted_vals = [i["indicator"] for i in indicators]

        self.assertIn("198.51.100.50", extracted_vals)
        self.assertIn("10.0.0.10", extracted_vals)
        self.assertIn("http://bad-domain.com/malware.exe", extracted_vals)
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", extracted_vals)

    def test_internal_provider_enrichment(self):
        """Verify internal provider returns accurate lab signatures and RFC1918 classification."""
        internal = InternalIntelProvider()

        # Known lab adversary
        res = asyncio.run(internal.enrich("198.51.100.23", "ipv4"))
        self.assertIsNotNone(res)
        self.assertEqual(res["reputation"], "malicious")
        self.assertEqual(res["confidence"], 90)
        self.assertEqual(res["severity"], "HIGH")
        self.assertIn("known_scanner", res["tags"])

        # RFC1918 private address
        res_priv = asyncio.run(internal.enrich("10.0.0.10", "ipv4"))
        self.assertIsNotNone(res_priv)
        self.assertEqual(res_priv["reputation"], "clean")
        self.assertEqual(res_priv["confidence"], 100)
        self.assertIn("rfc1918_private", res_priv["tags"])

    def test_redis_and_memory_caching(self):
        """Verify caching layer stores, returns, and respects TTL."""
        test_data = {
            "indicator": "198.51.100.99",
            "reputation": "suspicious",
            "confidence": 75,
            "provider": "internal",
        }

        # Store with 2-second TTL
        asyncio.run(ThreatIntelCache.set("198.51.100.99", "ipv4", test_data, ttl_seconds=2))

        # Retrieve
        cached = asyncio.run(ThreatIntelCache.get("198.51.100.99", "ipv4"))
        self.assertIsNotNone(cached)
        self.assertEqual(cached["reputation"], "suspicious")

        # After TTL expiry
        ThreatIntelCache._memory_expiry["sentinelx:intel:ipv4:198.51.100.99"] = 0
        expired = asyncio.run(ThreatIntelCache.get("198.51.100.99", "ipv4"))
        self.assertIsNone(expired)

    def test_threat_intel_risk_adjustment(self):
        """Verify deterministic risk adjustment based on threat intelligence."""
        # 1. Malicious reputation elevates score
        intel_mal = {
            "indicator": "198.51.100.50",
            "reputation": "malicious",
            "confidence": 90,
            "provider": "abuseipdb",
            "providers_reporting": ["abuseipdb", "virustotal"],
            "tags": ["c2", "ssh_attacker"],
        }
        score, sev, reason, factors = ThreatIntelRiskAdjuster.adjust_risk(
            base_score=60,
            base_severity="MEDIUM",
            intel=intel_mal,
        )
        self.assertGreater(score, 60)
        self.assertIn("malicious", reason.lower())
        self.assertIn(sev, ("HIGH", "CRITICAL"))
        # Check consensus points applied
        consensus_factors = [f for f in factors if "consensus" in f["factor"].lower()]
        self.assertEqual(len(consensus_factors), 1)

        # 2. Score clamping bounds [0, 100]
        score_max, _, _, _ = ThreatIntelRiskAdjuster.adjust_risk(
            base_score=95,
            base_severity="CRITICAL",
            intel=intel_mal,
        )
        self.assertLessEqual(score_max, 100)

        # 3. Clean reputation provides gentle reduction
        intel_clean = {
            "indicator": "10.0.0.10",
            "reputation": "clean",
            "confidence": 100,
            "provider": "internal",
        }
        score_clean, sev_clean, _, _ = ThreatIntelRiskAdjuster.adjust_risk(
            base_score=40,
            base_severity="LOW",
            intel=intel_clean,
        )
        self.assertLess(score_clean, 40)
        self.assertEqual(score_clean, 35)

    def test_provider_rate_limiting(self):
        """Verify provider rate limit backoff tracking."""
        vt = VirusTotalProvider()
        self.assertFalse(vt.is_available())  # unconfigured

        with patch.object(vt, "is_configured", return_value=True):
            self.assertTrue(vt.is_available())
            vt.mark_rate_limited(duration_seconds=10.0)
            self.assertFalse(vt.is_available())
            meta = vt.safe_metadata()
            self.assertTrue(meta["rate_limited"])


if __name__ == "__main__":
    unittest.main()
