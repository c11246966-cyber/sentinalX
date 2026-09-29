"""Internal Threat Intelligence Provider and Curated Local Feed."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.threat_intel.indicator import is_private_or_reserved_ip
from backend.app.threat_intel.providers.base import BaseThreatIntelProvider


class InternalIntelProvider(BaseThreatIntelProvider):
    """Always-available baseline intelligence provider.
    
    Provides RFC1918 private network classification, benign infrastructure verification,
    and curated threat feeds for simulated lab adversaries and deterministic testing.
    """

    KNOWN_LAB_INDICATORS: Dict[str, Dict[str, Any]] = {
        "198.51.100.23": {
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "tags": ["known_scanner", "ssh_bruteforce", "rfc5737_lab_adversary"],
        },
        "198.51.100.50": {
            "reputation": "malicious",
            "confidence": 92,
            "severity": "HIGH",
            "tags": ["brute_force_botnet", "credential_stuffing", "credential_access"],
        },
        "198.51.100.89": {
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "tags": ["ssh_attacker", "bruteforce_cluster"],
        },
        "203.0.113.15": {
            "reputation": "malicious",
            "confidence": 88,
            "severity": "HIGH",
            "tags": ["web_attack_source", "sqli_probe", "initial_access"],
        },
        "203.0.113.88": {
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "tags": ["sql_injection_origin", "waf_violator"],
        },
        "192.0.2.100": {
            "reputation": "suspicious",
            "confidence": 85,
            "severity": "MEDIUM",
            "tags": ["reconnaissance_source", "port_scanner"],
        },
        "192.0.2.144": {
            "reputation": "suspicious",
            "confidence": 80,
            "severity": "MEDIUM",
            "tags": ["port_scanner", "discovery_probe"],
        },
        "192.0.2.200": {
            "reputation": "malicious",
            "confidence": 95,
            "severity": "CRITICAL",
            "tags": ["syn_flood_origin", "ddos_botnet", "impact"],
        },
        "malware-c2-test.internal": {
            "reputation": "malicious",
            "confidence": 95,
            "severity": "CRITICAL",
            "tags": ["c2_beacon", "trojan_dropper"],
        },
        "phishing-test.lab": {
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "tags": ["credential_harvesting", "phishing"],
        },
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "tags": ["empty_file_hash"],
        },
        "44d88612fea8a8f36de82e1278abb02f": {
            "reputation": "malicious",
            "confidence": 98,
            "severity": "CRITICAL",
            "tags": ["eicar_test_signature", "malware_test"],
        },
    }

    def __init__(self) -> None:
        super().__init__(
            name="internal",
            supported_types=["ipv4", "ipv6", "domain", "url", "hash"],
            timeout=1.0,
        )

    def is_configured(self) -> bool:
        return True

    def is_available(self) -> bool:
        return True

    async def enrich(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        clean_ind = indicator.strip().lower()
        now = datetime.now(timezone.utc)

        # 1. Check known lab / threat feed signatures
        if clean_ind in self.KNOWN_LAB_INDICATORS:
            info = self.KNOWN_LAB_INDICATORS[clean_ind]
            return {
                "provider": self.name,
                "indicator": indicator,
                "indicator_type": indicator_type,
                "reputation": info["reputation"],
                "confidence": info["confidence"],
                "severity": info["severity"],
                "tags": list(info["tags"]),
                "first_seen": now,
                "last_seen": now,
                "source": self.name,
                "raw_provider_metadata": {"feed": "sentinelx_curated_ioc"},
            }

        # 2. Check private RFC 1918 / Loopback addresses
        if indicator_type in ("ipv4", "ipv6", "ip") and is_private_or_reserved_ip(clean_ind):
            return {
                "provider": self.name,
                "indicator": indicator,
                "indicator_type": indicator_type,
                "reputation": "clean",
                "confidence": 100,
                "severity": "INFORMATIONAL",
                "tags": ["rfc1918_private", "internal_trusted"],
                "first_seen": now,
                "last_seen": now,
                "source": self.name,
                "raw_provider_metadata": {"scope": "private_network"},
            }

        # 3. Default fallback
        return {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "unknown",
            "confidence": 0,
            "severity": "LOW",
            "tags": ["unclassified"],
            "first_seen": now,
            "last_seen": now,
            "source": self.name,
            "raw_provider_metadata": {"lookup": "no_internal_match"},
        }
