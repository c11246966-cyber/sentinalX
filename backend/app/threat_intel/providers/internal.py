"""Internal Threat Intelligence Provider and Curated Local Feed for Phase 8."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.threat_intel.indicator import (
    BLOCKED_INTERNAL_HOSTS,
    is_private_or_reserved_ip,
)
from backend.app.threat_intel.providers.base import BaseThreatIntelProvider


class InternalIntelProvider(BaseThreatIntelProvider):
    """Local, deterministic threat intelligence provider and internal curated IOC feed.
    
    Provides offline IOC lookup, RFC1918/Loopback private classification,
    and curated threat datasets across IPv4, IPv6, Domain, URL, MD5, SHA1, and SHA256.
    """

    KNOWN_LAB_INDICATORS: Dict[str, Dict[str, Any]] = {
        # --- IPv4 Indicators ---
        "198.51.100.23": {
            "indicator_type": "ipv4",
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "threat_category": "Brute Force / SSH Attack",
            "description": "Known laboratory SSH brute-force adversary simulating credential access.",
            "matching_reason": "Matches internal IOC feed: persistent automated SSH brute-force source.",
            "tags": ["known_scanner", "ssh_bruteforce", "rfc5737_lab_adversary"],
            "created_at": "2026-09-01T00:00:00Z",
        },
        "198.51.100.50": {
            "indicator_type": "ipv4",
            "reputation": "malicious",
            "confidence": 92,
            "severity": "HIGH",
            "threat_category": "Credential Access / Botnet",
            "description": "Distributed credential stuffing botnet node probing enterprise authentication endpoints.",
            "matching_reason": "Matches internal IOC feed: high-volume credential stuffing botnet.",
            "tags": ["brute_force_botnet", "credential_stuffing", "credential_access"],
            "created_at": "2026-09-01T00:00:00Z",
        },
        "198.51.100.89": {
            "indicator_type": "ipv4",
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "threat_category": "Brute Force / SSH Attack",
            "description": "Automated SSH brute-force cluster targeting administrative bastion servers.",
            "matching_reason": "Matches internal IOC feed: targeted SSH credential brute-forcer.",
            "tags": ["ssh_attacker", "bruteforce_cluster"],
            "created_at": "2026-09-05T00:00:00Z",
        },
        "203.0.113.15": {
            "indicator_type": "ipv4",
            "reputation": "malicious",
            "confidence": 88,
            "severity": "HIGH",
            "threat_category": "Web Application Attack",
            "description": "Web vulnerability scanner and SQL injection probe host.",
            "matching_reason": "Matches internal IOC feed: recurring SQL injection scanner.",
            "tags": ["web_attack_source", "sqli_probe", "initial_access"],
            "created_at": "2026-09-10T00:00:00Z",
        },
        "203.0.113.88": {
            "indicator_type": "ipv4",
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "threat_category": "Web Application Attack",
            "description": "Active SQL injection exploitation origin observed violating WAF inspection boundaries.",
            "matching_reason": "Matches internal IOC feed: confirmed web exploitation host.",
            "tags": ["sql_injection_origin", "waf_violator"],
            "created_at": "2026-09-12T00:00:00Z",
        },
        "192.0.2.100": {
            "indicator_type": "ipv4",
            "reputation": "suspicious",
            "confidence": 85,
            "severity": "MEDIUM",
            "threat_category": "Reconnaissance / Scanner",
            "description": "Network port and service reconnaissance scanner probing gateway entrypoints.",
            "matching_reason": "Matches internal IOC feed: active port reconnaissance scanner.",
            "tags": ["reconnaissance_source", "port_scanner"],
            "created_at": "2026-09-15T00:00:00Z",
        },
        "192.0.2.144": {
            "indicator_type": "ipv4",
            "reputation": "suspicious",
            "confidence": 80,
            "severity": "MEDIUM",
            "threat_category": "Reconnaissance / Scanner",
            "description": "Endpoint discovery probe testing common management and telemetry ports.",
            "matching_reason": "Matches internal IOC feed: endpoint discovery probe.",
            "tags": ["port_scanner", "discovery_probe"],
            "created_at": "2026-09-18T00:00:00Z",
        },
        "192.0.2.200": {
            "indicator_type": "ipv4",
            "reputation": "malicious",
            "confidence": 95,
            "severity": "CRITICAL",
            "threat_category": "Denial of Service / SYN Flood",
            "description": "High-volume SYN flood DDoS botnet controller simulating network exhaustion impact.",
            "matching_reason": "Matches internal IOC feed: active volumetric DDoS botnet node.",
            "tags": ["syn_flood_origin", "ddos_botnet", "impact"],
            "created_at": "2026-09-20T00:00:00Z",
        },
        "8.8.8.8": {
            "indicator_type": "ipv4",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Benign / Trusted DNS",
            "description": "Google Public DNS trusted recursive resolver.",
            "matching_reason": "Matches internal IOC feed: globally recognized benign DNS resolver.",
            "tags": ["trusted_dns", "benign_infrastructure"],
            "created_at": "2026-01-01T00:00:00Z",
        },
        "1.1.1.1": {
            "indicator_type": "ipv4",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Benign / Trusted DNS",
            "description": "Cloudflare Public DNS trusted recursive resolver.",
            "matching_reason": "Matches internal IOC feed: globally recognized benign DNS resolver.",
            "tags": ["trusted_dns", "benign_infrastructure"],
            "created_at": "2026-01-01T00:00:00Z",
        },

        # --- IPv6 Indicators ---
        "2001:db8::dead:beef": {
            "indicator_type": "ipv6",
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "threat_category": "IPv6 Adversary / C2",
            "description": "Documentation network IPv6 adversary beaconing simulated C2 channel.",
            "matching_reason": "Matches internal IOC feed: simulated IPv6 adversary C2 endpoint.",
            "tags": ["ipv6_adversary", "c2_beacon", "lab_adversary"],
            "created_at": "2026-09-22T00:00:00Z",
        },
        "2001:db8:85a3::8a2e:370:7334": {
            "indicator_type": "ipv6",
            "reputation": "suspicious",
            "confidence": 75,
            "severity": "MEDIUM",
            "threat_category": "IPv6 Reconnaissance",
            "description": "IPv6 network discovery scanner testing peripheral router ports.",
            "matching_reason": "Matches internal IOC feed: IPv6 perimeter reconnaissance probe.",
            "tags": ["ipv6_scanner", "discovery_probe"],
            "created_at": "2026-09-24T00:00:00Z",
        },
        "2001:4860:4860::8888": {
            "indicator_type": "ipv6",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Benign / Trusted DNS",
            "description": "Google Public DNS IPv6 primary resolver.",
            "matching_reason": "Matches internal IOC feed: trusted public DNS resolver.",
            "tags": ["trusted_dns", "benign_infrastructure"],
            "created_at": "2026-01-01T00:00:00Z",
        },

        # --- Domain Indicators ---
        "malware-c2-test.internal": {
            "indicator_type": "domain",
            "reputation": "malicious",
            "confidence": 95,
            "severity": "CRITICAL",
            "threat_category": "Command & Control (C2)",
            "description": "Synthetic lab C2 domain utilized for adversary staging, beaconing, and dropper payloads.",
            "matching_reason": "Matches internal IOC feed: designated laboratory C2 beacon domain.",
            "tags": ["c2_beacon", "trojan_dropper", "command_control"],
            "created_at": "2026-09-25T00:00:00Z",
        },
        "phishing-test.lab": {
            "indicator_type": "domain",
            "reputation": "malicious",
            "confidence": 90,
            "severity": "HIGH",
            "threat_category": "Credential Harvesting / Phishing",
            "description": "Simulated phishing domain impersonating internal SSO identity provider.",
            "matching_reason": "Matches internal IOC feed: simulated credential harvesting lure.",
            "tags": ["credential_harvesting", "phishing", "impersonation"],
            "created_at": "2026-09-26T00:00:00Z",
        },
        "ransomware-payload-drop.org.test": {
            "indicator_type": "domain",
            "reputation": "malicious",
            "confidence": 98,
            "severity": "CRITICAL",
            "threat_category": "Ransomware Distribution",
            "description": "Adversary infrastructure staging domain for simulated encrypted payload distribution.",
            "matching_reason": "Matches internal IOC feed: active ransomware dropper domain.",
            "tags": ["ransomware", "payload_delivery", "high_impact"],
            "created_at": "2026-09-27T00:00:00Z",
        },
        "suspicious-miner-domain.test": {
            "indicator_type": "domain",
            "reputation": "suspicious",
            "confidence": 82,
            "severity": "MEDIUM",
            "threat_category": "Cryptomining Pool",
            "description": "Stratum protocol pool communication domain indicating unauthorized coin mining.",
            "matching_reason": "Matches internal IOC feed: cryptomining pool connection endpoint.",
            "tags": ["cryptominer", "stratum_protocol", "resource_hijacking"],
            "created_at": "2026-09-28T00:00:00Z",
        },
        "sentinelx.local": {
            "indicator_type": "domain",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Internal Infrastructure",
            "description": "Legitimate internal SentinelX platform service domain.",
            "matching_reason": "Matches internal IOC feed: verified internal service domain.",
            "tags": ["internal_infrastructure", "trusted_service"],
            "created_at": "2026-01-01T00:00:00Z",
        },

        # --- URL Indicators ---
        "http://malware-c2-test.internal/beacon": {
            "indicator_type": "url",
            "reputation": "malicious",
            "confidence": 95,
            "severity": "CRITICAL",
            "threat_category": "Command & Control (C2)",
            "description": "Simulated HTTP beacon check-in endpoint for compromised endpoints.",
            "matching_reason": "Matches internal IOC feed: active adversary C2 beacon URL.",
            "tags": ["c2_endpoint", "http_beacon", "malicious_url"],
            "created_at": "2026-09-28T00:00:00Z",
        },
        "https://phishing-test.lab/login/verify.php": {
            "indicator_type": "url",
            "reputation": "malicious",
            "confidence": 92,
            "severity": "HIGH",
            "threat_category": "Credential Harvesting / Phishing",
            "description": "Phishing credential capture and harvesting form target.",
            "matching_reason": "Matches internal IOC feed: malicious credential capture URL.",
            "tags": ["credential_capture", "phishing_url"],
            "created_at": "2026-09-28T00:00:00Z",
        },
        "http://198.51.100.23/exploit.sh": {
            "indicator_type": "url",
            "reputation": "malicious",
            "confidence": 94,
            "severity": "CRITICAL",
            "threat_category": "Exploit Delivery",
            "description": "Remote shell script download URL used in automated exploit chains.",
            "matching_reason": "Matches internal IOC feed: malicious script payload staging URL.",
            "tags": ["exploit_delivery", "shell_payload", "dropper"],
            "created_at": "2026-09-28T00:00:00Z",
        },

        # --- File Hashes (MD5, SHA1, SHA256) ---
        # MD5
        "44d88612fea8a8f36de82e1278abb02f": {
            "indicator_type": "md5",
            "reputation": "malicious",
            "confidence": 98,
            "severity": "CRITICAL",
            "threat_category": "Malware / Antivirus Test",
            "description": "Standard EICAR standard anti-virus test file MD5 signature.",
            "matching_reason": "Matches internal IOC feed: industry standard EICAR test signature.",
            "tags": ["eicar_test_signature", "malware_test", "standard_test_hash"],
            "created_at": "2026-01-01T00:00:00Z",
        },
        "d41d8cd98f00b204e9800998ecf8427e": {
            "indicator_type": "md5",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Benign / Zero Byte",
            "description": "MD5 hash of a benign empty (zero-byte) file.",
            "matching_reason": "Matches internal IOC feed: verified empty file hash.",
            "tags": ["empty_file_hash", "benign"],
            "created_at": "2026-01-01T00:00:00Z",
        },

        # SHA1
        "3395856ce81f2b7382dee72602f798b642f14140": {
            "indicator_type": "sha1",
            "reputation": "malicious",
            "confidence": 98,
            "severity": "CRITICAL",
            "threat_category": "Malware / Antivirus Test",
            "description": "Standard EICAR standard anti-virus test file SHA1 signature.",
            "matching_reason": "Matches internal IOC feed: industry standard EICAR test signature.",
            "tags": ["eicar_test_signature", "malware_test", "standard_test_hash"],
            "created_at": "2026-01-01T00:00:00Z",
        },
        "da39a3ee5e6b4b0d3255bfef95601890afd80709": {
            "indicator_type": "sha1",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Benign / Zero Byte",
            "description": "SHA1 hash of a benign empty (zero-byte) file.",
            "matching_reason": "Matches internal IOC feed: verified empty file hash.",
            "tags": ["empty_file_hash", "benign"],
            "created_at": "2026-01-01T00:00:00Z",
        },

        # SHA256
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
            "indicator_type": "sha256",
            "reputation": "malicious",
            "confidence": 98,
            "severity": "CRITICAL",
            "threat_category": "Malware / Antivirus Test",
            "description": "Standard EICAR standard anti-virus test file SHA256 signature.",
            "matching_reason": "Matches internal IOC feed: industry standard EICAR test signature.",
            "tags": ["eicar_test_signature", "malware_test", "standard_test_hash"],
            "created_at": "2026-01-01T00:00:00Z",
        },
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "indicator_type": "sha256",
            "reputation": "clean",
            "confidence": 100,
            "severity": "INFORMATIONAL",
            "threat_category": "Benign / Zero Byte",
            "description": "SHA256 hash of a benign empty (zero-byte) file.",
            "matching_reason": "Matches internal IOC feed: verified empty file hash.",
            "tags": ["empty_file_hash", "benign"],
            "created_at": "2026-01-01T00:00:00Z",
        },
    }

    def __init__(self) -> None:
        super().__init__(
            name="internal",
            supported_types=["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "hash"],
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
                "known": True,
                "provider": self.name,
                "indicator": indicator,
                "indicator_type": info.get("indicator_type", indicator_type),
                "reputation": info["reputation"],
                "confidence": info["confidence"],
                "severity": info["severity"],
                "threat_category": info.get("threat_category", "General Threat"),
                "description": info.get("description", "Internal curated threat indicator"),
                "matching_reason": info.get("matching_reason", "Matched internal curated IOC dataset"),
                "tags": list(info.get("tags", [])),
                "first_seen": info.get("created_at") or now.isoformat(),
                "last_seen": now.isoformat(),
                "source": "internal",
                "raw_provider_metadata": {
                    "feed": "sentinelx_curated_ioc",
                    "threat_category": info.get("threat_category"),
                    "description": info.get("description"),
                },
            }

        # 2. Check private RFC 1918 / Loopback addresses and local hosts
        is_private_ip = indicator_type in ("ipv4", "ipv6", "ip") and is_private_or_reserved_ip(clean_ind)
        is_local_host = clean_ind in BLOCKED_INTERNAL_HOSTS or (
            clean_ind.endswith((".internal", ".local")) and clean_ind not in self.KNOWN_LAB_INDICATORS
        )

        if is_private_ip or is_local_host:
            return {
                "known": True,
                "provider": self.name,
                "indicator": indicator,
                "indicator_type": indicator_type,
                "reputation": "clean",
                "confidence": 100,
                "severity": "INFORMATIONAL",
                "threat_category": "Internal Infrastructure",
                "description": "RFC1918 private network, loopback, or internal cloud infrastructure address.",
                "matching_reason": "Private or reserved address space - internal to environment.",
                "tags": ["rfc1918_private", "internal_trusted", "non_routable"],
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "source": "internal",
                "raw_provider_metadata": {
                    "scope": "private_network",
                    "threat_category": "Internal Infrastructure",
                },
            }

        # 3. Default fallback for unknown indicators (no match)
        return {
            "known": False,
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "unknown",
            "confidence": 0,
            "severity": "LOW",
            "threat_category": "Uncategorized",
            "description": "Indicator not cataloged in internal curated threat intelligence feed.",
            "matching_reason": "No internal IOC match found.",
            "tags": ["unclassified"],
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "source": "internal",
            "raw_provider_metadata": {"lookup": "no_internal_match"},
        }
