"""VirusTotal Threat Intelligence Provider (v3 API)."""

import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
from backend.app.core.logging import logger
from backend.app.threat_intel.providers.base import BaseThreatIntelProvider

try:
    from backend.app.core.config import settings
except ImportError:
    settings = None


class VirusTotalProvider(BaseThreatIntelProvider):
    """Enriches IP addresses, domains, URLs, and file hashes using VirusTotal v3 API."""

    def __init__(self) -> None:
        timeout_val = (
            getattr(settings, "THREAT_INTEL_TIMEOUT_S", None)
            or getattr(settings, "THREAT_INTEL_TIMEOUT_SECONDS", None)
            or os.getenv("THREAT_INTEL_TIMEOUT_S")
            or os.getenv("THREAT_INTEL_TIMEOUT_SECONDS")
            or 5.0
        )
        super().__init__(
            name="virustotal",
            supported_types=["ipv4", "domain", "url", "hash"],
            timeout=float(timeout_val),
        )

    def is_configured(self) -> bool:
        key = getattr(settings, "VIRUSTOTAL_API_KEY", None) or os.getenv("VIRUSTOTAL_API_KEY", "")
        return bool(key and key.strip())

    def _get_api_key(self) -> str:
        return (getattr(settings, "VIRUSTOTAL_API_KEY", None) or os.getenv("VIRUSTOTAL_API_KEY", "")).strip()

    def _build_url(self, indicator: str, indicator_type: str) -> Optional[str]:
        base = "https://www.virustotal.com/api/v3"
        if indicator_type == "ipv4":
            return f"{base}/ip_addresses/{indicator}"
        elif indicator_type == "domain":
            return f"{base}/domains/{indicator}"
        elif indicator_type == "hash":
            return f"{base}/files/{indicator}"
        elif indicator_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"{base}/urls/{url_id}"
        return None

    def _query_sync(self, url: str) -> Optional[Dict[str, Any]]:
        headers = {
            "x-apikey": self._get_api_key(),
            "User-Agent": "SentinelX-SOC-ThreatIntel/1.0",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    raw_data = resp.read(65536)  # 64KB max
                    return json.loads(raw_data.decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            if http_err.code == 429:
                self.mark_rate_limited(60.0)
            elif http_err.code in (401, 403):
                logger.warning("VirusTotal authentication failed. Verify API key.")
            elif http_err.code != 404:
                logger.warning(f"VirusTotal HTTP {http_err.code} for query.")
        except Exception as exc:
            logger.warning(f"VirusTotal query failed: {type(exc).__name__}")
        return None

    async def enrich(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        if not self.is_available() or indicator_type not in self.supported_types:
            return None

        url = self._build_url(indicator, indicator_type)
        if not url:
            return None

        data = await asyncio.to_thread(self._query_sync, url)
        if not data or "data" not in data:
            return None

        attributes = data["data"].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = max(1, malicious + suspicious + harmless + undetected)

        tags = attributes.get("tags", [])
        if malicious > 0:
            tags.append("vt_malicious")

        # Deterministic reputation & confidence calculation
        if malicious >= 3:
            reputation = "malicious"
            confidence = min(100, int((malicious / total_engines) * 100) + 30)
            severity = "CRITICAL" if malicious >= 10 else "HIGH"
        elif malicious > 0 or suspicious >= 2:
            reputation = "suspicious"
            confidence = min(85, int(((malicious + suspicious) / total_engines) * 100) + 20)
            severity = "MEDIUM"
        elif harmless > 10 and malicious == 0:
            reputation = "clean"
            confidence = min(95, int((harmless / total_engines) * 100))
            severity = "INFORMATIONAL"
        else:
            reputation = "unknown"
            confidence = 10
            severity = "LOW"

        now = datetime.now(timezone.utc)
        return {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": reputation,
            "confidence": confidence,
            "severity": severity,
            "tags": tags[:10],
            "first_seen": now,
            "last_seen": now,
            "source": self.name,
            "raw_provider_metadata": {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total_engines,
                "reputation_score": attributes.get("reputation", 0),
            },
        }
