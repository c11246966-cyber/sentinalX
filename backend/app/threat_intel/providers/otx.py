"""AlienVault OTX (Open Threat Exchange) Provider."""

import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request
from backend.app.core.logging import logger
from backend.app.threat_intel.providers.base import BaseThreatIntelProvider

try:
    from backend.app.core.config import settings
except ImportError:
    settings = None


class AlienVaultOTXProvider(BaseThreatIntelProvider):
    """Enriches indicators using AlienVault OTX (Open Threat Exchange) Direct Connect API."""

    def __init__(self) -> None:
        super().__init__(
            name="alienvault_otx",
            supported_types=["ipv4", "ipv6", "domain", "url", "hash"],
            timeout=float(getattr(settings, "THREAT_INTEL_TIMEOUT_SECONDS", 5.0) if settings else 5.0),
        )

    def is_configured(self) -> bool:
        key = (
            getattr(settings, "OTX_API_KEY", None)
            or getattr(settings, "ALIENVAULT_OTX_KEY", None)
            or os.getenv("OTX_API_KEY", "")
            or os.getenv("ALIENVAULT_OTX_KEY", "")
        )
        return bool(key and key.strip())

    def _get_api_key(self) -> str:
        return (
            getattr(settings, "OTX_API_KEY", None)
            or getattr(settings, "ALIENVAULT_OTX_KEY", None)
            or os.getenv("OTX_API_KEY", "")
            or os.getenv("ALIENVAULT_OTX_KEY", "")
        ).strip()

    def _build_url(self, indicator: str, indicator_type: str) -> Optional[str]:
        base = "https://otx.alienvault.com/api/v1/indicators"
        encoded = urllib.parse.quote(indicator, safe="")
        if indicator_type in ("ipv4", "ipv6"):
            return f"{base}/IPv4/{encoded}/general" if indicator_type == "ipv4" else f"{base}/IPv6/{encoded}/general"
        elif indicator_type == "domain":
            return f"{base}/domain/{encoded}/general"
        elif indicator_type == "hash":
            return f"{base}/file/{encoded}/general"
        elif indicator_type == "url":
            return f"{base}/url/{encoded}/general"
        return None

    def _query_sync(self, url: str) -> Optional[Dict[str, Any]]:
        headers = {
            "X-OTX-API-KEY": self._get_api_key(),
            "User-Agent": "SentinelX-SOC-ThreatIntel/1.0",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    raw_data = resp.read(65536)
                    return json.loads(raw_data.decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            if http_err.code == 429:
                self.mark_rate_limited(60.0)
            elif http_err.code in (401, 403):
                logger.warning("AlienVault OTX authentication failed. Check OTX key.")
            elif http_err.code != 404:
                logger.warning(f"AlienVault OTX HTTP {http_err.code}")
        except Exception as exc:
            logger.warning(f"AlienVault OTX request error: {type(exc).__name__}")
        return None

    async def enrich(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        if not self.is_available() or indicator_type not in self.supported_types:
            return None

        url = self._build_url(indicator, indicator_type)
        if not url:
            return None

        data = await asyncio.to_thread(self._query_sync, url)
        if not data:
            return None

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        tags = []
        adversaries = set()
        for p in pulses[:5]:
            for tag in p.get("tags", []):
                clean_tag = tag.strip().lower().replace(" ", "_")
                if clean_tag and clean_tag not in tags:
                    tags.append(clean_tag)
            if p.get("adversary"):
                adversaries.add(p["adversary"])

        if pulse_count >= 5 or any("c2" in t or "ransomware" in t for t in tags):
            reputation = "malicious"
            confidence = min(95, 50 + pulse_count * 5)
            severity = "CRITICAL" if pulse_count >= 10 else "HIGH"
        elif pulse_count > 0:
            reputation = "suspicious"
            confidence = min(75, 40 + pulse_count * 5)
            severity = "MEDIUM"
        else:
            reputation = "unknown"
            confidence = 15
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
                "pulse_count": pulse_count,
                "adversaries": list(adversaries),
                "validation": data.get("validation", []),
            },
        }
