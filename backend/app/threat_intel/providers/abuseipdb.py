"""AbuseIPDB Threat Intelligence Provider (v2 API)."""

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


class AbuseIPDBProvider(BaseThreatIntelProvider):
    """Enriches IPv4 and IPv6 addresses using AbuseIPDB check API."""

    CATEGORY_NAMES = {
        3: "fraud_orders",
        4: "ddos_attack",
        9: "open_proxy",
        10: "web_spam",
        11: "email_spam",
        14: "port_scan",
        15: "hacking",
        18: "brute_force",
        19: "bad_web_bot",
        20: "exploited_host",
        21: "web_app_attack",
        22: "ssh",
        23: "iot_targeted",
    }

    def __init__(self) -> None:
        super().__init__(
            name="abuseipdb",
            supported_types=["ipv4", "ipv6"],
            timeout=float(getattr(settings, "THREAT_INTEL_TIMEOUT_SECONDS", 5.0) if settings else 5.0),
        )

    def is_configured(self) -> bool:
        key = getattr(settings, "ABUSEIPDB_API_KEY", None) or os.getenv("ABUSEIPDB_API_KEY", "")
        return bool(key and key.strip())

    def _get_api_key(self) -> str:
        return (getattr(settings, "ABUSEIPDB_API_KEY", None) or os.getenv("ABUSEIPDB_API_KEY", "")).strip()

    def _query_sync(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose"
        headers = {
            "Key": self._get_api_key(),
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
                logger.warning("AbuseIPDB authentication rejected. Check API key.")
            elif http_err.code != 404:
                logger.warning(f"AbuseIPDB query HTTP {http_err.code}")
        except Exception as exc:
            logger.warning(f"AbuseIPDB request failed: {type(exc).__name__}")
        return None

    async def enrich(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        if not self.is_available() or indicator_type not in self.supported_types:
            return None

        result = await asyncio.to_thread(self._query_sync, indicator)
        if not result or "data" not in result:
            return None

        data = result["data"]
        score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        is_whitelisted = data.get("isWhitelisted", False)

        tags = []
        if data.get("usageType"):
            tags.append(str(data["usageType"]).lower().replace(" ", "_"))
        if data.get("countryCode"):
            tags.append(f"geo_{data['countryCode'].lower()}")
        if data.get("isTor"):
            tags.append("tor_exit_node")

        for report in data.get("reports", [])[:5]:
            for cat in report.get("categories", []):
                cat_name = self.CATEGORY_NAMES.get(cat)
                if cat_name and cat_name not in tags:
                    tags.append(cat_name)

        if is_whitelisted or (score == 0 and total_reports == 0):
            reputation = "clean"
            confidence = 90
            severity = "INFORMATIONAL"
        elif score >= 75:
            reputation = "malicious"
            confidence = score
            severity = "CRITICAL" if score >= 90 else "HIGH"
        elif score >= 25 or total_reports >= 5:
            reputation = "suspicious"
            confidence = max(score, 50)
            severity = "MEDIUM"
        else:
            reputation = "unknown"
            confidence = 20
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
                "abuse_score": score,
                "total_reports": total_reports,
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_whitelisted": is_whitelisted,
            },
        }
