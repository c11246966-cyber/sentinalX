"""Threat Intelligence orchestrator, provider dispatcher, and consensus engine."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
try:
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession
    from backend.app.models.threat_intel import ThreatIntelligence
except ImportError:
    select = None
    AsyncSession = Any
    ThreatIntelligence = None

from backend.app.core.logging import logger
from backend.app.threat_intel.cache import ThreatIntelCache
from backend.app.threat_intel.indicator import (
    IndicatorType,
    is_ssrf_risk,
    validate_indicator,
)
from backend.app.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from backend.app.threat_intel.providers.base import BaseThreatIntelProvider
from backend.app.threat_intel.providers.internal import InternalIntelProvider
from backend.app.threat_intel.providers.otx import AlienVaultOTXProvider
from backend.app.threat_intel.providers.virustotal import VirusTotalProvider
from backend.app.threat_intel.risk_adjuster import ThreatIntelRiskAdjuster


class ThreatIntelManager:
    """Coordinates threat intelligence lookup, consensus aggregation, and persistence."""

    _providers: Dict[str, BaseThreatIntelProvider] = {
        "virustotal": VirusTotalProvider(),
        "abuseipdb": AbuseIPDBProvider(),
        "alienvault_otx": AlienVaultOTXProvider(),
        "internal": InternalIntelProvider(),
    }

    @classmethod
    def get_providers(cls) -> Dict[str, BaseThreatIntelProvider]:
        return cls._providers

    @classmethod
    def get_provider_status(cls) -> List[Dict[str, Any]]:
        """Return safe metadata for all threat intelligence providers without leaking credentials."""
        return [p.safe_metadata() for p in cls._providers.values()]

    @classmethod
    async def enrich_indicator(
        cls,
        indicator: str,
        indicator_type: Optional[str] = None,
        force_refresh: bool = False,
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Validate, query, consensus-aggregate, cache, and persist threat intelligence."""
        # 1. Strict validation
        is_valid, canonical, ind_type = validate_indicator(indicator, indicator_type)
        if not is_valid:
            raise ValueError(f"Invalid threat indicator format: '{indicator}'")

        # 2. Check cache unless force_refresh
        if not force_refresh:
            cached = await ThreatIntelCache.get(canonical, ind_type)
            if cached:
                return cached

        # 3. Check for SSRF / Internal safety
        # If the indicator is private IP or internal host, do not query external providers
        has_ssrf_risk = is_ssrf_risk(canonical, ind_type)

        # 4. Dispatch to providers
        tasks = []
        providers_queried = []

        if has_ssrf_risk:
            # Query ONLY internal provider for RFC1918 / loopback addresses
            internal_prov = cls._providers["internal"]
            tasks.append(internal_prov.enrich(canonical, ind_type))
            providers_queried.append("internal")
        else:
            for name, prov in cls._providers.items():
                if prov.is_available() and ind_type in prov.supported_types:
                    tasks.append(prov.enrich(canonical, ind_type))
                    providers_queried.append(name)

        if not tasks:
            # Fallback to internal provider
            internal_prov = cls._providers["internal"]
            tasks.append(internal_prov.enrich(canonical, ind_type))
            providers_queried.append("internal")

        # Execute provider queries concurrently with safety
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results: List[Dict[str, Any]] = []
        for r in responses:
            if isinstance(r, dict) and r.get("reputation"):
                valid_results.append(r)
            elif isinstance(r, Exception):
                logger.warning(f"Threat intelligence provider exception: {r}")

        # 5. Aggregate into unified consensus
        aggregated = cls._aggregate_consensus(canonical, ind_type, valid_results, providers_queried)

        # 6. Store in Redis / memory cache
        await ThreatIntelCache.set(canonical, ind_type, aggregated)

        # 7. Persist to PostgreSQL if db session provided
        if db is not None:
            try:
                await cls._persist_to_db(db, aggregated)
            except Exception as exc:
                logger.warning(f"Could not persist threat intelligence to database: {exc}")

        return aggregated

    @classmethod
    def _aggregate_consensus(
        cls,
        indicator: str,
        indicator_type: str,
        results: List[Dict[str, Any]],
        providers_queried: List[str],
    ) -> Dict[str, Any]:
        """Merge multiple provider responses into a deterministic, consensus reputation."""
        now = datetime.now(timezone.utc)
        if not results:
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "provider": "none",
                "providers_reporting": [],
                "providers_queried": providers_queried,
                "reputation": "unknown",
                "confidence": 0,
                "severity": "LOW",
                "tags": ["unverified"],
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "source": "threat_intel",
                "raw_provider_metadata": {},
                "timestamp": now.isoformat(),
            }

        reputations = [r["reputation"] for r in results]
        confidences = [int(r.get("confidence", 0)) for r in results]
        all_tags = set()
        providers_reporting = []
        raw_meta = {}

        for r in results:
            prov = r.get("provider", "unknown")
            providers_reporting.append(prov)
            for t in r.get("tags") or []:
                all_tags.add(t)
            if r.get("raw_provider_metadata"):
                raw_meta[prov] = r["raw_provider_metadata"]

        # Consensus determination
        malicious_count = reputations.count("malicious")
        suspicious_count = reputations.count("suspicious")
        clean_count = reputations.count("clean")

        if malicious_count > 0:
            reputation = "malicious"
            base_conf = max(confidences) if confidences else 80
            # Multi-provider agreement increases confidence
            confidence = min(100, base_conf + (malicious_count - 1) * 10)
            severity = "CRITICAL" if confidence >= 85 else "HIGH"
        elif suspicious_count > 0:
            reputation = "suspicious"
            confidence = max(confidences) if confidences else 50
            severity = "MEDIUM"
        elif clean_count > 0:
            reputation = "clean"
            confidence = max(confidences) if confidences else 80
            severity = "INFORMATIONAL"
        else:
            reputation = "unknown"
            confidence = int(sum(confidences) / len(confidences)) if confidences else 0
            severity = "LOW"

        primary_provider = providers_reporting[0] if len(providers_reporting) == 1 else "consensus"

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "provider": primary_provider,
            "providers_reporting": providers_reporting,
            "providers_queried": providers_queried,
            "reputation": reputation,
            "confidence": confidence,
            "severity": severity,
            "tags": sorted(list(all_tags))[:15],
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "source": "threat_intel",
            "raw_provider_metadata": raw_meta,
            "timestamp": now.isoformat(),
        }

    @classmethod
    async def _persist_to_db(cls, db: AsyncSession, data: Dict[str, Any]) -> None:
        """Upsert threat intelligence record in PostgreSQL."""
        if select is None or ThreatIntelligence is None or db is None:
            return

        stmt = select(ThreatIntelligence).where(
            ThreatIntelligence.indicator == data["indicator"],
            ThreatIntelligence.indicator_type == data["indicator_type"],
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if record:
            record.provider = data["provider"]
            record.reputation = data["reputation"]
            record.confidence = data["confidence"]
            record.severity = data["severity"]
            record.tags = data["tags"]
            record.last_seen = now
            record.raw_response = data["raw_provider_metadata"]
            record.updated_at = now
        else:
            record = ThreatIntelligence(
                indicator=data["indicator"],
                indicator_type=data["indicator_type"],
                provider=data["provider"],
                reputation=data["reputation"],
                confidence=data["confidence"],
                severity=data["severity"],
                tags=data["tags"],
                source=data["source"],
                first_seen=now,
                last_seen=now,
                raw_response=data["raw_provider_metadata"],
                created_at=now,
                updated_at=now,
            )
            db.add(record)

        await db.commit()

    @classmethod
    async def enrich_and_adjust_alert(
        cls,
        alert_dict: Dict[str, Any],
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Extract indicators from an alert, enrich them, and adjust risk score deterministically."""
        # Candidate indicator: source_ip preferred, then destination_ip
        candidate_ip = alert_dict.get("source_ip") or alert_dict.get("destination_ip")
        if not candidate_ip or candidate_ip in ("unknown", "None", ""):
            return alert_dict

        try:
            intel = await cls.enrich_indicator(indicator=candidate_ip, indicator_type="ip", db=db)
            alert_dict["threat_intel_context"] = intel

            # If threat intelligence returns actionable intelligence, calculate risk adjustment
            rep = intel.get("reputation", "unknown").lower()
            if rep in ("malicious", "suspicious", "clean"):
                base_score = int(alert_dict.get("risk_score", 50))
                base_sev = str(alert_dict.get("severity", "MEDIUM"))

                new_score, new_sev, reason, factors = ThreatIntelRiskAdjuster.adjust_risk(
                    base_score=base_score,
                    base_severity=base_sev,
                    intel=intel,
                )

                alert_dict["risk_score"] = new_score
                alert_dict["severity"] = new_sev
                alert_dict["risk_adjustment_reason"] = reason

        except Exception as exc:
            logger.warning(f"Alert enrichment error: {exc}")

        return alert_dict
