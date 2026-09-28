"""Threat intelligence lookup endpoints."""

from fastapi import APIRouter
from backend.app.services.intel_service import ThreatIntelService

router = APIRouter()


@router.get("/{indicator}", summary="Query reputation for IP, domain, or file hash")
async def query_indicator(indicator: str):
    """Query threat intelligence reputation.

    Gracefully uses internal caching and mock records when external provider
    API keys (VirusTotal, AbuseIPDB, AlienVault OTX) are absent.
    """
    indicator_type = "ip"
    if "." in indicator and not indicator.replace(".", "").isdigit():
        indicator_type = "domain"
    elif len(indicator) in (32, 40, 64) and indicator.isalnum():
        indicator_type = "hash"

    return ThreatIntelService.enrich_indicator(indicator, indicator_type)
