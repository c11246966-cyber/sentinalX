"""Threat intelligence schemas for Phase 5."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EnrichIndicatorRequest(BaseModel):
    indicator: str = Field(..., description="IPv4, IPv6, domain, URL, or hash to enrich", example="198.51.100.23")
    indicator_type: Optional[str] = Field(None, description="Optional type hint (ipv4, ipv6, domain, url, hash)", example="ipv4")
    force_refresh: bool = Field(False, description="Bypass cache and force upstream query")


class ThreatIntelProviderMeta(BaseModel):
    name: str
    configured: bool
    available: bool
    supported_types: List[str]
    rate_limited: bool = False
    external: bool = False
    status: str = "operational"


class ProviderStatusResponse(BaseModel):
    providers: List[ThreatIntelProviderMeta]


class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: str
    provider: str
    providers_reporting: Optional[List[str]] = Field(default_factory=list)
    reputation: str  # clean, suspicious, malicious, unknown
    confidence: int = Field(ge=0, le=100)
    severity: str = "LOW"  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    threat_category: Optional[str] = "General Threat"
    description: Optional[str] = None
    matching_reason: Optional[str] = None
    known: bool = True
    tags: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source: str = "threat_intel"
    raw_provider_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class ThreatIntelligenceRecordResponse(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    provider: str
    reputation: str
    confidence: int
    severity: str
    threat_category: Optional[str] = None
    description: Optional[str] = None
    matching_reason: Optional[str] = None
    tags: Optional[List[str]] = None
    source: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    raw_response: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
