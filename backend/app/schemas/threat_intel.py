"""Threat intelligence schemas."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ThreatIntelLookup(BaseModel):
    indicator: str
    indicator_type: str = Field(..., example="ip")  # ip, domain, hash
    provider: str = Field(default="internal")
    reputation: str = Field(default="unknown")  # clean, suspicious, malicious
    confidence: int = Field(default=0, ge=0, le=100)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw_response: Optional[Dict[str, Any]] = None


class ThreatIntelResponse(ThreatIntelLookup):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
