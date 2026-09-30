"""Pydantic schemas for Host Inventory & Endpoint Monitoring in Phase 6."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HostBase(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255, description="Host system FQDN or NetBIOS identifier")
    ip_address: str = Field(..., min_length=7, max_length=45, description="Primary network IP address (IPv4 or IPv6)")
    operating_system: str = Field("Windows", max_length=100, description="OS platform (e.g. Windows Server 2022, Ubuntu 22.04)")
    agent_version: str = Field("1.0.0", max_length=50, description="Installed telemetry agent version")
    status: str = Field("ONLINE", max_length=20, description="Endpoint status: ONLINE, OFFLINE, DEGRADED, ISOLATED")


class HostCreate(HostBase):
    pass


class HostUpdate(BaseModel):
    ip_address: Optional[str] = Field(None, max_length=45)
    operating_system: Optional[str] = Field(None, max_length=100)
    agent_version: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, max_length=20)


class HostHeartbeat(BaseModel):
    agent_version: Optional[str] = None
    status: Optional[str] = "ONLINE"
    system_metrics: Optional[Dict[str, Any]] = None


class HostIsolationRequest(BaseModel):
    isolate: bool = Field(..., description="True to simulate containment; False to restore network connectivity")
    reason: str = Field(..., min_length=3, max_length=255, description="Justification for containment action")


class HostResponse(HostBase):
    id: int
    last_seen: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class HostDetailResponse(HostResponse):
    event_count: int = 0
    alert_count: int = 0
    calculated_risk: int = 0
    recent_events: List[Dict[str, Any]] = []
    recent_alerts: List[Dict[str, Any]] = []
