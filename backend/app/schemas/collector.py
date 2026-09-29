"""Pydantic schemas for endpoint telemetry collectors and agents."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CollectorRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Friendly display name for the collector")
    hostname: str = Field(..., min_length=2, max_length=255, description="Host system FQDN or NetBIOS name")
    ip_address: str = Field(..., max_length=45, description="Primary network IP address")
    operating_system: str = Field("Windows", max_length=100, description="OS platform (e.g. Windows 11, Windows Server 2022)")
    agent_version: str = Field("1.0.0", max_length=50, description="Installed collector agent version")
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Safe host architecture/telemetry metadata")


class CollectorRegisterResponse(BaseModel):
    collector_id: str
    api_key: str = Field(..., description="Secret collector authorization token (only shown once)")
    name: str
    hostname: str
    operating_system: str
    registered_at: datetime
    status: str
    instructions: str


class CollectorHeartbeatRequest(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    agent_version: Optional[str] = None
    status: Optional[str] = "ONLINE"
    telemetry_stats: Optional[Dict[str, Any]] = None


class CollectorHeartbeatResponse(BaseModel):
    collector_id: str
    status: str
    last_seen: datetime
    server_time: datetime
    next_heartbeat_seconds: int = 30


class CollectorResponse(BaseModel):
    id: int
    collector_id: str
    name: str
    hostname: str
    ip_address: str
    operating_system: str
    agent_version: str
    status: str
    registered_at: datetime
    last_seen: datetime
    event_count: int
    alert_count: int
    metadata_json: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class CollectorDetailResponse(CollectorResponse):
    recent_events: List[Dict[str, Any]] = []
    recent_alerts: List[Dict[str, Any]] = []
