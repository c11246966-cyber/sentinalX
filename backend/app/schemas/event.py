"""Event ingestion, query, and representation schemas matching Phase 3 specs."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal
import uuid
from pydantic import BaseModel, Field


class EventIngest(BaseModel):
    """Payload for incoming security events via POST /api/v1/events."""
    event_id: Optional[str] = Field(None, example="evt_8f3d1b7a2c")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="network", example="network")
    source_ip: Optional[str] = Field(None, example="198.51.100.44")
    destination_ip: Optional[str] = Field(None, example="10.0.0.5")
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, example="TCP")
    event_type: str = Field(..., example="port_scan")
    severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "INFORMATIONAL"
    username: Optional[str] = Field(None, example="root")
    hostname: Optional[str] = Field(None, example="PROD-WEB-01")
    process_name: Optional[str] = Field(None, example="/usr/bin/nmap")
    command_line: Optional[str] = None
    message: str = Field(..., example="SYN connection request")
    raw_event: Optional[Dict[str, Any]] = None
    normalized_event: Optional[Dict[str, Any]] = None
    mitre_technique: Optional[str] = Field(None, example="T1046")
    status: str = Field(default="RECEIVED")


class EventResponse(BaseModel):
    """Stored normalized event response."""
    id: int
    event_id: str
    timestamp: datetime
    source: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str
    severity: str
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    message: str
    raw_event: Optional[Dict[str, Any]] = None
    normalized_event: Optional[Dict[str, Any]] = None
    mitre_technique: Optional[str] = None
    status: str
    host_id: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True


class EventBatchIngest(BaseModel):
    """Batch ingestion of multiple events."""
    events: List[EventIngest]


class EventIngestResponse(BaseModel):
    """Acknowledgement of ingested events with created detection alerts."""
    status: str = "success"
    ingested_count: int
    event_ids: List[str]
    generated_alerts: List[Dict[str, Any]] = []
