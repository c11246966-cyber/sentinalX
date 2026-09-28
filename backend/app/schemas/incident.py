"""Incident management schemas."""

from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class IncidentBase(BaseModel):
    title: str
    description: str
    severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    risk_score: int = Field(default=50, ge=0, le=100)
    status: Literal["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"] = "NEW"
    assigned_to: Optional[int] = None
    analyst_notes: Optional[str] = None


class IncidentCreate(IncidentBase):
    alert_ids: Optional[List[int]] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    analyst_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None


class IncidentResponse(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    alert_count: Optional[int] = 0

    class Config:
        from_attributes = True
