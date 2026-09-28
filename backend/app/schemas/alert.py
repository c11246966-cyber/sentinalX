"""Alert data schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    factor: str
    points: int


class AlertBase(BaseModel):
    title: str
    description: str
    severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: int = Field(ge=0, le=100)
    status: Literal["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "TRIAGED"] = "NEW"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    analyst_notes: Optional[str] = None


class AlertCreate(AlertBase):
    event_id: Optional[int] = None
    rule_id: Optional[int] = None
    incident_id: Optional[int] = None
    risk_factors: Optional[List[RiskFactor]] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    analyst_notes: Optional[str] = None
    incident_id: Optional[int] = None


class AlertResponse(AlertBase):
    id: int
    event_id: Optional[int] = None
    rule_id: Optional[int] = None
    incident_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
