"""Audit logging schema definitions."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AuditLogBase(BaseModel):
    action: str = Field(..., example="user_login")
    target_type: str = Field(..., example="user")
    target_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    source_ip: Optional[str] = None


class AuditLogCreate(AuditLogBase):
    user_id: Optional[int] = None


class AuditLogResponse(AuditLogBase):
    id: int
    user_id: Optional[int] = None
    timestamp: datetime

    class Config:
        from_attributes = True
