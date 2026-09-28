"""Detection rule schemas."""

from datetime import datetime
from typing import Any, Dict, Optional, Literal
from pydantic import BaseModel, Field


class DetectionRuleBase(BaseModel):
    name: str = Field(..., max_length=150)
    description: str
    category: str = Field(..., example="authentication")
    severity: Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    rule_type: str = Field(default="threshold", example="threshold")
    rule_definition: Dict[str, Any]
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    enabled: bool = True


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[Literal["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]] = None
    rule_definition: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class DetectionRuleResponse(DetectionRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
