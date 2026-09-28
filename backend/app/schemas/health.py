"""Health check and system telemetry schemas."""

from datetime import datetime, timezone
from typing import Dict, Literal, Optional
from pydantic import BaseModel, Field


class ServiceHealthDetail(BaseModel):
    """Component-specific status detail."""
    status: Literal["healthy", "degraded", "unhealthy", "disabled"]
    latency_ms: Optional[float] = None
    message: Optional[str] = None


class HealthStatusResponse(BaseModel):
    """Comprehensive health check payload."""
    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ..., description="Overall platform operational status"
    )
    version: str = Field(..., description="SentinelX platform version")
    environment: str = Field(..., description="Current running environment")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO 8601 UTC timestamp of the health check",
    )
    services: Dict[str, ServiceHealthDetail] = Field(
        default_factory=dict,
        description="Health states of underlying dependencies (database, redis, ingestion, etc.)",
    )
