"""Collector / Agent registration and status tracking model for Phase 6."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.core.database import Base


class Collector(Base):
    """Represents a registered endpoint telemetry collector/agent."""

    __tablename__ = "collectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    collector_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    operating_system: Mapped[str] = mapped_column(String(100), default="Windows", nullable=False)
    agent_version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ONLINE", index=True, nullable=False)  # ONLINE, DEGRADED, OFFLINE
    api_key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, default=dict, nullable=True)
