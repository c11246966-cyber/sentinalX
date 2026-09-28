"""Security event storage model with full Phase 3 telemetry fields."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base


class SecurityEvent(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
        default=lambda: f"evt_{uuid.uuid4().hex[:16]}",
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # windows, linux, network, audit, web
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)  # TCP, UDP, ICMP, HTTP
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="INFORMATIONAL", nullable=False)
    username: Mapped[str | None] = mapped_column(String(100), index=True, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_event: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    normalized_event: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(50), index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="PROCESSED", nullable=False)
    host_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    host = relationship("Host", back_populates="events")
    alerts = relationship("Alert", back_populates="event")


# Composite indexes for high-throughput time-range and correlation queries
Index("idx_events_type_timestamp", SecurityEvent.event_type, SecurityEvent.timestamp)
Index("idx_events_source_ip_timestamp", SecurityEvent.source_ip, SecurityEvent.timestamp)
Index("idx_events_hostname_timestamp", SecurityEvent.hostname, SecurityEvent.timestamp)
Index("idx_events_username_timestamp", SecurityEvent.username, SecurityEvent.timestamp)
