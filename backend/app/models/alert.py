"""Alert management model."""

from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", index=True, nullable=False)  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: Mapped[int] = mapped_column(Integer, default=50, index=True, nullable=False)  # 0-100
    status: Mapped[str] = mapped_column(String(30), default="NEW", index=True, nullable=False)  # NEW, TRIAGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(100), nullable=True)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    event = relationship("SecurityEvent", back_populates="alerts")
    rule = relationship("DetectionRule", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")


Index("idx_alerts_status_severity", Alert.status, Alert.severity)
Index("idx_alerts_risk_score", Alert.risk_score.desc())
