"""Threat intelligence indicator model."""

from datetime import datetime, timezone
from sqlalchemy import DateTime, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.core.database import Base


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    indicator: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(30), index=True, nullable=False)  # ip, domain, hash
    provider: Mapped[str] = mapped_column(String(50), default="internal", nullable=False)
    reputation: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)  # clean, suspicious, malicious
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0-100
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    raw_response: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


Index("idx_intel_indicator_lookup", ThreatIntelligence.indicator, ThreatIntelligence.indicator_type)
