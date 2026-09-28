"""Event ingestion and normalization service."""

from typing import Any, Dict
from backend.app.schemas.event import EventIngest


class EventService:
    """Manages raw event reception, validation, and database persistence."""

    @staticmethod
    def normalize_event(payload: EventIngest) -> Dict[str, Any]:
        """Normalize event schema and extract standardized entities."""
        return payload.model_dump()
