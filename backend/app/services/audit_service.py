"""Audit logging service for SOC operations and security events."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.models.audit import AuditLog


class AuditService:
    """Handles persistent recording of compliance and operational audit trails."""

    @staticmethod
    async def log_action(
        db: AsyncSession,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
    ) -> Optional[AuditLog]:
        """Record an immutable audit log entry."""
        if not getattr(settings, "AUDIT_LOG_ENABLED", True):
            return None

        try:
            entry = AuditLog(
                user_id=user_id,
                action=action,
                target_type=target_type,
                target_id=str(target_id) if target_id is not None else None,
                details=details or {},
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
            )
            db.add(entry)
            await db.commit()
            await db.refresh(entry)
            logger.info("AUDIT [%s] by user_id=%s on %s:%s", action, user_id, target_type, target_id)
            return entry
        except Exception as exc:
            await db.rollback()
            logger.error("Failed to write audit log entry: %s", exc)
            return None

    @staticmethod
    async def get_logs(
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> List[AuditLog]:
        """Retrieve paginated audit logs ordered by newest first."""
        query = select(AuditLog).order_by(desc(AuditLog.timestamp))
        if action:
            query = query.where(AuditLog.action == action)
        if target_type:
            query = query.where(AuditLog.target_type == target_type)

        query = query.limit(limit).offset(offset)
        result = await db.execute(query)
        return list(result.scalars().all())
