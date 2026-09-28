"""Audit log retrieval API endpoints."""

from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_admin, require_analyst
from backend.app.models.user import User
from backend.app.schemas.audit import AuditLogResponse
from backend.app.services.audit_service import AuditService

router = APIRouter()


@router.get(
    "",
    response_model=List[AuditLogResponse],
    summary="List SOC security audit logs (Requires Analyst or Admin role)",
)
@router.get(
    "/",
    response_model=List[AuditLogResponse],
    include_in_schema=False,
)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    target_type: Optional[str] = None,
) -> List[AuditLogResponse]:
    """Query chronological audit log events."""
    logs = await AuditService.get_logs(
        db=db,
        limit=limit,
        offset=offset,
        action=action,
        target_type=target_type,
    )
    return logs
