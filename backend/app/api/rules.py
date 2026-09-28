"""MITRE ATT&CK and Detection Rules endpoints."""

from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_admin, require_analyst, require_viewer
from backend.app.detection.mitre import get_all_mitre_techniques, lookup_mitre
from backend.app.models.rule import DetectionRule
from backend.app.models.user import User
from backend.app.schemas.rule import DetectionRuleCreate, DetectionRuleResponse, DetectionRuleUpdate

router = APIRouter()


@router.get(
    "",
    response_model=List[DetectionRuleResponse],
    summary="List active detection rules",
)
@router.get(
    "/",
    response_model=List[DetectionRuleResponse],
    include_in_schema=False,
)
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    category: Optional[str] = None,
    severity: Optional[str] = None,
) -> List[DetectionRuleResponse]:
    """Retrieve catalog of detection rules."""
    stmt = select(DetectionRule).order_by(DetectionRule.id.asc())
    if category:
        stmt = stmt.where(DetectionRule.category == category.lower())
    if severity:
        stmt = stmt.where(DetectionRule.severity == severity.upper())
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get(
    "/mitre",
    summary="Get full MITRE ATT&CK technique catalog mapped to detection engine",
)
async def get_mitre_catalog(
    current_user: Annotated[User, Depends(require_viewer)],
) -> List[Dict[str, str]]:
    """Expose full MITRE technique and tactic mappings."""
    return get_all_mitre_techniques()


@router.get(
    "/mitre/{technique_id}",
    summary="Lookup specific MITRE technique details",
)
async def get_mitre_technique(
    technique_id: str,
    current_user: Annotated[User, Depends(require_viewer)],
) -> Dict[str, str]:
    """Lookup single MITRE technique by ID (e.g. T1046, T1110)."""
    info = lookup_mitre(technique_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MITRE technique '{technique_id}' not found in platform catalog",
        )
    return info
