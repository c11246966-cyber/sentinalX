"""Threat Intelligence API endpoints for Phase 5."""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_analyst, require_viewer
from backend.app.models.alert import Alert
from backend.app.models.incident import Incident
from backend.app.models.threat_intel import ThreatIntelligence
from backend.app.models.user import User
from backend.app.schemas.threat_intel import (
    EnrichIndicatorRequest,
    ProviderStatusResponse,
    ThreatIntelligenceRecordResponse,
    ThreatIntelResult,
)
from backend.app.services.audit_service import AuditService
from backend.app.threat_intel.indicator import validate_indicator
from backend.app.threat_intel.providers.internal import InternalIntelProvider
from backend.app.threat_intel.service import ThreatIntelManager

router = APIRouter()


@router.get(
    "/providers",
    response_model=ProviderStatusResponse,
    summary="Get internal provider status and availability (Never returns secrets)",
)
async def get_providers_status(
    current_user: Annotated[User, Depends(require_viewer)],
) -> ProviderStatusResponse:
    """Return safe metadata for configured threat intelligence providers."""
    providers_meta = ThreatIntelManager.get_provider_status()
    return ProviderStatusResponse(providers=providers_meta)


@router.post(
    "/enrich",
    response_model=ThreatIntelResult,
    summary="Enrich an indicator on-demand (Requires Analyst role)",
)
async def enrich_indicator_api(
    payload: EnrichIndicatorRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> ThreatIntelResult:
    """Trigger threat intelligence enrichment for an IPv4, IPv6, domain, URL, or hash."""
    is_valid, canonical, ind_type = validate_indicator(payload.indicator, payload.indicator_type)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid indicator format: '{payload.indicator}'. Must be a valid IPv4, IPv6, domain, URL, or hash.",
        )

    try:
        result = await ThreatIntelManager.enrich_indicator(
            indicator=canonical,
            indicator_type=ind_type,
            force_refresh=payload.force_refresh,
            db=db,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Enrichment service error: {type(exc).__name__}",
        )

    # Audit logging for analyst-triggered manual enrichment
    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="threat_intel_manual_enrich",
        target_type="indicator",
        target_id=canonical,
        user_id=current_user.id,
        details={
            "indicator_type": ind_type,
            "reputation": result.get("reputation"),
            "confidence": result.get("confidence"),
            "providers": result.get("providers_reporting"),
        },
        source_ip=client_ip,
    )

    return ThreatIntelResult(**result)


@router.get(
    "/indicators",
    response_model=List[ThreatIntelligenceRecordResponse],
    summary="List stored threat intelligence indicators with multi-field filtering",
)
async def list_indicators(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    reputation: Optional[str] = None,
    indicator_type: Optional[str] = None,
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    search: Optional[str] = None,
) -> List[ThreatIntelligenceRecordResponse]:
    """Retrieve cataloged threat indicators ordered by most recently seen."""
    query = select(ThreatIntelligence).order_by(desc(ThreatIntelligence.last_seen))

    if reputation:
        query = query.where(ThreatIntelligence.reputation == reputation.lower())
    if indicator_type:
        query = query.where(ThreatIntelligence.indicator_type == indicator_type.lower())
    if min_confidence is not None:
        query = query.where(ThreatIntelligence.confidence >= min_confidence)
    if search:
        search_pattern = f"%{search}%"
        query = query.where(ThreatIntelligence.indicator.ilike(search_pattern))

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    records = list(result.scalars().all())

    if not records and offset == 0 and not search and not reputation and not indicator_type:
        now = datetime.now(timezone.utc)
        for ind_val, info in InternalIntelProvider.KNOWN_LAB_INDICATORS.items():
            db.add(
                ThreatIntelligence(
                    indicator=ind_val,
                    indicator_type=info.get("indicator_type", "ipv4"),
                    provider="internal",
                    reputation=info["reputation"],
                    confidence=info["confidence"],
                    severity=info["severity"],
                    threat_category=info.get("threat_category", "General Threat"),
                    description=info.get("description"),
                    matching_reason=info.get("matching_reason"),
                    tags=info.get("tags", []),
                    source="internal",
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                    updated_at=now,
                )
            )
        await db.commit()
        re_result = await db.execute(query)
        records = list(re_result.scalars().all())

    return records


@router.get(
    "/indicators/{indicator}",
    response_model=ThreatIntelResult,
    summary="Get or query detailed threat intelligence for a specific indicator",
)
async def get_indicator_detail(
    indicator: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
) -> ThreatIntelResult:
    """Retrieve threat intelligence result for an indicator."""
    is_valid, canonical, ind_type = validate_indicator(indicator)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid indicator format: '{indicator}'",
        )

    try:
        result = await ThreatIntelManager.enrich_indicator(
            indicator=canonical,
            indicator_type=ind_type,
            force_refresh=False,
            db=db,
        )
        return ThreatIntelResult(**result)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lookup failed: {str(exc)}",
        )


@router.get(
    "/indicators/{indicator}/related-alerts",
    summary="Find alerts associated with a specific indicator (source IP, destination IP, or IOC)",
)
async def get_indicator_related_alerts(
    indicator: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    limit: int = Query(20, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """Retrieve alerts that reference this indicator."""
    clean_ind = indicator.strip()
    stmt = (
        select(Alert)
        .where(
            or_(
                Alert.source_ip == clean_ind,
                Alert.destination_ip == clean_ind,
                Alert.description.ilike(f"%{clean_ind}%"),
            )
        )
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "status": a.status,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "mitre_technique": a.mitre_technique,
            "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.get(
    "/indicators/{indicator}/related-incidents",
    summary="Find incidents containing alerts with this indicator",
)
async def get_indicator_related_incidents(
    indicator: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    limit: int = Query(10, ge=1, le=50),
) -> List[Dict[str, Any]]:
    """Retrieve correlated incidents associated with this indicator."""
    clean_ind = indicator.strip()
    # 1. Find alert IDs with this indicator
    alert_stmt = select(Alert.incident_id).where(
        or_(
            Alert.source_ip == clean_ind,
            Alert.destination_ip == clean_ind,
            Alert.description.ilike(f"%{clean_ind}%"),
        )
    )
    res = await db.execute(alert_stmt)
    incident_ids = [row[0] for row in res.all() if row[0] is not None]

    if not incident_ids:
        # Also check incident description directly
        inc_stmt = select(Incident).where(Incident.description.ilike(f"%{clean_ind}%")).limit(limit)
        inc_res = await db.execute(inc_stmt)
        return [
            {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "status": inc.status,
                "created_at": inc.created_at.isoformat(),
            }
            for inc in inc_res.scalars().all()
        ]

    inc_query = (
        select(Incident)
        .where(Incident.id.in_(incident_ids))
        .order_by(desc(Incident.created_at))
        .limit(limit)
    )
    result = await db.execute(inc_query)
    incidents = result.scalars().all()

    return [
        {
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "status": inc.status,
            "created_at": inc.created_at.isoformat(),
        }
        for inc in incidents
    ]
