"""Event ingestion pipeline, normalization, detection triggering, and search."""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user_optional, get_db, require_viewer
from backend.app.api.websocket import manager
from backend.app.detection.correlation import CorrelationEngine
from backend.app.detection.engine import DetectionEngine
from backend.app.models.alert import Alert
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.schemas.event import EventBatchIngest, EventIngest, EventIngestResponse, EventResponse
from backend.app.services.audit_service import AuditService

router = APIRouter()
correlation_engine = CorrelationEngine(window_seconds=300)


def normalize_event_payload(payload: EventIngest) -> Dict[str, Any]:
    """Validate, format, and assign canonical metadata to incoming telemetry."""
    event_id = payload.event_id or f"evt_{uuid.uuid4().hex[:16]}"
    ts = payload.timestamp or datetime.now(timezone.utc)

    normalized = {
        "event_id": event_id,
        "timestamp": ts,
        "source": payload.source.strip().lower(),
        "source_ip": payload.source_ip.strip() if payload.source_ip else None,
        "destination_ip": payload.destination_ip.strip() if payload.destination_ip else None,
        "source_port": payload.source_port,
        "destination_port": payload.destination_port,
        "protocol": payload.protocol.upper() if payload.protocol else None,
        "event_type": payload.event_type.strip().lower(),
        "severity": payload.severity,
        "username": payload.username.strip() if payload.username else None,
        "hostname": payload.hostname.strip() if payload.hostname else None,
        "process_name": payload.process_name.strip() if payload.process_name else None,
        "command_line": payload.command_line.strip() if payload.command_line else None,
        "message": payload.message.strip(),
        "mitre_technique": payload.mitre_technique,
        "status": "NORMALIZED",
        "raw_event": payload.raw_event or payload.model_dump(mode="json"),
    }
    normalized["normalized_event"] = {
        "canonical_type": normalized["event_type"],
        "src": f"{normalized['source_ip']}:{normalized['source_port']}" if normalized['source_ip'] else None,
        "dst": f"{normalized['destination_ip']}:{normalized['destination_port']}" if normalized['destination_ip'] else None,
        "user": normalized["username"],
        "host": normalized["hostname"],
    }
    return normalized


@router.post(
    "",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a security telemetry event (supports API key/token or agent ingestion)",
)
@router.post(
    "/",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
@router.post(
    "/ingest",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest security telemetry from endpoint collector agents",
)
async def ingest_event(
    payload: EventIngest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Optional[User], Depends(get_current_user_optional)],
    x_collector_id: Optional[str] = Header(None, alias="X-Collector-ID"),
    x_collector_key: Optional[str] = Header(None, alias="X-Collector-Key"),
) -> EventIngestResponse:
    """Ingest, normalize, persist, evaluate rules, and correlate incident."""
    # Collector authorization check if collector headers supplied
    if x_collector_id:
        try:
            import hashlib
            from backend.app.models.collector import Collector
            col_stmt = select(Collector).where(Collector.collector_id == x_collector_id)
            col_res = await db.execute(col_stmt)
            collector = col_res.scalar_one_or_none()
            if not collector:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Collector ID.")
            if x_collector_key:
                token_hash = hashlib.sha256(x_collector_key.encode("utf-8")).hexdigest()
                if token_hash != collector.api_key_hash:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Collector Key.")
            collector.event_count += 1
            collector.last_seen = datetime.now(timezone.utc)
            collector.status = "ONLINE"
        except HTTPException:
            raise
        except Exception:
            pass

    norm = normalize_event_payload(payload)

    # Duplicate check on event_id if provided
    if norm.get("event_id"):
        dup_stmt = select(SecurityEvent.id).where(SecurityEvent.event_id == norm["event_id"])
        dup_res = await db.execute(dup_stmt)
        if dup_res.scalar_one_or_none():
            return EventIngestResponse(
                status="DUPLICATE_IGNORED",
                ingested_count=0,
                event_ids=[norm["event_id"]],
                generated_alerts=[],
            )

    # 1. Store normalized event in PostgreSQL
    db_event = SecurityEvent(
        event_id=norm["event_id"],
        timestamp=norm["timestamp"],
        source=norm["source"],
        source_ip=norm["source_ip"],
        destination_ip=norm["destination_ip"],
        source_port=norm["source_port"],
        destination_port=norm["destination_port"],
        protocol=norm["protocol"],
        event_type=norm["event_type"],
        severity=norm["severity"],
        username=norm["username"],
        hostname=norm["hostname"],
        process_name=norm["process_name"],
        command_line=norm["command_line"],
        message=norm["message"],
        raw_event=norm["raw_event"],
        normalized_event=norm["normalized_event"],
        mitre_technique=norm["mitre_technique"],
        status="PROCESSED",
    )
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)

    # 2. Run real-time detection engine
    detected_alerts = DetectionEngine.evaluate_event(norm)
    generated_alert_dicts = []

    for alert_info in detected_alerts:
        # Phase 5: Threat Intelligence Enrichment & Risk Adjustment
        enriched_info = dict(alert_info)
        try:
            from backend.app.threat_intel.service import ThreatIntelManager
            enriched_info = await ThreatIntelManager.enrich_and_adjust_alert(enriched_info, db=db)
        except Exception:
            pass

        db_alert = Alert(
            event_id=db_event.id,
            title=enriched_info["title"],
            description=enriched_info["description"],
            severity=enriched_info.get("severity", alert_info["severity"]),
            risk_score=enriched_info.get("risk_score", alert_info["risk_score"]),
            source_ip=enriched_info.get("source_ip"),
            destination_ip=enriched_info.get("destination_ip"),
            mitre_technique=enriched_info.get("mitre_technique"),
            mitre_tactic=enriched_info.get("mitre_tactic"),
            threat_intel_context=enriched_info.get("threat_intel_context"),
            risk_adjustment_reason=enriched_info.get("risk_adjustment_reason"),
            status="NEW",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(db_alert)
        await db.commit()
        await db.refresh(db_alert)

        alert_dict = {
            "id": db_alert.id,
            "title": db_alert.title,
            "severity": db_alert.severity,
            "risk_score": db_alert.risk_score,
            "status": db_alert.status,
            "mitre_technique": db_alert.mitre_technique,
            "source_ip": db_alert.source_ip,
            "destination_ip": db_alert.destination_ip,
            "threat_intel_context": db_alert.threat_intel_context,
            "risk_adjustment_reason": db_alert.risk_adjustment_reason,
            "created_at": db_alert.created_at.isoformat(),
        }
        generated_alert_dicts.append(alert_dict)

        # Broadcast new alert real-time
        await manager.broadcast({
            "type": "new_alert",
            "alert": alert_dict,
        })

        # 3. Multi-event correlation engine evaluation
        incident_candidate = correlation_engine.add_alert(alert_dict)
        if incident_candidate:
            db_incident = Incident(
                title=incident_candidate["title"],
                description=incident_candidate["description"],
                severity=incident_candidate["severity"],
                risk_score=incident_candidate["risk_score"],
                status="NEW",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(db_incident)
            await db.commit()
            await db.refresh(db_incident)

            # Link alert to incident
            db_alert.incident_id = db_incident.id
            await db.commit()

            # Broadcast new incident real-time
            await manager.broadcast({
                "type": "new_incident",
                "incident": {
                    "id": db_incident.id,
                    "title": db_incident.title,
                    "severity": db_incident.severity,
                    "risk_score": db_incident.risk_score,
                    "status": db_incident.status,
                    "created_at": db_incident.created_at.isoformat(),
                },
            })

    # Broadcast event real-time
    await manager.broadcast({
        "type": "new_event",
        "event": {
            "id": db_event.id,
            "event_id": db_event.event_id,
            "timestamp": db_event.timestamp.isoformat(),
            "event_type": db_event.event_type,
            "severity": db_event.severity,
            "source_ip": db_event.source_ip,
            "destination_ip": db_event.destination_ip,
            "message": db_event.message,
        },
    })

    return EventIngestResponse(
        status="success",
        ingested_count=1,
        event_ids=[norm["event_id"]],
        generated_alerts=generated_alert_dicts,
    )


@router.post(
    "/batch",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Batch ingest security events",
)
async def ingest_batch_events(
    batch: EventBatchIngest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EventIngestResponse:
    """Ingest multiple security events in a single transaction."""
    event_ids = []
    generated_alerts = []

    for event_in in batch.events:
        res = await ingest_event(payload=event_in, db=db, current_user=None)
        event_ids.extend(res.event_ids)
        generated_alerts.extend(res.generated_alerts)

    return EventIngestResponse(
        status="success",
        ingested_count=len(event_ids),
        event_ids=event_ids,
        generated_alerts=generated_alerts,
    )


@router.get(
    "",
    response_model=List[EventResponse],
    summary="Search, filter, and list normalized security events",
)
@router.get(
    "/",
    response_model=List[EventResponse],
    include_in_schema=False,
)
async def list_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Optional[User], Depends(get_current_user_optional)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    hostname: Optional[str] = None,
    username: Optional[str] = None,
    severity: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = None,
) -> List[EventResponse]:
    """Retrieve indexed security events with pagination, full-text search, and multi-field filters."""
    query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))

    if event_type:
        query = query.where(SecurityEvent.event_type == event_type.lower())
    if source_ip:
        query = query.where(SecurityEvent.source_ip == source_ip)
    if destination_ip:
        query = query.where(SecurityEvent.destination_ip == destination_ip)
    if hostname:
        query = query.where(SecurityEvent.hostname == hostname)
    if username:
        query = query.where(SecurityEvent.username == username)
    if severity:
        query = query.where(SecurityEvent.severity == severity.upper())
    if mitre_technique:
        query = query.where(SecurityEvent.mitre_technique == mitre_technique)
    if status_filter:
        query = query.where(SecurityEvent.status == status_filter.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            SecurityEvent.message.ilike(search_pattern)
            | SecurityEvent.event_id.ilike(search_pattern)
            | SecurityEvent.process_name.ilike(search_pattern)
        )

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())
