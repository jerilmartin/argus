"""ARGUS Event API Routes.

Provides REST endpoints for creating, retrieving, and analyzing
security events. The /analyze endpoint is a placeholder for
Phase 3 ML integration.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from argus.database.database import get_db
from argus.database.repository import EventRepository
from argus.schemas import (
    AnalysisResult,
    ArgusEvent,
    ArgusEventListResponse,
    ArgusEventResponse,
)

router = APIRouter(prefix="/events", tags=["events"])


def _db_event_to_pydantic(db_event) -> ArgusEvent:
    """Convert a SQLAlchemy SecurityEvent to an ArgusEvent Pydantic model."""
    return ArgusEvent(
        event_id=db_event.event_id,
        timestamp=db_event.timestamp,
        source=db_event.source,
        event_type=db_event.event_type,
        source_ip=db_event.source_ip,
        source_port=db_event.source_port,
        destination_ip=db_event.destination_ip,
        destination_port=db_event.destination_port,
        protocol=db_event.protocol,
        service=db_event.service,
        duration=db_event.duration,
        source_bytes=db_event.source_bytes,
        destination_bytes=db_event.destination_bytes,
        connection_state=db_event.connection_state,
        attack_type=db_event.attack_type,
        severity=db_event.severity,
        raw_event=db_event.raw_event,
        metadata=db_event.metadata_,
        created_at=db_event.created_at,
    )


@router.get("", response_model=ArgusEventListResponse)
async def get_events(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    source: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    destination_ip: Optional[str] = Query(default=None),
    min_severity: Optional[int] = Query(default=None, ge=0, le=100),
    db: Session = Depends(get_db),
):
    """Retrieve normalized security events with optional filters.

    Supports pagination via limit/offset and filtering by source,
    event_type, IPs, and minimum severity.
    """
    repo = EventRepository(db)
    db_events = repo.get_events(
        limit=limit,
        offset=offset,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        min_severity=min_severity,
    )
    total = repo.count_events(
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        min_severity=min_severity,
    )

    events = [_db_event_to_pydantic(e) for e in db_events]
    return ArgusEventListResponse(events=events, total=total)


@router.get("/{event_id}", response_model=ArgusEventResponse)
async def get_event(event_id: str, db: Session = Depends(get_db)):
    """Retrieve a single event by its ARGUS event_id."""
    repo = EventRepository(db)
    db_event = repo.get_event_by_id(event_id)

    if db_event is None:
        raise HTTPException(status_code=404, detail=f"Event not found: {event_id}")

    return ArgusEventResponse(event=_db_event_to_pydantic(db_event))


@router.post("", response_model=ArgusEventResponse, status_code=201)
async def create_event(event: ArgusEvent, db: Session = Depends(get_db)):
    """Store a normalized ARGUS event.

    Accepts a complete ArgusEvent and persists it to the database.
    Returns 409 if the event_id already exists.
    """
    repo = EventRepository(db)
    db_event = repo.create_event(event)

    if db_event is None:
        raise HTTPException(
            status_code=409,
            detail=f"Event already exists: {event.event_id}",
        )

    return ArgusEventResponse(event=_db_event_to_pydantic(db_event))


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_event(event: ArgusEvent):
    """Placeholder for ML analysis.

    In Phase 3, this endpoint will:
    1. Run the event through the anomaly detection model
    2. Classify the attack type
    3. Compute a risk score (0-100)

    Currently returns a placeholder indicating ML is not yet implemented.
    """
    return AnalysisResult(
        event_id=event.event_id,
        status="ml_not_implemented",
        message="ML analysis will be available in Phase 3. "
                "The event has been received but not scored.",
        anomaly_score=None,
        attack_type=None,
        risk_score=None,
    )
