"""ARGUS Event Repository.

Data access layer for security events. All database operations
for events go through this module, keeping the rest of the
application independent of SQLAlchemy specifics.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from argus.database.models import SecurityEvent
from argus.schemas import ArgusEvent

logger = logging.getLogger("argus.database.repository")


class EventRepository:
    """Repository for CRUD operations on security events."""

    def __init__(self, db: Session):
        self.db = db

    def create_event(self, event: ArgusEvent) -> SecurityEvent | None:
        """Insert a normalized ARGUS event into the database.

        Returns the created SecurityEvent, or None if the event_id
        already exists (deduplication).
        """
        db_event = SecurityEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            source_ip=event.source_ip,
            source_port=event.source_port,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol,
            service=event.service,
            duration=event.duration,
            source_bytes=event.source_bytes,
            destination_bytes=event.destination_bytes,
            connection_state=event.connection_state,
            attack_type=event.attack_type,
            severity=event.severity,
            raw_event=_serialize_raw_event(event.raw_event),
            metadata_=event.metadata,
            created_at=event.created_at,
        )

        try:
            self.db.add(db_event)
            self.db.commit()
            self.db.refresh(db_event)
            logger.debug("Inserted event: %s", event.event_id)
            return db_event
        except IntegrityError:
            self.db.rollback()
            logger.warning("Duplicate event_id (skipping): %s", event.event_id)
            return None

    def create_events_bulk(self, events: list[ArgusEvent]) -> int:
        """Insert multiple events in a single transaction.

        Returns the count of successfully inserted events.
        Skips duplicates silently.
        """
        inserted = 0

        for event in events:
            db_event = SecurityEvent(
                event_id=event.event_id,
                timestamp=event.timestamp,
                source=event.source,
                event_type=event.event_type,
                source_ip=event.source_ip,
                source_port=event.source_port,
                destination_ip=event.destination_ip,
                destination_port=event.destination_port,
                protocol=event.protocol,
                service=event.service,
                duration=event.duration,
                source_bytes=event.source_bytes,
                destination_bytes=event.destination_bytes,
                connection_state=event.connection_state,
                attack_type=event.attack_type,
                severity=event.severity,
                raw_event=_serialize_raw_event(event.raw_event),
                metadata_=event.metadata,
                created_at=event.created_at,
            )
            self.db.add(db_event)
            inserted += 1

        try:
            self.db.commit()
            logger.info("Bulk inserted %d events", inserted)
            return inserted
        except IntegrityError as e:
            self.db.rollback()
            logger.warning("Bulk insert failed (falling back to individual): %s", e)
            # Fallback: insert one by one, skipping duplicates
            inserted = 0
            for event in events:
                result = self.create_event(event)
                if result is not None:
                    inserted += 1
            return inserted

    def get_event_by_id(self, event_id: str) -> SecurityEvent | None:
        """Retrieve a single event by its ARGUS event_id."""
        return (
            self.db.query(SecurityEvent)
            .filter(SecurityEvent.event_id == event_id)
            .first()
        )

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        min_severity: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[SecurityEvent]:
        """Query events with optional filters.

        Supports filtering by source, event_type, IPs, severity, and
        time range. Results are ordered by timestamp descending (newest first).
        """
        query = self.db.query(SecurityEvent)

        if source:
            query = query.filter(SecurityEvent.source == source)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if source_ip:
            query = query.filter(SecurityEvent.source_ip == source_ip)
        if destination_ip:
            query = query.filter(SecurityEvent.destination_ip == destination_ip)
        if min_severity is not None:
            query = query.filter(SecurityEvent.severity >= min_severity)
        if start_time:
            query = query.filter(SecurityEvent.timestamp >= start_time)
        if end_time:
            query = query.filter(SecurityEvent.timestamp <= end_time)

        return (
            query.order_by(SecurityEvent.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count_events(
        self,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> int:
        """Count events with optional filters."""
        query = self.db.query(func.count(SecurityEvent.id))

        if source:
            query = query.filter(SecurityEvent.source == source)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)

        return query.scalar() or 0


def _serialize_raw_event(raw_event: dict | None) -> dict | None:
    """Ensure raw_event is JSON-serializable.

    Converts datetime objects to ISO format strings since JSONB
    cannot store Python datetime objects directly.
    """
    if raw_event is None:
        return None

    def _convert(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    return {k: _convert(v) for k, v in raw_event.items()}
