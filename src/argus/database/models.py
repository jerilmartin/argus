"""ARGUS Database Models (SQLAlchemy ORM).

Defines the security_events table that stores all normalized ARGUS events.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for ARGUS models."""
    pass


class SecurityEvent(Base):
    """Normalized security event stored in PostgreSQL.

    This table is the persistent store for all ARGUS events,
    regardless of their source (Zeek, Suricata, future tools).

    Mirrors the ArgusEvent Pydantic schema for consistency.
    """

    __tablename__ = "security_events"

    # Primary key (database-internal)
    id = Column(Integer, primary_key=True, autoincrement=True)

    # ARGUS event identity
    event_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    source = Column(String(20), nullable=False)
    event_type = Column(String(50), nullable=False)

    # Network 5-tuple
    source_ip = Column(String(45), nullable=True)  # IPv6 max length
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(45), nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)

    # Service / Application
    service = Column(String(50), nullable=True)

    # Traffic metrics
    duration = Column(Float, nullable=True)
    source_bytes = Column(Integer, nullable=True)
    destination_bytes = Column(Integer, nullable=True)

    # Connection state
    connection_state = Column(String(20), nullable=True)

    # Threat intelligence (populated by ML in Phase 3)
    attack_type = Column(String(100), nullable=True)
    severity = Column(Integer, nullable=True)

    # Raw data preservation
    raw_event = Column(JSONB, nullable=True)
    metadata_ = Column("metadata", JSONB, nullable=True)

    # Record tracking
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Indexes for common query patterns
    __table_args__ = (
        Index("ix_security_events_timestamp", "timestamp"),
        Index("ix_security_events_source", "source"),
        Index("ix_security_events_event_type", "event_type"),
        Index("ix_security_events_source_ip", "source_ip"),
        Index("ix_security_events_destination_ip", "destination_ip"),
        Index("ix_security_events_severity", "severity"),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent(event_id={self.event_id!r}, "
            f"source={self.source!r}, "
            f"event_type={self.event_type!r}, "
            f"source_ip={self.source_ip!r})>"
        )
