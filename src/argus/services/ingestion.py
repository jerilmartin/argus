"""ARGUS Ingestion Service.

Reads Zeek and Suricata log files, parses them, normalizes them
into the ARGUS unified schema, and stores them in PostgreSQL.

Supports offline (batch) ingestion from files. Live file watching
will be added in a future phase.

CLI Usage:
    python -m argus.services.ingestion --source zeek --file logs/zeek/conn.log
    python -m argus.services.ingestion --source zeek --file logs/zeek/dns.log
    python -m argus.services.ingestion --source suricata --file logs/suricata/eve.json
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from argus.database.database import SessionLocal, init_db
from argus.database.repository import EventRepository
from argus.parsers.suricata_parser import SuricataEveParser
from argus.parsers.zeek_parser import ZeekLogParser
from argus.schemas import ArgusEvent
from argus.services.normalization import (
    normalize_suricata_event,
    normalize_zeek_event,
)
from argus.utils.logging import setup_logging

logger = logging.getLogger("argus.services.ingestion")


def ingest_zeek_file(filepath: str | Path) -> list[ArgusEvent]:
    """Parse and normalize a Zeek log file.

    Returns a list of normalized ARGUS events.
    """
    filepath = Path(filepath)
    logger.info("Ingesting Zeek file: %s", filepath)

    parser = ZeekLogParser()
    events: list[ArgusEvent] = []

    for raw_record in parser.parse_file(filepath):
        log_type = parser.get_log_type() or "unknown"
        try:
            event = normalize_zeek_event(raw_record, log_type)
            events.append(event)
        except Exception as e:
            logger.error("Failed to normalize Zeek record: %s", e)

    logger.info("Normalized %d events from Zeek file: %s", len(events), filepath.name)
    return events


def ingest_suricata_file(filepath: str | Path) -> list[ArgusEvent]:
    """Parse and normalize a Suricata EVE JSON file.

    Returns a list of normalized ARGUS events.
    """
    filepath = Path(filepath)
    logger.info("Ingesting Suricata file: %s", filepath)

    parser = SuricataEveParser()
    events: list[ArgusEvent] = []

    for raw_event in parser.parse_file(filepath):
        try:
            event = normalize_suricata_event(raw_event)
            events.append(event)
        except Exception as e:
            logger.error("Failed to normalize Suricata event: %s", e)

    logger.info(
        "Normalized %d events from Suricata file: %s", len(events), filepath.name
    )
    return events


def store_events(events: list[ArgusEvent]) -> int:
    """Store a list of normalized events in PostgreSQL.

    Returns the count of successfully inserted events.
    """
    if not events:
        logger.warning("No events to store")
        return 0

    db = SessionLocal()
    try:
        repo = EventRepository(db)
        inserted = repo.create_events_bulk(events)
        logger.info("Stored %d events in database", inserted)
        return inserted
    finally:
        db.close()


def ingest_file(source: str, filepath: str | Path) -> int:
    """Full ingestion pipeline: parse → normalize → store.

    Args:
        source: "zeek" or "suricata"
        filepath: Path to the log file

    Returns:
        Number of events successfully stored.
    """
    filepath = Path(filepath)

    if not filepath.exists():
        logger.error("File not found: %s", filepath)
        return 0

    # Parse and normalize
    if source == "zeek":
        events = ingest_zeek_file(filepath)
    elif source == "suricata":
        events = ingest_suricata_file(filepath)
    else:
        logger.error("Unknown source: %s (expected 'zeek' or 'suricata')", source)
        return 0

    # Store in database
    return store_events(events)


def main():
    """CLI entry point for the ingestion service."""
    argparser = argparse.ArgumentParser(
        description="ARGUS Ingestion Service — ingest security logs into PostgreSQL",
    )
    argparser.add_argument(
        "--source",
        required=True,
        choices=["zeek", "suricata"],
        help="Log source type",
    )
    argparser.add_argument(
        "--file",
        required=True,
        help="Path to the log file to ingest",
    )
    argparser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )

    args = argparser.parse_args()

    # Initialize
    setup_logging(level=args.log_level)
    init_db()

    # Run ingestion
    filepath = Path(args.file)
    logger.info("=" * 60)
    logger.info("ARGUS Ingestion — source=%s file=%s", args.source, filepath)
    logger.info("=" * 60)

    count = ingest_file(args.source, filepath)

    logger.info("=" * 60)
    logger.info("Ingestion complete: %d events stored", count)
    logger.info("=" * 60)

    if count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
