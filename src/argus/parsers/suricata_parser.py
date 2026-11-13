"""ARGUS Suricata EVE JSON Parser.

Parses Suricata EVE JSON log files (eve.json) into structured Python
dictionaries. Handles JSON Lines format, malformed lines, and
normalizes Suricata event fields.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger("argus.parsers.suricata")


class SuricataEveParser:
    """Parser for Suricata EVE JSON log files.

    Reads eve.json (JSON Lines format — one JSON object per line),
    parses each event, and yields structured dictionaries.

    Usage:
        parser = SuricataEveParser()
        for event in parser.parse_file("logs/suricata/eve.json"):
            print(event)
    """

    # Event types that contain useful security data
    SECURITY_EVENT_TYPES = {"alert", "dns", "http", "tls", "flow", "fileinfo", "ssh", "smb"}

    # Event types to skip (stats, internal housekeeping)
    SKIP_EVENT_TYPES = {"stats"}

    def parse_line(self, line: str) -> dict[str, Any] | None:
        """Parse a single JSON line from eve.json.

        Returns None for blank lines or events that should be skipped.
        Returns the parsed dictionary for valid events.
        Logs a warning for malformed JSON.
        """
        line = line.strip()
        if not line:
            return None

        try:
            event = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning("Malformed JSON line (skipping): %s — %s", line[:100], e)
            return None

        if not isinstance(event, dict):
            logger.warning("EVE line is not a JSON object (skipping): %s", type(event))
            return None

        # Skip stats events — they are internal Suricata housekeeping
        event_type = event.get("event_type", "")
        if event_type in self.SKIP_EVENT_TYPES:
            logger.debug("Skipping event_type '%s'", event_type)
            return None

        return event

    def parse_file(self, filepath: str | Path) -> Generator[dict[str, Any], None, None]:
        """Parse a Suricata EVE JSON file, yielding one dict per valid event.

        Skips blank lines, malformed JSON, and stats events.
        Preserves all other events including dns, flow, alert, http, etc.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Suricata EVE file not found: {filepath}")

        logger.info("Parsing Suricata EVE file: %s", filepath)

        record_count = 0
        error_count = 0

        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                event = self.parse_line(line)
                if event is not None:
                    record_count += 1
                    yield event
                elif line.strip():
                    # Non-empty line that failed parsing or was skipped
                    error_count += 1

        logger.info(
            "Finished parsing %s: %d events parsed, %d skipped/errors",
            filepath.name,
            record_count,
            error_count,
        )
