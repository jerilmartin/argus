"""ARGUS Zeek Log Parser.

Parses Zeek TSV log files (conn.log, dns.log, etc.) into structured
Python dictionaries. Handles Zeek header lines, field detection,
type conversion, and unset value normalization.

Designed to be reusable across all Zeek log types.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger("argus.parsers.zeek")

# Zeek type conversion mapping
ZEEK_TYPE_CONVERTERS = {
    "time": lambda v: datetime.fromtimestamp(float(v), tz=timezone.utc),
    "interval": lambda v: float(v),
    "count": lambda v: int(v),
    "int": lambda v: int(v),
    "port": lambda v: int(v),
    "double": lambda v: float(v),
    "bool": lambda v: v == "T",
    "string": lambda v: v,
    "addr": lambda v: v,
    "subnet": lambda v: v,
    "enum": lambda v: v,
}


def _get_converter(zeek_type: str):
    """Get a type converter function for a Zeek type.

    Handles compound types like set[string], vector[string], etc.
    """
    # Handle compound types
    if zeek_type.startswith("set[") or zeek_type.startswith("vector["):
        return lambda v: v.split(",") if v else []

    return ZEEK_TYPE_CONVERTERS.get(zeek_type, lambda v: v)


class ZeekLogParser:
    """Parser for Zeek TSV log files.

    Reads Zeek log headers to determine field names, types, and
    separator/unset conventions, then parses data lines into
    structured dictionaries with proper type conversion.

    Usage:
        parser = ZeekLogParser()
        for record in parser.parse_file("logs/zeek/conn.log"):
            print(record)
    """

    def __init__(self):
        self.separator: str = "\t"
        self.set_separator: str = ","
        self.empty_field: str = "(empty)"
        self.unset_field: str = "-"
        self.path: str | None = None
        self.fields: list[str] = []
        self.types: list[str] = []

    def _parse_header_line(self, line: str) -> bool:
        """Parse a Zeek header line. Returns True if it was a header line."""
        line = line.rstrip("\n\r")

        if line.startswith("#separator"):
            # The separator value uses escaped representation
            sep_value = line.split(" ", 1)[1] if " " in line else "\\x09"
            # Convert \\x09 to actual tab character
            self.separator = bytes(sep_value, "utf-8").decode("unicode_escape")
            return True

        if line.startswith("#set_separator"):
            self.set_separator = line.split(self.separator, 1)[1]
            return True

        if line.startswith("#empty_field"):
            self.empty_field = line.split(self.separator, 1)[1]
            return True

        if line.startswith("#unset_field"):
            self.unset_field = line.split(self.separator, 1)[1]
            return True

        if line.startswith("#path"):
            self.path = line.split(self.separator, 1)[1]
            return True

        if line.startswith("#fields"):
            self.fields = line.split(self.separator)[1:]
            return True

        if line.startswith("#types"):
            self.types = line.split(self.separator)[1:]
            return True

        if line.startswith("#open") or line.startswith("#close"):
            return True

        if line.startswith("#"):
            return True

        return False

    def _convert_value(self, value: str, field_index: int) -> Any:
        """Convert a Zeek field value to its appropriate Python type.

        Returns None for unset or empty fields.
        """
        if value == self.unset_field:
            return None
        if value == self.empty_field:
            return None

        if field_index < len(self.types):
            zeek_type = self.types[field_index]
            converter = _get_converter(zeek_type)
            try:
                return converter(value)
            except (ValueError, TypeError, OverflowError) as e:
                field_name = (
                    self.fields[field_index]
                    if field_index < len(self.fields)
                    else f"field_{field_index}"
                )
                logger.warning(
                    "Failed to convert field '%s' value '%s' as type '%s': %s",
                    field_name,
                    value,
                    zeek_type,
                    e,
                )
                return value

        return value

    def parse_line(self, line: str) -> dict[str, Any] | None:
        """Parse a single Zeek data line into a dictionary.

        Returns None if the line is a header/comment or empty.
        Requires that headers have already been parsed.
        """
        line = line.rstrip("\n\r")

        if not line or line.startswith("#"):
            return None

        parts = line.split(self.separator)

        if len(parts) != len(self.fields):
            logger.warning(
                "Field count mismatch: expected %d, got %d in line: %s",
                len(self.fields),
                len(parts),
                line[:100],
            )
            return None

        record = {}
        for i, (field, value) in enumerate(zip(self.fields, parts)):
            record[field] = self._convert_value(value, i)

        return record

    def parse_file(self, filepath: str | Path) -> Generator[dict[str, Any], None, None]:
        """Parse a Zeek log file, yielding one dictionary per data line.

        Automatically reads and processes header lines first, then
        yields converted data records.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Zeek log file not found: {filepath}")

        logger.info("Parsing Zeek log file: %s", filepath)

        # Reset state for this file
        self.fields = []
        self.types = []
        self.path = None

        record_count = 0

        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if self._parse_header_line(line):
                    continue

                record = self.parse_line(line)
                if record is not None:
                    record_count += 1
                    yield record

        logger.info(
            "Finished parsing %s: %d records from log type '%s'",
            filepath.name,
            record_count,
            self.path,
        )

    def get_log_type(self) -> str | None:
        """Return the Zeek log type (from #path header), e.g. 'conn', 'dns'."""
        return self.path
