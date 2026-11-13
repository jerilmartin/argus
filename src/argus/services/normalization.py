"""ARGUS Normalization Service.

Converts raw parsed events from Zeek and Suricata into the unified
ARGUS event schema. This is the bridge between source-specific parsers
and the rest of the ARGUS pipeline.

This layer is intentionally independent of the database — it only
transforms data structures.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from argus.schemas import ArgusEvent

logger = logging.getLogger("argus.services.normalization")


def normalize_zeek_conn(raw: dict[str, Any]) -> ArgusEvent:
    """Normalize a Zeek conn.log record into an ARGUS event.

    Maps Zeek connection fields to the unified schema:
        id.orig_h -> source_ip
        id.orig_p -> source_port
        id.resp_h -> destination_ip
        id.resp_p -> destination_port
        proto      -> protocol
        service    -> service
        duration   -> duration
        orig_bytes -> source_bytes
        resp_bytes -> destination_bytes
        conn_state -> connection_state
    """
    timestamp = raw.get("ts")
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif not isinstance(timestamp, datetime):
        timestamp = datetime.now(timezone.utc)

    return ArgusEvent(
        timestamp=timestamp,
        source="zeek",
        event_type="connection",
        source_ip=raw.get("id.orig_h"),
        source_port=_safe_int(raw.get("id.orig_p")),
        destination_ip=raw.get("id.resp_h"),
        destination_port=_safe_int(raw.get("id.resp_p")),
        protocol=_safe_lower(raw.get("proto")),
        service=_safe_lower(raw.get("service")),
        duration=_safe_float(raw.get("duration")),
        source_bytes=_safe_int(raw.get("orig_bytes")),
        destination_bytes=_safe_int(raw.get("resp_bytes")),
        connection_state=raw.get("conn_state"),
        attack_type=None,
        severity=None,
        raw_event=raw,
        metadata={
            "zeek_uid": raw.get("uid"),
            "zeek_log_type": "conn",
            "history": raw.get("history"),
            "missed_bytes": _safe_int(raw.get("missed_bytes")),
            "orig_pkts": _safe_int(raw.get("orig_pkts")),
            "resp_pkts": _safe_int(raw.get("resp_pkts")),
            "orig_ip_bytes": _safe_int(raw.get("orig_ip_bytes")),
            "resp_ip_bytes": _safe_int(raw.get("resp_ip_bytes")),
        },
    )


def normalize_zeek_dns(raw: dict[str, Any]) -> ArgusEvent:
    """Normalize a Zeek dns.log record into an ARGUS event.

    Maps Zeek DNS fields to the unified schema, with DNS-specific
    information stored in metadata.
    """
    timestamp = raw.get("ts")
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif not isinstance(timestamp, datetime):
        timestamp = datetime.now(timezone.utc)

    return ArgusEvent(
        timestamp=timestamp,
        source="zeek",
        event_type="dns",
        source_ip=raw.get("id.orig_h"),
        source_port=_safe_int(raw.get("id.orig_p")),
        destination_ip=raw.get("id.resp_h"),
        destination_port=_safe_int(raw.get("id.resp_p")),
        protocol=_safe_lower(raw.get("proto")),
        service="dns",
        duration=_safe_float(raw.get("rtt")),
        source_bytes=None,
        destination_bytes=None,
        connection_state=None,
        attack_type=None,
        severity=None,
        raw_event=raw,
        metadata={
            "zeek_uid": raw.get("uid"),
            "zeek_log_type": "dns",
            "query": raw.get("query"),
            "qtype_name": raw.get("qtype_name"),
            "qclass_name": raw.get("qclass_name"),
            "rcode_name": raw.get("rcode_name"),
            "answers": raw.get("answers"),
            "trans_id": raw.get("trans_id"),
            "AA": raw.get("AA"),
            "TC": raw.get("TC"),
            "RD": raw.get("RD"),
            "RA": raw.get("RA"),
            "rejected": raw.get("rejected"),
        },
    )


def normalize_zeek_event(raw: dict[str, Any], log_type: str) -> ArgusEvent:
    """Normalize any Zeek log record based on its log type.

    Routes to the appropriate normalizer. Falls back to a generic
    normalizer for unsupported log types.
    """
    normalizers = {
        "conn": normalize_zeek_conn,
        "dns": normalize_zeek_dns,
    }

    normalizer = normalizers.get(log_type)
    if normalizer:
        return normalizer(raw)

    # Generic fallback for unsupported Zeek log types
    logger.warning("No specific normalizer for Zeek log type '%s', using generic", log_type)
    return _normalize_zeek_generic(raw, log_type)


def _normalize_zeek_generic(raw: dict[str, Any], log_type: str) -> ArgusEvent:
    """Generic normalizer for Zeek log types without a specific handler."""
    timestamp = raw.get("ts")
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif not isinstance(timestamp, datetime):
        timestamp = datetime.now(timezone.utc)

    return ArgusEvent(
        timestamp=timestamp,
        source="zeek",
        event_type=log_type,
        source_ip=raw.get("id.orig_h"),
        source_port=_safe_int(raw.get("id.orig_p")),
        destination_ip=raw.get("id.resp_h"),
        destination_port=_safe_int(raw.get("id.resp_p")),
        protocol=_safe_lower(raw.get("proto")),
        service=None,
        raw_event=raw,
        metadata={"zeek_uid": raw.get("uid"), "zeek_log_type": log_type},
    )


def normalize_suricata_event(raw: dict[str, Any]) -> ArgusEvent:
    """Normalize a Suricata EVE JSON event into an ARGUS event.

    Handles multiple Suricata event types:
    - alert: maps alert.signature, alert.category, alert.severity
    - dns: maps DNS query/response info into metadata
    - flow: maps flow byte/packet counters
    - other: generic mapping of network 5-tuple

    The complete raw event is always preserved in raw_event.
    """
    # Parse timestamp
    timestamp = _parse_suricata_timestamp(raw.get("timestamp"))

    event_type = raw.get("event_type", "unknown")

    # Network 5-tuple (common to most Suricata events)
    source_ip = raw.get("src_ip")
    source_port = _safe_int(raw.get("src_port"))
    destination_ip = raw.get("dest_ip")
    destination_port = _safe_int(raw.get("dest_port"))
    protocol = _safe_lower(raw.get("proto"))

    # Defaults
    service = raw.get("app_proto")
    duration = None
    source_bytes = None
    destination_bytes = None
    connection_state = None
    attack_type = None
    severity = None
    metadata: dict[str, Any] = {
        "suricata_event_type": event_type,
        "flow_id": raw.get("flow_id"),
    }

    # Event-type-specific extraction
    if event_type == "alert":
        alert_data = raw.get("alert", {})
        attack_type = alert_data.get("signature")
        severity = _map_suricata_severity(alert_data.get("severity"))
        metadata["alert_signature"] = alert_data.get("signature")
        metadata["alert_signature_id"] = alert_data.get("signature_id")
        metadata["alert_category"] = alert_data.get("category")
        metadata["alert_severity"] = alert_data.get("severity")
        metadata["alert_action"] = alert_data.get("action")

    elif event_type == "dns":
        service = "dns"
        dns_data = raw.get("dns", {})
        metadata["dns_type"] = dns_data.get("type")
        metadata["dns_id"] = dns_data.get("id")
        metadata["dns_rcode"] = dns_data.get("rcode")

        # Extract queries
        queries = dns_data.get("queries", [])
        if queries:
            metadata["dns_query"] = queries[0].get("rrname")
            metadata["dns_qtype"] = queries[0].get("rrtype")

        # Extract answers
        answers = dns_data.get("answers", [])
        if answers:
            metadata["dns_answers"] = [
                {"rrname": a.get("rrname"), "rrtype": a.get("rrtype"), "rdata": a.get("rdata")}
                for a in answers
            ]

    elif event_type == "flow":
        flow_data = raw.get("flow", {})
        source_bytes = _safe_int(flow_data.get("bytes_toserver"))
        destination_bytes = _safe_int(flow_data.get("bytes_toclient"))
        connection_state = flow_data.get("state")
        service = raw.get("app_proto")

        # Calculate duration from start/end timestamps
        flow_start = _parse_suricata_timestamp(flow_data.get("start"))
        flow_end = _parse_suricata_timestamp(flow_data.get("end"))
        if flow_start and flow_end:
            duration = (flow_end - flow_start).total_seconds()

        metadata["flow_pkts_toserver"] = flow_data.get("pkts_toserver")
        metadata["flow_pkts_toclient"] = flow_data.get("pkts_toclient")
        metadata["flow_state"] = flow_data.get("state")
        metadata["flow_reason"] = flow_data.get("reason")
        metadata["flow_alerted"] = flow_data.get("alerted")

    return ArgusEvent(
        timestamp=timestamp,
        source="suricata",
        event_type=event_type,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        service=service,
        duration=duration,
        source_bytes=source_bytes,
        destination_bytes=destination_bytes,
        connection_state=connection_state,
        attack_type=attack_type,
        severity=severity,
        raw_event=raw,
        metadata=metadata,
    )


# --- Helper Functions ---


def _safe_int(value: Any) -> int | None:
    """Safely convert a value to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _safe_float(value: Any) -> float | None:
    """Safely convert a value to float, returning None on failure."""
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _safe_lower(value: Any) -> str | None:
    """Safely lowercase a string value, returning None on failure."""
    if value is None:
        return None
    return str(value).lower()


def _parse_suricata_timestamp(ts_str: str | None) -> datetime:
    """Parse a Suricata ISO 8601 timestamp into a UTC datetime.

    Suricata format: 2025-12-21T18:11:58.249612+0000
    """
    if ts_str is None:
        return datetime.now(timezone.utc)

    try:
        # Handle Suricata's timezone format (+0000 vs +00:00)
        # Python 3.7+ fromisoformat needs colon in offset for some versions
        ts_clean = ts_str.strip()
        if ts_clean.endswith("+0000") or ts_clean.endswith("-0000"):
            ts_clean = ts_clean[:-5] + "+00:00"
        elif len(ts_clean) > 5 and ts_clean[-5] in "+-" and ts_clean[-4:].isdigit():
            # Convert +0530 to +05:30
            ts_clean = ts_clean[:-2] + ":" + ts_clean[-2:]

        return datetime.fromisoformat(ts_clean).astimezone(timezone.utc)
    except (ValueError, TypeError) as e:
        logger.warning("Failed to parse Suricata timestamp '%s': %s", ts_str, e)
        return datetime.now(timezone.utc)


def _map_suricata_severity(suricata_severity: int | None) -> int | None:
    """Map Suricata alert severity (1-3) to ARGUS severity (0-100).

    Suricata severity: 1 = high, 2 = medium, 3 = low
    ARGUS severity: 0-100 scale
    """
    if suricata_severity is None:
        return None

    mapping = {
        1: 90,  # High
        2: 60,  # Medium
        3: 30,  # Low
    }
    return mapping.get(suricata_severity, 50)
