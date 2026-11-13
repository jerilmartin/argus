"""Tests for the Suricata EVE JSON parser."""

import json
import tempfile
from pathlib import Path

import pytest

from argus.parsers.suricata_parser import SuricataEveParser


# --- Sample events ---

DNS_REQUEST = {
    "timestamp": "2025-12-21T18:11:58.249612+0000",
    "flow_id": 1916503659958416,
    "event_type": "dns",
    "src_ip": "2001:0db8:0012:0000:0000:0000:0000:0002",
    "src_port": 54993,
    "dest_ip": "2001:0db8:0012:0000:0000:0000:0000:0001",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
        "type": "request",
        "id": 2947,
        "queries": [{"rrname": "netcamp.ch", "rrtype": "AAAA"}],
    },
}

FLOW_EVENT = {
    "timestamp": "2025-12-21T18:11:58.249612+0000",
    "flow_id": 1916503659958416,
    "event_type": "flow",
    "src_ip": "2001:0db8:0012:0000:0000:0000:0000:0002",
    "src_port": 54993,
    "dest_ip": "2001:0db8:0012:0000:0000:0000:0000:0001",
    "dest_port": 53,
    "proto": "UDP",
    "app_proto": "dns",
    "flow": {
        "pkts_toserver": 1,
        "pkts_toclient": 1,
        "bytes_toserver": 90,
        "bytes_toclient": 118,
        "start": "2025-12-21T18:11:58.249612+0000",
        "end": "2025-12-21T18:11:58.250575+0000",
        "state": "established",
        "reason": "shutdown",
        "alerted": False,
    },
}

ALERT_EVENT = {
    "timestamp": "2025-12-21T18:11:58.249612+0000",
    "event_type": "alert",
    "src_ip": "192.168.1.100",
    "src_port": 12345,
    "dest_ip": "10.0.0.1",
    "dest_port": 80,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "signature_id": 2001,
        "signature": "ET MALWARE Known Trojan",
        "category": "Malware",
        "severity": 1,
    },
}

STATS_EVENT = {
    "timestamp": "2026-08-16T13:13:32.516649+0000",
    "event_type": "stats",
    "stats": {"uptime": 0, "decoder": {"pkts": 2}},
}


def _write_eve_file(events: list[dict]) -> Path:
    """Write events as JSON Lines to a temp file."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    for event in events:
        tmp.write(json.dumps(event) + "\n")
    tmp.close()
    return Path(tmp.name)


class TestSuricataParserBasic:
    """Test basic JSON parsing."""

    def test_parse_single_dns(self):
        parser = SuricataEveParser()
        filepath = _write_eve_file([DNS_REQUEST])
        events = list(parser.parse_file(filepath))
        assert len(events) == 1
        assert events[0]["event_type"] == "dns"

    def test_parse_multiple_events(self):
        parser = SuricataEveParser()
        filepath = _write_eve_file([DNS_REQUEST, FLOW_EVENT])
        events = list(parser.parse_file(filepath))
        assert len(events) == 2

    def test_parse_flow_event(self):
        parser = SuricataEveParser()
        filepath = _write_eve_file([FLOW_EVENT])
        events = list(parser.parse_file(filepath))
        assert len(events) == 1
        assert events[0]["event_type"] == "flow"
        assert events[0]["flow"]["bytes_toserver"] == 90


class TestSuricataParserAlerts:
    """Test alert event parsing."""

    def test_alert_fields(self):
        parser = SuricataEveParser()
        filepath = _write_eve_file([ALERT_EVENT])
        events = list(parser.parse_file(filepath))
        assert len(events) == 1
        event = events[0]
        assert event["event_type"] == "alert"
        assert event["alert"]["signature"] == "ET MALWARE Known Trojan"
        assert event["alert"]["severity"] == 1
        assert event["src_ip"] == "192.168.1.100"


class TestSuricataParserFiltering:
    """Test that stats events are skipped."""

    def test_stats_skipped(self):
        parser = SuricataEveParser()
        filepath = _write_eve_file([DNS_REQUEST, STATS_EVENT, FLOW_EVENT])
        events = list(parser.parse_file(filepath))
        # Stats should be filtered out
        assert len(events) == 2
        event_types = [e["event_type"] for e in events]
        assert "stats" not in event_types


class TestSuricataParserMalformed:
    """Test handling of malformed input."""

    def test_blank_lines_skipped(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        tmp.write(json.dumps(DNS_REQUEST) + "\n")
        tmp.write("\n")  # blank line
        tmp.write("   \n")  # whitespace-only line
        tmp.write(json.dumps(FLOW_EVENT) + "\n")
        tmp.close()

        parser = SuricataEveParser()
        events = list(parser.parse_file(Path(tmp.name)))
        assert len(events) == 2

    def test_malformed_json_skipped(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        tmp.write(json.dumps(DNS_REQUEST) + "\n")
        tmp.write("{invalid json\n")
        tmp.write(json.dumps(FLOW_EVENT) + "\n")
        tmp.close()

        parser = SuricataEveParser()
        events = list(parser.parse_file(Path(tmp.name)))
        assert len(events) == 2

    def test_file_not_found(self):
        parser = SuricataEveParser()
        with pytest.raises(FileNotFoundError):
            list(parser.parse_file("/nonexistent/path/eve.json"))

    def test_empty_file(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        tmp.close()

        parser = SuricataEveParser()
        events = list(parser.parse_file(Path(tmp.name)))
        assert events == []
