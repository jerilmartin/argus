"""Tests for the normalization service."""

from datetime import datetime, timezone

from argus.schemas import ArgusEvent
from argus.services.normalization import (
    normalize_suricata_event,
    normalize_zeek_conn,
    normalize_zeek_dns,
    normalize_zeek_event,
)


class TestZeekConnNormalization:
    """Test Zeek conn.log → ARGUS event normalization."""

    SAMPLE_CONN = {
        "ts": datetime(2026, 8, 12, 16, 58, 10, tzinfo=timezone.utc),
        "uid": "C6Mykp2apaOt6P0z2e",
        "id.orig_h": "2001:db8:12::2",
        "id.orig_p": 54993,
        "id.resp_h": "2001:db8:12::1",
        "id.resp_p": 53,
        "proto": "udp",
        "service": "dns",
        "duration": 0.000963,
        "orig_bytes": 28,
        "resp_bytes": 56,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": True,
        "missed_bytes": 0,
        "history": "Dd",
        "orig_pkts": 1,
        "orig_ip_bytes": 76,
        "resp_pkts": 1,
        "resp_ip_bytes": 104,
    }

    def test_source_is_zeek(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.source == "zeek"

    def test_event_type_is_connection(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.event_type == "connection"

    def test_ip_mapping(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.source_ip == "2001:db8:12::2"
        assert event.destination_ip == "2001:db8:12::1"

    def test_port_mapping(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.source_port == 54993
        assert event.destination_port == 53

    def test_protocol_lowercase(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.protocol == "udp"

    def test_duration(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert abs(event.duration - 0.000963) < 1e-6

    def test_bytes(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.source_bytes == 28
        assert event.destination_bytes == 56

    def test_connection_state(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.connection_state == "SF"

    def test_attack_type_is_none(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.attack_type is None

    def test_severity_is_none(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.severity is None

    def test_raw_event_preserved(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.raw_event is not None
        assert event.raw_event["uid"] == "C6Mykp2apaOt6P0z2e"

    def test_metadata_has_zeek_uid(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.metadata["zeek_uid"] == "C6Mykp2apaOt6P0z2e"

    def test_event_id_generated(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert event.event_id is not None
        assert len(event.event_id) == 36  # UUID format

    def test_returns_argus_event(self):
        event = normalize_zeek_conn(self.SAMPLE_CONN)
        assert isinstance(event, ArgusEvent)

    def test_missing_duration_is_none(self):
        data = {**self.SAMPLE_CONN, "duration": None}
        event = normalize_zeek_conn(data)
        assert event.duration is None

    def test_missing_bytes_is_none(self):
        data = {**self.SAMPLE_CONN, "orig_bytes": None, "resp_bytes": None}
        event = normalize_zeek_conn(data)
        assert event.source_bytes is None
        assert event.destination_bytes is None


class TestZeekDnsNormalization:
    """Test Zeek dns.log → ARGUS event normalization."""

    SAMPLE_DNS = {
        "ts": datetime(2026, 8, 12, 16, 58, 10, tzinfo=timezone.utc),
        "uid": "C6Mykp2apaOt6P0z2e",
        "id.orig_h": "2001:db8:12::2",
        "id.orig_p": 54993,
        "id.resp_h": "2001:db8:12::1",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": 2947,
        "rtt": 0.000963,
        "query": "netcamp.ch",
        "qtype_name": "AAAA",
        "qclass_name": "C_INTERNET",
        "rcode_name": "NOERROR",
        "AA": True,
        "TC": False,
        "RD": True,
        "RA": True,
        "answers": ["2a00:1128:0:149::100"],
        "rejected": False,
    }

    def test_event_type_is_dns(self):
        event = normalize_zeek_dns(self.SAMPLE_DNS)
        assert event.event_type == "dns"

    def test_service_is_dns(self):
        event = normalize_zeek_dns(self.SAMPLE_DNS)
        assert event.service == "dns"

    def test_metadata_has_query(self):
        event = normalize_zeek_dns(self.SAMPLE_DNS)
        assert event.metadata["query"] == "netcamp.ch"

    def test_metadata_has_qtype(self):
        event = normalize_zeek_dns(self.SAMPLE_DNS)
        assert event.metadata["qtype_name"] == "AAAA"


class TestZeekEventRouter:
    """Test the normalize_zeek_event router function."""

    def test_routes_to_conn(self):
        data = TestZeekConnNormalization.SAMPLE_CONN
        event = normalize_zeek_event(data, "conn")
        assert event.event_type == "connection"

    def test_routes_to_dns(self):
        data = TestZeekDnsNormalization.SAMPLE_DNS
        event = normalize_zeek_event(data, "dns")
        assert event.event_type == "dns"

    def test_unknown_type_uses_generic(self):
        data = {
            "ts": 1766340718.0,
            "uid": "Ctest",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 1234,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 5678,
            "proto": "tcp",
        }
        event = normalize_zeek_event(data, "weird")
        assert event.event_type == "weird"
        assert event.source == "zeek"


class TestSuricataNormalization:
    """Test Suricata EVE → ARGUS event normalization."""

    SAMPLE_DNS = {
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

    SAMPLE_FLOW = {
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

    SAMPLE_ALERT = {
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

    def test_dns_source_is_suricata(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.source == "suricata"

    def test_dns_event_type(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.event_type == "dns"

    def test_dns_ip_mapping(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.source_ip == "2001:0db8:0012:0000:0000:0000:0000:0002"
        assert event.destination_ip == "2001:0db8:0012:0000:0000:0000:0000:0001"

    def test_dns_protocol_lowercase(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.protocol == "udp"

    def test_dns_metadata_has_query(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.metadata["dns_query"] == "netcamp.ch"

    def test_flow_bytes(self):
        event = normalize_suricata_event(self.SAMPLE_FLOW)
        assert event.source_bytes == 90
        assert event.destination_bytes == 118

    def test_flow_state(self):
        event = normalize_suricata_event(self.SAMPLE_FLOW)
        assert event.connection_state == "established"

    def test_flow_service(self):
        event = normalize_suricata_event(self.SAMPLE_FLOW)
        assert event.service == "dns"

    def test_alert_attack_type(self):
        event = normalize_suricata_event(self.SAMPLE_ALERT)
        assert event.attack_type == "ET MALWARE Known Trojan"

    def test_alert_severity_mapped(self):
        event = normalize_suricata_event(self.SAMPLE_ALERT)
        # Suricata severity 1 (high) → ARGUS 90
        assert event.severity == 90

    def test_alert_metadata(self):
        event = normalize_suricata_event(self.SAMPLE_ALERT)
        assert event.metadata["alert_category"] == "Malware"
        assert event.metadata["alert_signature_id"] == 2001

    def test_raw_event_preserved(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.raw_event is not None
        assert event.raw_event["flow_id"] == 1916503659958416

    def test_no_attack_type_for_non_alerts(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.attack_type is None

    def test_no_severity_for_non_alerts(self):
        event = normalize_suricata_event(self.SAMPLE_DNS)
        assert event.severity is None
