"""Tests for the Zeek log parser."""

import tempfile
from pathlib import Path

import pytest

from argus.parsers.zeek_parser import ZeekLogParser


# --- Sample log content ---

CONN_LOG = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-08-12-16-58-10
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tip_proto
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tcount
1766340718.249612\tC6Mykp2apaOt6P0z2e\t2001:db8:12::2\t54993\t2001:db8:12::1\t53\tudp\tdns\t0.000963\t28\t56\tSF\tT\tT\t0\tDd\t1\t76\t1\t104\t-\t17
#close\t2026-08-12-16-58-10
"""

DNS_LOG = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#open\t2026-08-12-16-58-10
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\topcode\topcode_name
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool\tcount\tstring
1766340718.249612\tC6Mykp2apaOt6P0z2e\t2001:db8:12::2\t54993\t2001:db8:12::1\t53\tudp\t2947\t0.000963\tnetcamp.ch\t1\tC_INTERNET\t28\tAAAA\t0\tNOERROR\tT\tF\tT\tT\t0\t2a00:1128:0:149::100\t0.000000\tF\t0\tquery
#close\t2026-08-12-16-58-10
"""

CONN_LOG_MULTI = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-08-12-16-58-10
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tip_proto
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tcount
1766340718.249612\tC6Mykp2apaOt6P0z2e\t192.168.1.100\t54993\t10.0.0.1\t53\tudp\tdns\t0.000963\t28\t56\tSF\tT\tT\t0\tDd\t1\t76\t1\t104\t-\t17
1766340720.123456\tC7Abcd3efgh4\t192.168.1.200\t12345\t10.0.0.2\t80\ttcp\thttp\t1.234567\t1024\t2048\tSF\tT\tF\t0\tShADadfF\t10\t1500\t8\t2500\t-\t6
1766340722.654321\tC8Xyz9ijk0lm\t10.0.0.5\t33333\t172.16.0.1\t443\ttcp\tssl\t-\t-\t-\tS0\tF\tF\t0\tS\t1\t60\t0\t0\t-\t6
#close\t2026-08-12-16-58-10
"""


def _write_temp_log(content: str) -> Path:
    """Write log content to a temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


class TestZeekParserHeaders:
    """Test header parsing."""

    def test_detects_separator(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        list(parser.parse_file(filepath))
        assert parser.separator == "\t"

    def test_detects_fields(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        list(parser.parse_file(filepath))
        assert "ts" in parser.fields
        assert "id.orig_h" in parser.fields
        assert "conn_state" in parser.fields

    def test_detects_types(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        list(parser.parse_file(filepath))
        assert "time" in parser.types
        assert "addr" in parser.types

    def test_detects_path(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        list(parser.parse_file(filepath))
        assert parser.get_log_type() == "conn"

    def test_dns_path(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(DNS_LOG)
        list(parser.parse_file(filepath))
        assert parser.get_log_type() == "dns"


class TestZeekParserFields:
    """Test field parsing and type conversion."""

    def test_conn_record_count(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert len(records) == 1

    def test_conn_multi_records(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG_MULTI)
        records = list(parser.parse_file(filepath))
        assert len(records) == 3

    def test_timestamp_conversion(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        ts = records[0]["ts"]
        from datetime import datetime
        assert isinstance(ts, datetime)

    def test_port_is_int(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert isinstance(records[0]["id.orig_p"], int)
        assert records[0]["id.orig_p"] == 54993

    def test_duration_is_float(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert isinstance(records[0]["duration"], float)
        assert abs(records[0]["duration"] - 0.000963) < 1e-6

    def test_bytes_are_int(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert records[0]["orig_bytes"] == 28
        assert records[0]["resp_bytes"] == 56

    def test_bool_conversion(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert records[0]["local_orig"] is True

    def test_ipv6_address(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert records[0]["id.orig_h"] == "2001:db8:12::2"

    def test_ipv4_address(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG_MULTI)
        records = list(parser.parse_file(filepath))
        assert records[0]["id.orig_h"] == "192.168.1.100"

    def test_unset_becomes_none(self):
        """Zeek '-' unset values should become None."""
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG_MULTI)
        records = list(parser.parse_file(filepath))
        # Third record has duration=- and bytes=-
        assert records[2]["duration"] is None
        assert records[2]["orig_bytes"] is None
        assert records[2]["resp_bytes"] is None

    def test_set_type_with_unset(self):
        """set[string] with '-' should become None."""
        parser = ZeekLogParser()
        filepath = _write_temp_log(CONN_LOG)
        records = list(parser.parse_file(filepath))
        assert records[0]["tunnel_parents"] is None

    def test_dns_query_field(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log(DNS_LOG)
        records = list(parser.parse_file(filepath))
        assert records[0]["query"] == "netcamp.ch"
        assert records[0]["qtype_name"] == "AAAA"
        assert records[0]["rcode_name"] == "NOERROR"


class TestZeekParserEdgeCases:
    """Test error handling and edge cases."""

    def test_file_not_found(self):
        parser = ZeekLogParser()
        with pytest.raises(FileNotFoundError):
            list(parser.parse_file("/nonexistent/path/conn.log"))

    def test_empty_file(self):
        parser = ZeekLogParser()
        filepath = _write_temp_log("")
        records = list(parser.parse_file(filepath))
        assert records == []

    def test_headers_only(self):
        content = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid
#types\ttime\tstring
#close\t2026-08-12-16-58-10
"""
        parser = ZeekLogParser()
        filepath = _write_temp_log(content)
        records = list(parser.parse_file(filepath))
        assert records == []
