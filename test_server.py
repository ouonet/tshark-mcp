"""
Unit tests for TShark MCP Server.

All tests mock server._run so they work without tshark installed.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

import server
from server import (
    analyze_pcap_file,
    capture_and_decrypt,
    capture_live,
    capture_process,
    follow_tls_stream,
    export_to_json,
    extract_fields,
    extract_packet_details,
    filter_and_save,
    follow_stream,
    get_conversations,
    get_packet_statistics,
    list_interfaces,
    list_processes,
    run_tshark_command,
    _get_process_connections,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(stdout="output", stderr=""):
    r = MagicMock()
    r.returncode = 0
    r.stdout = stdout
    r.stderr = stderr
    return r


def _err(stderr="some error", returncode=1):
    r = MagicMock()
    r.returncode = returncode
    r.stdout = ""
    r.stderr = stderr
    return r


PATCH = "server._run"


# ---------------------------------------------------------------------------
# _TSHARK path and _NOT_FOUND_MSG
# ---------------------------------------------------------------------------

class TestTsharkPath:
    def test_default_path_is_tshark(self):
        # When TSHARK_PATH env var is not set, default should be "tshark"
        # (module-level value already resolved; just assert it's a non-empty string)
        assert server._TSHARK  # truthy

    def test_not_found_msg_contains_path(self):
        assert server._TSHARK in server._NOT_FOUND_MSG

    def test_not_found_msg_mentions_env_var(self):
        assert "TSHARK_PATH" in server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_list_interfaces_returns_not_found_msg(self, mock_run):
        result = list_interfaces()
        assert result == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_run_tshark_command_returns_not_found_msg(self, mock_run):
        result = run_tshark_command("-D")
        assert result == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_analyze_pcap_file_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert analyze_pcap_file(str(pcap)) == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_get_packet_statistics_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert get_packet_statistics(str(pcap)) == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_extract_packet_details_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert extract_packet_details(str(pcap), 1) == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_extract_fields_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert extract_fields(str(pcap), "ip.src") == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_export_to_json_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert export_to_json(str(pcap)) == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_get_conversations_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert get_conversations(str(pcap)) == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_follow_stream_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert follow_stream(str(pcap), "tcp") == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_capture_live_returns_not_found_msg(self, mock_run):
        assert capture_live("eth0") == server._NOT_FOUND_MSG

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_filter_and_save_returns_not_found_msg(self, mock_run, tmp_path):
        pcap = tmp_path / "in.pcap"
        pcap.touch()
        assert filter_and_save(str(pcap), str(tmp_path / "out.pcap"), "tcp") == server._NOT_FOUND_MSG


# ---------------------------------------------------------------------------
# run_tshark_command
# ---------------------------------------------------------------------------

class TestRunTsharkCommand:
    @patch(PATCH, return_value=_ok("hello"))
    def test_basic(self, mock_run):
        result = run_tshark_command("-D")
        mock_run.assert_called_once_with("-D", timeout=30)
        assert result == "hello"

    @patch(PATCH, return_value=_ok("output"))
    def test_quoted_args_parsed_correctly(self, mock_run):
        run_tshark_command('-r file.pcap -Y "http.request"')
        mock_run.assert_called_once_with("-r", "file.pcap", "-Y", "http.request", timeout=30)

    @patch(PATCH, return_value=_err("bad option"))
    def test_nonzero_returncode_returns_error(self, mock_run):
        result = run_tshark_command("--invalid")
        assert "Error:" in result and "bad option" in result

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 30))
    def test_timeout(self, mock_run):
        assert "timed out" in run_tshark_command("-D")

    @patch("server.os.name", "nt")
    @patch(PATCH, return_value=_ok("ok"))
    def test_windows_path_preserved(self, mock_run):
        run_tshark_command('-r "C:\\captures\\a.pcap" -Y "http.request"')
        mock_run.assert_called_once_with("-r", "C:\\captures\\a.pcap", "-Y", "http.request", timeout=30)


# ---------------------------------------------------------------------------
# analyze_pcap_file
# ---------------------------------------------------------------------------

class TestAnalyzePcapFile:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in analyze_pcap_file(str(tmp_path / "missing.pcap"))

    @patch(PATCH, return_value=_ok("1 packet"))
    def test_no_filter(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = analyze_pcap_file(str(pcap))
        args = mock_run.call_args[0]
        assert "-r" in args and "-Y" not in args and "-c" in args
        assert result == "1 packet"

    @patch(PATCH, return_value=_ok("filtered"))
    def test_with_filter(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        analyze_pcap_file(str(pcap), display_filter="tcp")
        args = mock_run.call_args[0]
        assert "-Y" in args and "tcp" in args

    @patch(PATCH, return_value=_ok(""))
    def test_empty_output(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "No packets" in analyze_pcap_file(str(pcap))

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in analyze_pcap_file(str(pcap))


# ---------------------------------------------------------------------------
# get_packet_statistics
# ---------------------------------------------------------------------------

class TestGetPacketStatistics:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in get_packet_statistics(str(tmp_path / "x.pcap"))

    @patch(PATCH, return_value=_ok("===stats==="))
    def test_success(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = get_packet_statistics(str(pcap))
        args = mock_run.call_args[0]
        assert "-z" in args and "io,phs" in args
        assert result == "===stats==="

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in get_packet_statistics(str(pcap))


# ---------------------------------------------------------------------------
# extract_packet_details
# ---------------------------------------------------------------------------

class TestExtractPacketDetails:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in extract_packet_details(str(tmp_path / "x.pcap"), 1)

    @patch(PATCH, return_value=_ok("Frame 3: ..."))
    def test_correct_filter_arg(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        extract_packet_details(str(pcap), 3)
        args = mock_run.call_args[0]
        assert "-V" in args and "-Y" in args and "frame.number == 3" in args

    @patch(PATCH, return_value=_ok(""))
    def test_packet_not_found(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "No packet found" in extract_packet_details(str(pcap), 999)

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 30))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in extract_packet_details(str(pcap), 1)


# ---------------------------------------------------------------------------
# list_interfaces
# ---------------------------------------------------------------------------

class TestListInterfaces:
    @patch(PATCH, return_value=_ok("1. eth0\n2. lo\n"))
    def test_success(self, mock_run):
        result = list_interfaces()
        mock_run.assert_called_once_with("-D", timeout=10)
        assert "eth0" in result

    @patch(PATCH, return_value=_err("permission denied"))
    def test_error(self, mock_run):
        assert "Error:" in list_interfaces()

    @patch(PATCH, side_effect=Exception("unexpected"))
    def test_generic_exception(self, mock_run):
        assert "Error:" in list_interfaces()


# ---------------------------------------------------------------------------
# extract_fields
# ---------------------------------------------------------------------------

class TestExtractFields:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in extract_fields(str(tmp_path / "x.pcap"), "ip.src")

    @patch(PATCH, return_value=_ok("192.168.1.1\n"))
    def test_single_field(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = extract_fields(str(pcap), "ip.src")
        args = mock_run.call_args[0]
        assert "-T" in args and "fields" in args and "-e" in args and "ip.src" in args
        assert result == "192.168.1.1\n"

    @patch(PATCH, return_value=_ok("1.1.1.1\t2.2.2.2\n"))
    def test_multiple_fields(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        extract_fields(str(pcap), "ip.src, ip.dst")
        args = mock_run.call_args[0]
        assert list(args).count("-e") == 2
        assert "ip.src" in args and "ip.dst" in args

    @patch(PATCH, return_value=_ok("x\n"))
    def test_with_display_filter(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        extract_fields(str(pcap), "ip.src", display_filter="tcp")
        args = mock_run.call_args[0]
        assert "-Y" in args and "tcp" in args

    @patch(PATCH, return_value=_ok(""))
    def test_empty_result(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "No matching" in extract_fields(str(pcap), "ip.src")

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in extract_fields(str(pcap), "ip.src")


# ---------------------------------------------------------------------------
# export_to_json
# ---------------------------------------------------------------------------

class TestExportToJson:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in export_to_json(str(tmp_path / "x.pcap"))

    @patch(PATCH, return_value=_ok("[{}]"))
    def test_default_args(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = export_to_json(str(pcap))
        args = mock_run.call_args[0]
        assert "-T" in args and "json" in args and "-c" in args and "50" in args
        assert result == "[{}]"

    @patch(PATCH, return_value=_ok("[{}]"))
    def test_custom_max_packets(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        export_to_json(str(pcap), max_packets=10)
        assert "10" in mock_run.call_args[0]

    @patch(PATCH, return_value=_ok("[{}]"))
    def test_with_filter(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        export_to_json(str(pcap), display_filter="udp")
        args = mock_run.call_args[0]
        assert "-Y" in args and "udp" in args

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in export_to_json(str(pcap))


# ---------------------------------------------------------------------------
# get_conversations
# ---------------------------------------------------------------------------

class TestGetConversations:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in get_conversations(str(tmp_path / "x.pcap"))

    def test_invalid_protocol(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = get_conversations(str(pcap), protocol="ftp")
        assert "Error:" in result and "protocol" in result.lower()

    @pytest.mark.parametrize("proto", ["eth", "ip", "tcp", "udp", "sctp"])
    @patch(PATCH, return_value=_ok("conv stats"))
    def test_valid_protocols(self, mock_run, proto, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = get_conversations(str(pcap), protocol=proto)
        assert f"conv,{proto}" in mock_run.call_args[0]
        assert result == "conv stats"

    @patch(PATCH, return_value=_ok(""))
    def test_empty_result(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "No conversations" in get_conversations(str(pcap))

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in get_conversations(str(pcap))


# ---------------------------------------------------------------------------
# follow_stream
# ---------------------------------------------------------------------------

class TestFollowStream:
    def test_file_not_found(self, tmp_path):
        assert "does not exist" in follow_stream(str(tmp_path / "x.pcap"), "tcp")

    def test_invalid_protocol(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = follow_stream(str(pcap), "ftp")
        assert "Error:" in result and ("tcp" in result or "udp" in result or "sctp" in result)

    @pytest.mark.parametrize("proto", ["tcp", "udp", "sctp"])
    @patch(PATCH, return_value=_ok("stream data"))
    def test_valid_protocols(self, mock_run, proto, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = follow_stream(str(pcap), proto, stream_index=2)
        assert f"follow,{proto},ascii,2" in mock_run.call_args[0]
        assert result == "stream data"

    @patch(PATCH, return_value=_ok(""))
    def test_stream_not_found(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "No stream" in follow_stream(str(pcap), "tcp", stream_index=99)

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        assert "timed out" in follow_stream(str(pcap), "tcp")


# ---------------------------------------------------------------------------
# capture_live
# ---------------------------------------------------------------------------

class TestCaptureLive:
    @patch(PATCH, return_value=_ok("packet data"))
    def test_basic(self, mock_run):
        result = capture_live("eth0")
        args = mock_run.call_args[0]
        assert "-i" in args and "eth0" in args and "-c" in args and "50" in args
        assert result == "packet data"

    @patch(PATCH, return_value=_ok("x"))
    def test_packet_count_capped_at_500(self, mock_run):
        capture_live("eth0", packet_count=9999)
        assert "500" in mock_run.call_args[0]

    @patch(PATCH, return_value=_ok("x"))
    def test_duration_capped_at_60(self, mock_run):
        capture_live("eth0", duration=3600)
        assert "duration:60" in mock_run.call_args[0]

    @patch(PATCH, return_value=_ok("x"))
    def test_with_filter(self, mock_run):
        capture_live("eth0", display_filter="icmp")
        args = mock_run.call_args[0]
        assert "-Y" in args and "icmp" in args

    @patch(PATCH, return_value=_ok(""))
    def test_no_packets_captured(self, mock_run):
        assert "No packets" in capture_live("eth0")

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 15))
    def test_timeout(self, mock_run):
        assert "timed out" in capture_live("eth0")


# ---------------------------------------------------------------------------
# filter_and_save
# ---------------------------------------------------------------------------

class TestFilterAndSave:
    def test_input_file_not_found(self, tmp_path):
        assert "does not exist" in filter_and_save(
            str(tmp_path / "missing.pcap"),
            str(tmp_path / "out.pcap"),
            "tcp"
        )

    @patch(PATCH)
    def test_success(self, mock_run, tmp_path):
        pcap = tmp_path / "in.pcap"
        pcap.touch()
        out = tmp_path / "out.pcap"
        mock_run.side_effect = [_ok(""), _ok("", stderr="10 packets")]
        result = filter_and_save(str(pcap), str(out), "tcp")
        assert "Saved to" in result and str(out) in result
        first_args = mock_run.call_args_list[0][0]
        assert "-w" in first_args and "-Y" in first_args and "tcp" in first_args

    @patch(PATCH, return_value=_err("write failed"))
    def test_write_error(self, mock_run, tmp_path):
        pcap = tmp_path / "in.pcap"
        pcap.touch()
        assert "Error:" in filter_and_save(str(pcap), str(tmp_path / "out.pcap"), "tcp")

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "in.pcap"
        pcap.touch()
        assert "timed out" in filter_and_save(str(pcap), str(tmp_path / "out.pcap"), "tcp")


# ---------------------------------------------------------------------------
# TLS keylog_file parameter (analyze_pcap_file, extract_fields, export_to_json,
# follow_stream)
# ---------------------------------------------------------------------------

class TestTlsKeylogParam:
    """Verify that keylog_file is wired up correctly in each tool."""

    @patch(PATCH, return_value=_ok("output"))
    def test_analyze_pcap_passes_keylog(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        analyze_pcap_file(str(pcap), keylog_file=str(keys))
        args = mock_run.call_args[0]
        assert "-o" in args
        assert any(f"tls.keylog_file:{keys}" in a for a in args)

    def test_analyze_pcap_keylog_not_found(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = analyze_pcap_file(str(pcap), keylog_file=str(tmp_path / "missing.log"))
        assert "Error:" in result and "missing.log" in result

    @patch(PATCH, return_value=_ok("fields"))
    def test_extract_fields_passes_keylog(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        extract_fields(str(pcap), "http.request.uri", keylog_file=str(keys))
        args = mock_run.call_args[0]
        assert any(f"tls.keylog_file:{keys}" in a for a in args)

    def test_extract_fields_keylog_not_found(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = extract_fields(str(pcap), "ip.src", keylog_file=str(tmp_path / "missing.log"))
        assert "Error:" in result

    @patch(PATCH, return_value=_ok("[{}]"))
    def test_export_to_json_passes_keylog(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        export_to_json(str(pcap), keylog_file=str(keys))
        args = mock_run.call_args[0]
        assert any(f"tls.keylog_file:{keys}" in a for a in args)

    @patch(PATCH, return_value=_ok("stream data"))
    def test_follow_stream_passes_keylog(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        follow_stream(str(pcap), "tcp", keylog_file=str(keys))
        args = mock_run.call_args[0]
        assert any(f"tls.keylog_file:{keys}" in a for a in args)


# ---------------------------------------------------------------------------
# follow_tls_stream
# ---------------------------------------------------------------------------

class TestFollowTlsStream:
    def test_pcap_not_found(self, tmp_path):
        keys = tmp_path / "keys.log"
        keys.touch()
        result = follow_tls_stream(str(tmp_path / "missing.pcap"), str(keys))
        assert "does not exist" in result

    def test_keylog_not_found(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        result = follow_tls_stream(str(pcap), str(tmp_path / "missing.log"))
        assert "does not exist" in result

    @patch(PATCH, return_value=_ok("GET / HTTP/1.1\r\nHost: example.com"))
    def test_success(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        result = follow_tls_stream(str(pcap), str(keys), stream_index=0)
        args = mock_run.call_args[0]
        assert "follow,tls,ascii,0" in args
        assert any(f"tls.keylog_file:{keys}" in a for a in args)
        assert "GET" in result

    @patch(PATCH, return_value=_ok(""))
    def test_no_stream_found(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        result = follow_tls_stream(str(pcap), str(keys), stream_index=5)
        assert "No TLS stream" in result

    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 60))
    def test_timeout(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        assert "timed out" in follow_tls_stream(str(pcap), str(keys))

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        keys = tmp_path / "keys.log"
        keys.touch()
        assert follow_tls_stream(str(pcap), str(keys)) == server._NOT_FOUND_MSG


# ---------------------------------------------------------------------------
# capture_and_decrypt
# ---------------------------------------------------------------------------

class TestCaptureAndDecrypt:
    def test_keylog_not_found(self, tmp_path):
        result = capture_and_decrypt("eth0", str(tmp_path / "missing.log"), str(tmp_path / "out.pcap"))
        assert "does not exist" in result

    @patch(PATCH)
    def test_success_with_one_tls_stream(self, mock_run, tmp_path):
        keys = tmp_path / "keys.log"
        keys.touch()
        out = tmp_path / "out.pcap"

        # calls: capture, summary, discover-indices, follow-stream-5
        stream_content = (
            "===================================================================\n"
            "Follow: tls,ascii\nFilter: tls.stream eq 5\n"
            "Node 0: 1.1.1.1:50000\nNode 1: 2.2.2.2:443\n"
            "===================================================================\n"
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        mock_run.side_effect = [
            _ok(""),                                   # capture
            _ok("1 192.168.1.1 → 1.1.1.1 TLS 100"),  # summary
            _ok("5\n5\n5\n"),                          # discover TLS stream indices
            _ok(stream_content),                       # follow stream 5
        ]
        out.touch()

        result = capture_and_decrypt("eth0", str(keys), str(out))
        assert "Capture Summary" in result
        assert "Decrypted TLS" in result
        assert "GET" in result

    @patch(PATCH)
    def test_streams_beyond_index_4_are_found(self, mock_run, tmp_path):
        """Regression: streams at index >= 5 must not be skipped."""
        keys = tmp_path / "keys.log"
        keys.touch()
        out = tmp_path / "out.pcap"

        stream_content = (
            "Node 0: 10.0.0.1:12345\nNode 1: 10.0.0.2:443\n"
            "GET /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        )
        mock_run.side_effect = [
            _ok(""),             # capture
            _ok("pkt summary"),  # summary
            _ok("7\n7\n8\n8\n"), # indices: streams 7 and 8
            _ok(stream_content), # follow stream 7
            _ok(stream_content), # follow stream 8
        ]
        out.touch()

        result = capture_and_decrypt("eth0", str(keys), str(out))
        assert "TLS Stream 7" in result
        assert "TLS Stream 8" in result

    @patch(PATCH)
    def test_empty_streams_are_skipped(self, mock_run, tmp_path):
        """Streams where Node 0: :0 (no decryptable data) must be excluded."""
        keys = tmp_path / "keys.log"
        keys.touch()
        out = tmp_path / "out.pcap"

        empty = "Follow: tls,ascii\nFilter: tls.stream eq 0\nNode 0: :0\nNode 1: :0\n"
        mock_run.side_effect = [
            _ok(""),            # capture
            _ok("pkt summary"), # summary
            _ok("0\n0\n"),      # index 0
            _ok(empty),         # follow stream 0 → empty
        ]
        out.touch()

        result = capture_and_decrypt("eth0", str(keys), str(out))
        assert "no decryptable TLS streams found" in result

    @patch(PATCH, return_value=_err("capture failed"))
    def test_capture_error(self, mock_run, tmp_path):
        keys = tmp_path / "keys.log"
        keys.touch()
        result = capture_and_decrypt("eth0", str(keys), str(tmp_path / "out.pcap"))
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        keys = tmp_path / "keys.log"
        keys.touch()
        result = capture_and_decrypt("eth0", str(keys), str(tmp_path / "out.pcap"))
        assert result == server._NOT_FOUND_MSG


# ---------------------------------------------------------------------------
# _get_process_connections
# ---------------------------------------------------------------------------

SUBPROCESS_PATCH = "server.subprocess.run"


class TestGetProcessConnections:
    """Test the port/IP discovery helper for each platform."""

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH)
    def test_windows_parses_established_tcp(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "  TCP    192.168.1.100:54321    142.250.80.14:443    ESTABLISHED    1234\n"
                "  TCP    0.0.0.0:135            0.0.0.0:0            LISTENING      500\n"
            ),
            stderr="",
        )
        ports, ips = _get_process_connections(1234)
        assert 54321 in ports
        assert "142.250.80.14" in ips
        # PID 500 row must not bleed in
        assert 135 not in ports

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH)
    def test_windows_excludes_loopback_remote(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  TCP    127.0.0.1:8080    127.0.0.1:443    ESTABLISHED    9999\n",
            stderr="",
        )
        ports, ips = _get_process_connections(9999)
        assert 8080 in ports
        # loopback remote should be excluded
        assert "127.0.0.1" not in ips

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH)
    def test_windows_no_connections(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        ports, ips = _get_process_connections(1234)
        assert ports == set()
        assert ips == set()

    @patch("server.sys.platform", "darwin")
    @patch(SUBPROCESS_PATCH)
    def test_macos_parses_lsof_output(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "python3  1234  user  TCP  10.0.0.1:55000->93.184.216.34:443 (ESTABLISHED)\n"
                "python3  1234  user  TCP  *:8080 (LISTEN)\n"
            ),
            stderr="",
        )
        ports, ips = _get_process_connections(1234)
        assert 55000 in ports
        assert 8080 in ports
        assert "93.184.216.34" in ips

    @patch("server.sys.platform", "linux")
    @patch(SUBPROCESS_PATCH)
    def test_linux_parses_ss_output(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                "ESTAB  0      0      10.0.0.2:44444     8.8.8.8:443\n"
            ),
            stderr="",
        )
        ports, ips = _get_process_connections(1234)
        assert 44444 in ports
        assert "8.8.8.8" in ips

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH, side_effect=Exception("tool missing"))
    def test_exception_returns_empty(self, mock_run):
        ports, ips = _get_process_connections(1234)
        assert ports == set()
        assert ips == set()


# ---------------------------------------------------------------------------
# list_processes
# ---------------------------------------------------------------------------

class TestListProcesses:
    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH)
    def test_windows_returns_pid_and_name(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='"chrome.exe","1234","Console","1","100,000 K"\n"notepad.exe","5678","Console","1","5,000 K"\n',
            stderr="",
        )
        result = list_processes()
        assert "1234" in result
        assert "chrome.exe" in result
        assert "5678" in result

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH)
    def test_windows_name_filter(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='"chrome.exe","1234","Console","1","100,000 K"\n"notepad.exe","5678","Console","1","5,000 K"\n',
            stderr="",
        )
        result = list_processes("chrome")
        assert "chrome" in result.lower()
        assert "notepad" not in result.lower()

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH)
    def test_windows_filter_no_match(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='"chrome.exe","1234","Console","1","100,000 K"\n',
            stderr="",
        )
        result = list_processes("zzznomatch")
        assert "No matching" in result

    @patch("server.sys.platform", "linux")
    @patch(SUBPROCESS_PATCH)
    def test_linux_returns_ps_output(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="USER  PID  ...\nroot  42  python3\n",
            stderr="",
        )
        result = list_processes()
        assert "42" in result

    @patch("server.sys.platform", "linux")
    @patch(SUBPROCESS_PATCH)
    def test_linux_name_filter(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="USER  PID  CMD\nroot  42  python3\nroot  99  sshd\n",
            stderr="",
        )
        result = list_processes("python")
        assert "python" in result
        assert "sshd" not in result

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH, side_effect=subprocess.TimeoutExpired("tasklist", 15))
    def test_timeout(self, mock_run):
        result = list_processes()
        assert "timed out" in result

    @patch("server.sys.platform", "win32")
    @patch(SUBPROCESS_PATCH, side_effect=Exception("access denied"))
    def test_generic_exception(self, mock_run):
        result = list_processes()
        assert "Error:" in result


# ---------------------------------------------------------------------------
# capture_process
# ---------------------------------------------------------------------------

class TestCaptureProcess:
    @patch("server._get_process_connections", return_value=({54321}, {"142.250.80.14"}))
    @patch(PATCH)
    def test_basic_capture_uses_bpf_filter(self, mock_run, mock_conns, tmp_path):
        out = tmp_path / "out.pcap"
        mock_run.side_effect = [
            _ok(""),            # capture
            _ok("pkt summary"), # summary
        ]
        out.touch()
        result = capture_process(1234, "eth0", str(out))
        cap_args = mock_run.call_args_list[0][0]
        assert "-f" in cap_args
        assert "port 54321" in cap_args
        assert "54321" in result
        assert "pkt summary" in result

    @patch("server._get_process_connections", return_value=(set(), set()))
    @patch(PATCH)
    def test_no_connections_captures_without_filter(self, mock_run, mock_conns, tmp_path):
        out = tmp_path / "out.pcap"
        mock_run.side_effect = [_ok(""), _ok("")]
        out.touch()
        result = capture_process(1234, "eth0", str(out))
        cap_args = mock_run.call_args_list[0][0]
        assert "-f" not in cap_args
        assert "no active connections" in result.lower()

    @patch("server._get_process_connections", return_value=({443, 8080}, set()))
    @patch(PATCH)
    def test_multiple_ports_in_bpf(self, mock_run, mock_conns, tmp_path):
        out = tmp_path / "out.pcap"
        mock_run.side_effect = [_ok(""), _ok("x")]
        out.touch()
        capture_process(5678, "eth0", str(out))
        cap_args = mock_run.call_args_list[0][0]
        bpf_idx = list(cap_args).index("-f") + 1
        bpf = cap_args[bpf_idx]
        assert "port 443" in bpf
        assert "port 8080" in bpf

    @patch("server._get_process_connections", return_value=({54321}, set()))
    @patch(PATCH)
    def test_with_keylog_decrypts_tls(self, mock_run, mock_conns, tmp_path):
        out = tmp_path / "out.pcap"
        keys = tmp_path / "keys.log"
        keys.touch()
        stream_content = (
            "Node 0: 10.0.0.1:54321\nNode 1: 1.1.1.1:443\n"
            "GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        mock_run.side_effect = [
            _ok(""),              # capture
            _ok("pkt summary"),   # summary
            _ok("2\n2\n"),        # discover TLS stream indices
            _ok(stream_content),  # follow stream 2
        ]
        out.touch()
        result = capture_process(1234, "eth0", str(out), keylog_file=str(keys))
        assert "Decrypted TLS" in result
        assert "GET /secret" in result

    @patch("server._get_process_connections", return_value=({54321}, set()))
    @patch(PATCH)
    def test_packet_count_and_duration_capped(self, mock_run, mock_conns, tmp_path):
        out = tmp_path / "out.pcap"
        mock_run.side_effect = [_ok(""), _ok("")]
        out.touch()
        capture_process(1234, "eth0", str(out), duration=9999, packet_count=9999)
        cap_args = mock_run.call_args_list[0][0]
        assert "500" in cap_args
        assert "duration:60" in cap_args

    def test_keylog_not_found(self, tmp_path):
        result = capture_process(1234, "eth0", str(tmp_path / "out.pcap"),
                                 keylog_file=str(tmp_path / "missing.log"))
        assert "does not exist" in result

    @patch("server._get_process_connections", return_value=(set(), set()))
    @patch(PATCH, return_value=_err("permission denied"))
    def test_capture_error(self, mock_run, mock_conns, tmp_path):
        result = capture_process(1234, "eth0", str(tmp_path / "out.pcap"))
        assert "Error" in result

    @patch("server._get_process_connections", return_value=(set(), set()))
    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, mock_conns, tmp_path):
        result = capture_process(1234, "eth0", str(tmp_path / "out.pcap"))
        assert result == server._NOT_FOUND_MSG

    @patch("server._get_process_connections", return_value=(set(), set()))
    @patch(PATCH, side_effect=subprocess.TimeoutExpired("tshark", 40))
    def test_capture_timeout(self, mock_run, mock_conns, tmp_path):
        result = capture_process(1234, "eth0", str(tmp_path / "out.pcap"))
        assert "timed out" in result


# ---------------------------------------------------------------------------
# New tools — Tasks 3-11
# ---------------------------------------------------------------------------

from server import (
    get_traffic_timeseries,
    get_flow_matrix,
    analyze_dns,
    aggregate_flows,
    get_tcp_performance,
    reconstruct_tcap_dialogue,
    analyze_map_operations,
    export_objects,
    merge_pcap_files,
)


class TestGetTrafficTimeseries:
    @patch(PATCH, return_value=_ok(
        "| Interval | Frames | Bytes |\n"
        "| 0 <> 1   |     42 |  8400 |\n"
        "| 1 <> 2   |     17 |  3400 |\n"
    ))
    def test_returns_tshark_output(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_traffic_timeseries(str(f), interval_seconds=1.0)
        assert "Interval" in result
        call_args = " ".join(mock_run.call_args[0])
        assert "io,stat" in call_args
        assert "1.0" in call_args

    @patch(PATCH, return_value=_ok("stats"))
    def test_display_filter_passed(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        get_traffic_timeseries(str(f), interval_seconds=5.0, display_filter="tcp")
        call_args = " ".join(mock_run.call_args[0])
        assert "io,stat,5.0,tcp" in call_args

    def test_missing_file_returns_error(self):
        result = get_traffic_timeseries("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_traffic_timeseries(str(f))
        assert result == server._NOT_FOUND_MSG

    @patch(PATCH, return_value=_ok(""))
    def test_empty_output(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_traffic_timeseries(str(f))
        assert "No traffic" in result


class TestGetFlowMatrix:
    @patch(PATCH, return_value=_ok(
        "10.0.0.1\t10.0.0.2\t1500\n"
        "10.0.0.2\t10.0.0.1\t900\n"
        "10.0.0.1\t8.8.8.8\t200\n"
    ))
    def test_aggregates_top_pairs(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_flow_matrix(str(f))
        assert "10.0.0.1" in result
        assert "Packets" in result
        assert "Bytes" in result

    @patch(PATCH, return_value=_ok(
        "10.0.0.1\t10.0.0.2\t1500\n"
        "10.0.0.1\t10.0.0.2\t500\n"
    ))
    def test_sums_bytes_per_pair(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_flow_matrix(str(f))
        assert "2000" in result  # 1500 + 500

    @patch(PATCH, return_value=_ok(""))
    def test_empty_pcap_returns_no_data(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_flow_matrix(str(f))
        assert "No flow data" in result

    def test_missing_file_returns_error(self):
        result = get_flow_matrix("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_flow_matrix(str(f))
        assert result == server._NOT_FOUND_MSG


class TestAnalyzeDns:
    @patch(PATCH, return_value=_ok(
        "example.com\t0\t\t\t\n"
        "example.com\t0\t\t\t\n"
        "fail.example\t0\t\t\t\n"
        "example.com\t1\t0.012\texample.com\t0\n"
        "fail.example\t1\t0.001\t\t3\n"
    ))
    def test_parses_queries_and_responses(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_dns(str(f))
        assert "example.com" in result
        assert "Queries:" in result
        assert "Responses:" in result

    @patch(PATCH, return_value=_ok(
        "nx.example\t1\t0.001\t\t3\n"
    ))
    def test_nxdomain_detected(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_dns(str(f))
        assert "NXDOMAIN" in result

    @patch(PATCH, return_value=_ok(""))
    def test_no_dns_traffic(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_dns(str(f))
        assert "No DNS" in result

    def test_missing_file_returns_error(self):
        result = analyze_dns("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_dns(str(f))
        assert result == server._NOT_FOUND_MSG


class TestAggregateFlows:
    @patch(PATCH, return_value=_ok(
        "10.0.0.1\t10.0.0.2\t6\t1500\n"
        "10.0.0.1\t8.8.8.8\t17\t200\n"
    ))
    def test_default_grouping(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = aggregate_flows(str(f))
        assert "10.0.0" in result
        call_args = " ".join(mock_run.call_args[0])
        assert "ip.src" in call_args

    @patch(PATCH, return_value=_ok("10.0.0.1\t80\t5000\n"))
    def test_custom_group_by(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        aggregate_flows(str(f), group_by="ip.src,tcp.dstport")
        call_args = " ".join(mock_run.call_args[0])
        assert "tcp.dstport" in call_args

    @patch(PATCH, return_value=_ok(""))
    def test_empty_returns_no_data(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = aggregate_flows(str(f))
        assert "No flow data" in result

    def test_empty_group_by_returns_error(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = aggregate_flows(str(f), group_by="   ")
        assert "Error" in result

    def test_missing_file_returns_error(self):
        result = aggregate_flows("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = aggregate_flows(str(f))
        assert result == server._NOT_FOUND_MSG


class TestGetTcpPerformance:
    @patch(PATCH, return_value=_ok(
        "0.023\t65535\t\t\n"
        "0.041\t32768\t1\t\n"
        "\t16384\t\t1\n"
    ))
    def test_parses_tcp_fields(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_tcp_performance(str(f))
        assert "Retransmissions" in result
        assert "TCP packets" in result

    @patch(PATCH, return_value=_ok("0.010\t65535\t\t\n"))
    def test_rtt_shown_when_present(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_tcp_performance(str(f))
        assert "RTT" in result

    @patch(PATCH, return_value=_ok(""))
    def test_no_tcp_traffic(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_tcp_performance(str(f))
        assert "No TCP" in result

    def test_missing_file_returns_error(self):
        result = get_tcp_performance("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_tcp_performance(str(f))
        assert result == server._NOT_FOUND_MSG


class TestReconstructTcapDialogue:
    @patch(PATCH, return_value=_ok(
        "0.001\tbegin\taabbccdd\t\t1\tUpdateLocation\n"
        "0.025\tcontinue\taabbccdd\t11223344\t2\tUpdateLocation\n"
        "0.030\tend\t\t11223344\t2\tUpdateLocation\n"
    ))
    def test_parses_dialogue(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = reconstruct_tcap_dialogue(str(f))
        assert "aabbccdd" in result or "Dialogue" in result

    @patch(PATCH, return_value=_ok(""))
    def test_no_tcap_traffic(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = reconstruct_tcap_dialogue(str(f))
        assert "No TCAP" in result

    def test_missing_file_returns_error(self):
        result = reconstruct_tcap_dialogue("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = reconstruct_tcap_dialogue(str(f))
        assert result == server._NOT_FOUND_MSG


class TestAnalyzeMapOperations:
    @patch(PATCH, return_value=_ok(
        "2\t250208312345678\t79161234567\tUpdateLocation\n"
        "2\t250208312345678\t\tInsertSubscriberData\n"
        "56\t250208999888777\t79169876543\tSendRoutingInfoForSM\n"
    ))
    def test_parses_map_ops(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_map_operations(str(f))
        assert "UpdateLocation" in result or "MAP" in result

    @patch(PATCH, return_value=_ok(
        "2\t250208312345678\t\tUpdateLocation\n"
        "2\t250208312345678\t\tUpdateLocation\n"
        "56\t250208312345678\t\tSendRoutingInfoForSM\n"
    ))
    def test_imsi_tracking(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_map_operations(str(f))
        assert "250208312345678" in result or "IMSI" in result

    @patch(PATCH, return_value=_ok(""))
    def test_no_map_traffic(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_map_operations(str(f))
        assert "No MAP" in result

    def test_missing_file_returns_error(self):
        result = analyze_map_operations("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_map_operations(str(f))
        assert result == server._NOT_FOUND_MSG


class TestExportObjects:
    @patch("server.subprocess.run")
    def test_calls_tshark_export_objects(self, mock_subproc, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        pcap = tmp_path / "a.pcap"
        pcap.write_bytes(b"x")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_subproc.return_value = mock_result

        result = export_objects(str(pcap), "http", str(out_dir))
        call_args = " ".join(str(a) for a in mock_subproc.call_args[0][0])
        assert "--export-objects" in call_args
        assert "http" in call_args

    def test_unsupported_protocol_rejected(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = export_objects(str(f), "xyz", str(tmp_path))
        assert "Error" in result

    def test_missing_output_dir_returns_error(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = export_objects(str(f), "http", str(tmp_path / "nonexistent"))
        assert "Error" in result

    def test_missing_file_returns_error(self):
        result = export_objects("/no/such.pcap", "http", "/tmp")
        assert "Error" in result


class TestMergePcapFiles:
    @patch("server.subprocess.run")
    def test_calls_mergecap(self, mock_subproc, tmp_path):
        f1 = tmp_path / "a.pcap"
        f2 = tmp_path / "b.pcap"
        f1.write_bytes(b"x")
        f2.write_bytes(b"x")
        out = tmp_path / "merged.pcap"
        out.write_bytes(b"x")  # simulate output file created

        ok = MagicMock()
        ok.returncode = 0
        ok.stdout = "merged"
        ok.stderr = ""
        mock_subproc.return_value = ok

        result = merge_pcap_files(f"{f1},{f2}", str(out))
        calls = [" ".join(str(a) for a in c[0][0]) for c in mock_subproc.call_args_list]
        assert any("mergecap" in c for c in calls)

    def test_missing_input_file_returns_error(self, tmp_path):
        out = tmp_path / "out.pcap"
        result = merge_pcap_files("/no/a.pcap,/no/b.pcap", str(out))
        assert "Error" in result

    def test_single_file_rejected(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = merge_pcap_files(str(f), str(tmp_path / "out.pcap"))
        assert "Error" in result

    @patch("server._run", return_value=_ok("summary"))
    @patch("server.subprocess.run")
    @patch("server.sys.platform", "win32")
    @patch("server._TSHARK", r"C:\\Program Files\\Wireshark\\tshark.exe")
    def test_windows_uses_mergecap_exe(self, mock_subproc, mock_tshark_run, tmp_path):
        f1 = tmp_path / "a.pcap"
        f2 = tmp_path / "b.pcap"
        f1.write_bytes(b"x")
        f2.write_bytes(b"x")
        out = tmp_path / "merged.pcap"
        out.write_bytes(b"x")

        ok = MagicMock()
        ok.returncode = 0
        ok.stdout = "merged"
        ok.stderr = ""
        mock_subproc.return_value = ok

        merge_pcap_files(f"{f1},{f2}", str(out))
        cmd = [str(a) for a in mock_subproc.call_args[0][0]]
        assert any("mergecap.exe" in part for part in cmd)
