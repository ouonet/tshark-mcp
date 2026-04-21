# Professional Network Analysis Features — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 11 new MCP tools and fix 2 existing tools to cover professional network analysis needs: SCTP/SS7 signaling, time-series traffic, flow matrices, DNS deep analysis, TCP performance, TCAP/MAP telecom protocols, and file extraction.

**Architecture:** All new tools follow the existing pattern in `server.py` — `@mcp.tool()` decorated functions calling `_run()` (tshark subprocess wrapper) and aggregating results in Python where needed. Tests mock `server._run` so they work without tshark installed.

**Tech Stack:** Python 3.10+, TShark CLI, pytest, FastMCP. No new dependencies.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `server.py` | Modify | All new/fixed MCP tools live here |
| `test_server.py` | Modify | Tests for every new/fixed function |

---

## Task 1: Fix `get_conversations` — add SCTP support

**Files:**
- Modify: `server.py:427`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `test_server.py` inside a new `class TestGetConversationsSctp`:

```python
class TestGetConversationsSctp:
    @patch(PATCH, return_value=_ok("Conversations"))
    def test_sctp_protocol_accepted(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_conversations(str(f), protocol="sctp")
        assert "Conversations" in result
        call_args = " ".join(mock_run.call_args[0])
        assert "conv,sctp" in call_args

    def test_invalid_protocol_still_rejected(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_conversations(str(f), protocol="foobar")
        assert "Error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestGetConversationsSctp -v
```

Expected: FAIL — `get_conversations` rejects `sctp`.

- [ ] **Step 3: Apply the fix**

In `server.py` line 427, change:
```python
    allowed = {"eth", "ip", "tcp", "udp"}
```
to:
```python
    allowed = {"eth", "ip", "tcp", "udp", "sctp"}
```

Also update the docstring line 419:
```python
        protocol: Protocol to analyze - one of: eth, ip, tcp, udp, sctp (default: tcp)
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestGetConversationsSctp -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "fix: add sctp to get_conversations allowed protocols"
```

---

## Task 2: Fix `follow_stream` — add SCTP support

**Files:**
- Modify: `server.py:467`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `test_server.py`:

```python
class TestFollowStreamSctp:
    @patch(PATCH, return_value=_ok("SCTP stream data"))
    def test_sctp_stream_followed(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = follow_stream(str(f), protocol="sctp", stream_index=0)
        assert "SCTP stream data" in result
        call_args = " ".join(mock_run.call_args[0])
        assert "follow,sctp,ascii,0" in call_args

    def test_invalid_protocol_rejected(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = follow_stream(str(f), protocol="ftp")
        assert "Error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestFollowStreamSctp -v
```

Expected: FAIL — `follow_stream` rejects `sctp`.

- [ ] **Step 3: Apply the fix**

In `server.py` line 467, change:
```python
    if protocol not in ("tcp", "udp"):
        return "Error: protocol must be 'tcp' or 'udp'"
```
to:
```python
    if protocol not in ("tcp", "udp", "sctp"):
        return "Error: protocol must be 'tcp', 'udp', or 'sctp'"
```

Also update the docstring line 456:
```python
        protocol: Stream protocol - "tcp", "udp", or "sctp"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestFollowStreamSctp -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "fix: add sctp support to follow_stream"
```

---

## Task 3: New tool `get_traffic_timeseries`

Time-series analysis: packets and bytes per time interval, using tshark's built-in `io,stat` statistic.

**Files:**
- Modify: `server.py` (add after `get_packet_statistics`)
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `test_server.py`:

```python
from server import get_traffic_timeseries

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
        assert "Frames" in result
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
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestGetTrafficTimeseries -v
```

Expected: FAIL — `get_traffic_timeseries` not defined.

- [ ] **Step 3: Implement the tool**

Add after the `get_packet_statistics` function in `server.py`:

```python
@mcp.tool()
def get_traffic_timeseries(
    file_path: str,
    interval_seconds: float = 1.0,
    display_filter: Optional[str] = None,
) -> str:
    """
    Compute traffic volume over time — packets and bytes per interval.

    Uses tshark's io,stat to bucket traffic into fixed-width time windows.
    Useful for identifying bursts, sustained flows, and periodic patterns.

    Args:
        file_path: Path to the PCAP file
        interval_seconds: Bucket width in seconds (default: 1.0)
        display_filter: Optional display filter to restrict which packets
                        are counted (e.g. "tcp", "ip.addr == 10.0.0.1")

    Returns:
        Table of intervals with frame count and byte count per bucket
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    stat_expr = f"io,stat,{interval_seconds}"
    if display_filter:
        stat_expr += f",{display_filter}"

    try:
        result = _run("-r", file_path, "-q", "-z", stat_expr)
        if result.returncode == 0:
            return result.stdout or "No traffic data found"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Timeseries analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestGetTrafficTimeseries -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add get_traffic_timeseries tool for temporal traffic analysis"
```

---

## Task 4: New tool `get_flow_matrix`

Host-pair communication matrix: shows bytes and packet counts between each (src_ip, dst_ip) pair.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing test**

Add to `test_server.py`:

```python
from server import get_flow_matrix

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
        # Should contain a header and pair rows
        assert "src" in result.lower() or "10.0.0" in result

    @patch(PATCH, return_value=_ok(""))
    def test_empty_pcap_returns_no_data(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_flow_matrix(str(f))
        assert "No flow data" in result or result == "No flow data found"

    def test_missing_file_returns_error(self):
        result = get_flow_matrix("/no/such/file.pcap")
        assert "Error" in result

    @patch(PATCH, side_effect=FileNotFoundError)
    def test_tshark_not_found(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_flow_matrix(str(f))
        assert result == server._NOT_FOUND_MSG
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestGetFlowMatrix -v
```

Expected: FAIL — `get_flow_matrix` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def get_flow_matrix(
    file_path: str,
    display_filter: Optional[str] = None,
    top_n: int = 20,
) -> str:
    """
    Build a host-pair communication matrix showing traffic volume.

    Extracts ip.src, ip.dst, and frame.len fields from packets, then
    aggregates by (src, dst) pair sorted by total bytes descending.

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional display filter (e.g. "not arp")
        top_n: Number of top host pairs to return (default: 20)

    Returns:
        Ranked table of host pairs with packet count and byte totals
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    try:
        args = ["-r", file_path, "-T", "fields",
                "-e", "ip.src", "-e", "ip.dst", "-e", "frame.len"]
        if display_filter:
            args.extend(["-Y", display_filter])

        result = _run(*args)
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        # Aggregate (src, dst) -> (packets, bytes)
        flows: dict[tuple[str, str], list[int]] = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) != 3:
                continue
            src, dst, length = parts
            if not src or not dst:
                continue
            try:
                size = int(length)
            except ValueError:
                continue
            key = (src, dst)
            if key not in flows:
                flows[key] = [0, 0]
            flows[key][0] += 1
            flows[key][1] += size

        if not flows:
            return "No flow data found"

        # Sort by bytes descending, take top N
        sorted_flows = sorted(flows.items(), key=lambda x: x[1][1], reverse=True)[:top_n]

        lines = [f"{'Src IP':<20} {'Dst IP':<20} {'Packets':>10} {'Bytes':>12}"]
        lines.append("-" * 66)
        for (src, dst), (pkts, byts) in sorted_flows:
            lines.append(f"{src:<20} {dst:<20} {pkts:>10} {byts:>12}")
        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: Flow matrix analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestGetFlowMatrix -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add get_flow_matrix for host-pair communication analysis"
```

---

## Task 5: New tool `analyze_dns`

DNS query/response deep analysis: query patterns, response times, NXDOMAIN detection, top domains.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import analyze_dns

class TestAnalyzeDns:
    @patch(PATCH, return_value=_ok(
        "example.com\t0\t0.012\texample.com\t0\n"
        "fail.example\t0\t0.001\t\t3\n"
    ))
    def test_returns_parsed_output(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = analyze_dns(str(f))
        assert "example.com" in result

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
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestAnalyzeDns -v
```

Expected: FAIL — `analyze_dns` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def analyze_dns(
    file_path: str,
    display_filter: Optional[str] = None,
    top_n: int = 30,
) -> str:
    """
    Deep analysis of DNS traffic: query patterns, response times, error rates.

    Extracts per-query details including query name, response code, and
    response time, then summarises top queried domains and NXDOMAIN failures.

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional extra display filter (applied in addition to dns)
        top_n: Number of top domains to show in summary (default: 30)

    Returns:
        DNS summary with top queried domains, NXDOMAIN list, and response stats
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    base_filter = "dns"
    if display_filter:
        base_filter = f"dns and ({display_filter})"

    try:
        args = [
            "-r", file_path,
            "-T", "fields",
            "-e", "dns.qry.name",
            "-e", "dns.flags.response",
            "-e", "dns.time",
            "-e", "dns.resp.name",
            "-e", "dns.flags.rcode",
            "-Y", base_filter,
        ]
        result = _run(*args)
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        domain_counts: dict[str, int] = {}
        nxdomains: list[str] = []
        response_times: list[float] = []
        query_count = 0
        response_count = 0

        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue
            qname, is_response, resp_time, resp_name, rcode = parts

            if is_response == "0":
                # This is a query
                query_count += 1
                if qname:
                    domain_counts[qname] = domain_counts.get(qname, 0) + 1
            elif is_response == "1":
                # This is a response
                response_count += 1
                if resp_time:
                    try:
                        response_times.append(float(resp_time))
                    except ValueError:
                        pass
                if rcode == "3" and qname:  # NXDOMAIN
                    nxdomains.append(qname)

        if query_count == 0 and response_count == 0:
            return "No DNS traffic found"

        lines = ["=== DNS Analysis ===", f"Queries: {query_count}  Responses: {response_count}"]

        if response_times:
            avg_ms = sum(response_times) / len(response_times) * 1000
            max_ms = max(response_times) * 1000
            lines.append(f"Response time — avg: {avg_ms:.1f}ms  max: {max_ms:.1f}ms")

        lines.append(f"\n--- Top {top_n} Queried Domains ---")
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        for domain, count in sorted_domains:
            lines.append(f"  {count:>6}  {domain}")

        if nxdomains:
            unique_nx = sorted(set(nxdomains))
            lines.append(f"\n--- NXDOMAIN ({len(nxdomains)} failures, {len(unique_nx)} unique) ---")
            for d in unique_nx[:top_n]:
                lines.append(f"  {d}")

        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: DNS analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestAnalyzeDns -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add analyze_dns for DNS query/response deep analysis"
```

---

## Task 6: New tool `aggregate_flows`

Multi-dimensional flow aggregation: group packets by any combination of tshark fields.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import aggregate_flows

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

    @patch(PATCH, return_value=_ok("10.0.0.1\t80\t100\t5000\n"))
    def test_custom_group_by(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = aggregate_flows(str(f), group_by="ip.src,tcp.dstport")
        call_args = " ".join(mock_run.call_args[0])
        assert "tcp.dstport" in call_args

    @patch(PATCH, return_value=_ok(""))
    def test_empty_returns_no_data(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = aggregate_flows(str(f))
        assert "No flow data" in result

    def test_missing_file_returns_error(self):
        result = aggregate_flows("/no/such/file.pcap")
        assert "Error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestAggregateFlows -v
```

Expected: FAIL — `aggregate_flows` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def aggregate_flows(
    file_path: str,
    group_by: str = "ip.src,ip.dst,ip.proto",
    display_filter: Optional[str] = None,
    top_n: int = 20,
) -> str:
    """
    Aggregate packet flows grouped by arbitrary tshark field combinations.

    Extracts the specified fields plus frame.len from each packet, then
    groups and sums by those fields. Default grouping is (src IP, dst IP,
    protocol number).

    Args:
        file_path: Path to the PCAP file
        group_by: Comma-separated tshark field names to group by
                  (default: "ip.src,ip.dst,ip.proto").
                  Examples: "ip.src,tcp.dstport" for per-service flows,
                            "ip.src,ip.dst,ip.proto,tcp.dstport" for 5-tuple
        display_filter: Optional display filter (e.g. "tcp.dstport == 5432")
        top_n: Number of top flows to return, ranked by bytes (default: 20)

    Returns:
        Table of flow groups with packet count and byte total, ranked by volume
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    fields = [f.strip() for f in group_by.split(",") if f.strip()]
    if not fields:
        return "Error: group_by must contain at least one field name"

    try:
        args = ["-r", file_path, "-T", "fields"]
        for field in fields:
            args.extend(["-e", field])
        args.extend(["-e", "frame.len"])
        if display_filter:
            args.extend(["-Y", display_filter])

        result = _run(*args)
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        groups: dict[tuple[str, ...], list[int]] = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) != len(fields) + 1:
                continue
            key = tuple(parts[:-1])
            try:
                size = int(parts[-1])
            except ValueError:
                continue
            if key not in groups:
                groups[key] = [0, 0]
            groups[key][0] += 1
            groups[key][1] += size

        if not groups:
            return "No flow data found"

        sorted_groups = sorted(groups.items(), key=lambda x: x[1][1], reverse=True)[:top_n]

        header = "  ".join(f"{f:<18}" for f in fields) + f"  {'Packets':>10}  {'Bytes':>12}"
        lines = [header, "-" * len(header)]
        for key, (pkts, byts) in sorted_groups:
            row = "  ".join(f"{v:<18}" for v in key)
            lines.append(f"{row}  {pkts:>10}  {byts:>12}")
        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: Flow aggregation timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestAggregateFlows -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add aggregate_flows for multi-dimensional traffic grouping"
```

---

## Task 7: New tool `get_tcp_performance`

TCP performance metrics: retransmission rate, RTT, window size analysis.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import get_tcp_performance

class TestGetTcpPerformance:
    @patch(PATCH, return_value=_ok(
        "0.023\t65535\t\t\n"
        "0.041\t32768\t1\t\n"
        "\t\t\t1\n"
    ))
    def test_parses_tcp_fields(self, mock_run, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        result = get_tcp_performance(str(f))
        assert "RTT" in result or "Retransmission" in result

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
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestGetTcpPerformance -v
```

Expected: FAIL — `get_tcp_performance` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def get_tcp_performance(
    file_path: str,
    display_filter: Optional[str] = None,
) -> str:
    """
    Analyse TCP performance: RTT, retransmissions, window size, and lost segments.

    Extracts tcp.analysis.ack_rtt, tcp.window_size,
    tcp.analysis.retransmission, and tcp.analysis.lost_segment fields
    to compute aggregate statistics useful for diagnosing network quality.

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional display filter (e.g. "ip.addr == 10.0.0.1")

    Returns:
        Performance summary with RTT stats, retransmission count, and window info
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    base_filter = "tcp"
    if display_filter:
        base_filter = f"tcp and ({display_filter})"

    try:
        args = [
            "-r", file_path,
            "-T", "fields",
            "-e", "tcp.analysis.ack_rtt",
            "-e", "tcp.window_size",
            "-e", "tcp.analysis.retransmission",
            "-e", "tcp.analysis.lost_segment",
            "-Y", base_filter,
        ]
        result = _run(*args)
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        rtts: list[float] = []
        window_sizes: list[int] = []
        retransmissions = 0
        lost_segments = 0
        total_packets = 0

        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 4:
                continue
            rtt_str, win_str, retrans_str, lost_str = parts[:4]
            total_packets += 1

            if rtt_str:
                try:
                    rtts.append(float(rtt_str))
                except ValueError:
                    pass
            if win_str:
                try:
                    window_sizes.append(int(win_str))
                except ValueError:
                    pass
            if retrans_str == "1":
                retransmissions += 1
            if lost_str == "1":
                lost_segments += 1

        if total_packets == 0:
            return "No TCP traffic found"

        lines = ["=== TCP Performance Analysis ===", f"TCP packets analysed: {total_packets}"]

        if rtts:
            avg_rtt = sum(rtts) / len(rtts) * 1000
            max_rtt = max(rtts) * 1000
            min_rtt = min(rtts) * 1000
            lines.append(f"\nRTT (from {len(rtts)} ACK measurements):")
            lines.append(f"  avg: {avg_rtt:.2f}ms  min: {min_rtt:.2f}ms  max: {max_rtt:.2f}ms")
        else:
            lines.append("\nRTT: no ACK RTT measurements found")

        retrans_pct = retransmissions / total_packets * 100
        lines.append(f"\nRetransmissions: {retransmissions} ({retrans_pct:.2f}% of packets)")
        lines.append(f"Lost segments detected: {lost_segments}")

        if window_sizes:
            avg_win = sum(window_sizes) / len(window_sizes)
            min_win = min(window_sizes)
            lines.append(f"\nTCP Window size — avg: {avg_win:.0f}  min: {min_win}")
            if min_win == 0:
                lines.append("  WARNING: zero-window detected (receiver buffer full)")

        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: TCP performance analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestGetTcpPerformance -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add get_tcp_performance for RTT, retransmission, and window analysis"
```

---

## Task 8: New tool `reconstruct_tcap_dialogue`

Reconstruct SS7 TCAP dialogues (Begin/Continue/End/Abort chains) by OTID/DTID.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import reconstruct_tcap_dialogue

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
        assert "aabbccdd" in result or "Dialogue" in result or "begin" in result

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
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestReconstructTcapDialogue -v
```

Expected: FAIL — `reconstruct_tcap_dialogue` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def reconstruct_tcap_dialogue(
    file_path: str,
    display_filter: Optional[str] = None,
    max_dialogues: int = 20,
) -> str:
    """
    Reconstruct SS7 TCAP signaling dialogues from a PCAP file.

    Groups TCAP messages (Begin/Continue/End/Abort) by their transaction IDs
    (OTID/DTID) to show the full lifecycle of each signaling dialogue.
    MAP operation codes (when present) are included for each component.

    Typical protocol stack: SCTP → M3UA → SCCP → TCAP → MAP

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional extra filter (e.g. "sccp.called_party == '...'")
        max_dialogues: Maximum number of dialogues to reconstruct (default: 20)

    Returns:
        Per-dialogue message sequence with timestamps, message types, and MAP ops
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    base_filter = "tcap"
    if display_filter:
        base_filter = f"tcap and ({display_filter})"

    try:
        args = [
            "-r", file_path,
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "tcap.MessageType",
            "-e", "tcap.otid",
            "-e", "tcap.dtid",
            "-e", "tcap.invokeId",
            "-e", "gsm_map.opr.code",
            "-Y", base_filter,
        ]
        result = _run(*args, timeout=120)
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        # dialogues keyed by (otid, dtid) normalised — we track by the first
        # seen OTID and match incoming DTIDs back to it.
        otid_to_dialogue: dict[str, list[dict]] = {}
        dtid_to_otid: dict[str, str] = {}

        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 6:
                continue
            ts, msg_type, otid, dtid, invoke_id, map_op = parts[:6]
            otid = otid.strip()
            dtid = dtid.strip()

            # Determine which dialogue this belongs to
            dialogue_key = None
            if otid and otid not in dtid_to_otid:
                # New or existing dialogue started by this OTID
                if otid not in otid_to_dialogue:
                    otid_to_dialogue[otid] = []
                dialogue_key = otid
            if dtid and dtid in otid_to_dialogue:
                # Response referencing a known OTID
                dtid_to_otid[dtid] = dtid
                dialogue_key = dtid
            elif otid and otid in otid_to_dialogue:
                dialogue_key = otid
            elif dtid and dtid in dtid_to_otid:
                dialogue_key = dtid_to_otid[dtid]

            if dialogue_key is None:
                dialogue_key = otid or dtid or "unknown"
                if dialogue_key not in otid_to_dialogue:
                    otid_to_dialogue[dialogue_key] = []

            otid_to_dialogue[dialogue_key].append({
                "ts": ts, "type": msg_type, "otid": otid,
                "dtid": dtid, "invoke": invoke_id, "op": map_op,
            })

        if not otid_to_dialogue:
            return "No TCAP traffic found"

        lines = [f"=== TCAP Dialogue Reconstruction ({len(otid_to_dialogue)} dialogues) ==="]
        for i, (key, messages) in enumerate(list(otid_to_dialogue.items())[:max_dialogues]):
            lines.append(f"\n--- Dialogue {i+1} (OTID: {key}) ---")
            for msg in messages:
                op_str = f"  MAP-op:{msg['op']}" if msg['op'] else ""
                lines.append(
                    f"  t={msg['ts']:>10}s  [{msg['type']:<10}]"
                    f"  OTID={msg['otid'] or '-':>10}  DTID={msg['dtid'] or '-':>10}"
                    f"{op_str}"
                )
        if len(otid_to_dialogue) > max_dialogues:
            lines.append(f"\n... and {len(otid_to_dialogue) - max_dialogues} more dialogues")

        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: TCAP reconstruction timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestReconstructTcapDialogue -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add reconstruct_tcap_dialogue for SS7 signaling analysis"
```

---

## Task 9: New tool `analyze_map_operations`

MAP (Mobile Application Part) operation statistics with IMSI/MSISDN tracking.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import analyze_map_operations

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
        assert "UpdateLocation" in result or "IMSI" in result or "250208" in result

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
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestAnalyzeMapOperations -v
```

Expected: FAIL — `analyze_map_operations` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def analyze_map_operations(
    file_path: str,
    display_filter: Optional[str] = None,
    top_n: int = 20,
) -> str:
    """
    Analyse GSM MAP (Mobile Application Part) operations from SS7 traffic.

    Extracts MAP operation codes, IMSI, and MSISDN values to show which
    operations are most frequent and which subscribers are involved.
    Useful for telecom network auditing and SS7 security analysis.

    Typical protocol stack: SCTP → M3UA → SCCP → TCAP → MAP

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional extra filter to narrow MAP traffic
        top_n: Top N operations and subscribers to show (default: 20)

    Returns:
        MAP operation frequency table and per-IMSI activity summary
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    base_filter = "gsm_map"
    if display_filter:
        base_filter = f"gsm_map and ({display_filter})"

    try:
        args = [
            "-r", file_path,
            "-T", "fields",
            "-e", "gsm_map.opr.code",
            "-e", "gsm_map.imsi",
            "-e", "gsm_map.msisdn.digits",
            "-e", "gsm_map.opr.code_string",
            "-Y", base_filter,
        ]
        result = _run(*args, timeout=120)
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        op_counts: dict[str, int] = {}
        imsi_ops: dict[str, dict[str, int]] = {}
        total = 0

        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 4:
                continue
            op_code, imsi, msisdn, op_name = parts[:4]
            if not op_code and not op_name:
                continue
            total += 1
            label = op_name if op_name else f"op-{op_code}"
            op_counts[label] = op_counts.get(label, 0) + 1

            if imsi:
                if imsi not in imsi_ops:
                    imsi_ops[imsi] = {}
                imsi_ops[imsi][label] = imsi_ops[imsi].get(label, 0) + 1

        if total == 0:
            return "No MAP traffic found"

        lines = [f"=== MAP Operation Analysis ({total} messages) ==="]
        lines.append(f"\n--- Top {top_n} Operations ---")
        sorted_ops = sorted(op_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        for op, count in sorted_ops:
            pct = count / total * 100
            lines.append(f"  {count:>6} ({pct:5.1f}%)  {op}")

        if imsi_ops:
            lines.append(f"\n--- Top {top_n} Active IMSIs ---")
            sorted_imsi = sorted(imsi_ops.items(), key=lambda x: sum(x[1].values()), reverse=True)[:top_n]
            for imsi, ops in sorted_imsi:
                total_imsi = sum(ops.values())
                ops_str = ", ".join(f"{op}:{n}" for op, n in sorted(ops.items(), key=lambda x: x[1], reverse=True)[:3])
                lines.append(f"  IMSI {imsi}  ({total_imsi} msgs)  [{ops_str}]")

        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: MAP analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestAnalyzeMapOperations -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add analyze_map_operations for SS7 MAP protocol analysis"
```

---

## Task 10: New tool `export_objects`

Extract transferred files from HTTP, SMB, FTP, TFTP streams embedded in a PCAP.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import export_objects
import os

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

    def test_missing_file_returns_error(self):
        result = export_objects("/no/such.pcap", "http", "/tmp/out")
        assert "Error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestExportObjects -v
```

Expected: FAIL — `export_objects` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def export_objects(
    file_path: str,
    protocol: str,
    output_dir: str,
) -> str:
    """
    Extract transferred files from a PCAP using tshark's --export-objects.

    Reconstructs files exchanged over application protocols and writes them
    to output_dir. Useful for forensic recovery of HTTP downloads, SMB file
    transfers, FTP uploads/downloads, and TFTP transfers.

    Args:
        file_path: Path to the PCAP file
        protocol: Protocol layer to extract from — one of: http, smb, tftp,
                  imf, dicom
        output_dir: Directory where extracted files will be written (must exist)

    Returns:
        List of extracted files with sizes, or error message
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    allowed = {"http", "smb", "tftp", "imf", "dicom"}
    if protocol not in allowed:
        return f"Error: protocol must be one of {sorted(allowed)}"

    out_path = Path(output_dir)
    if not out_path.exists():
        return f"Error: output_dir {output_dir} does not exist"

    try:
        result = subprocess.run(
            [_TSHARK, "-r", file_path, "--export-objects", f"{protocol},{output_dir}"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120,
        )
        if result.returncode != 0:
            return f"Error: {result.stderr}"

        extracted = list(out_path.iterdir())
        if not extracted:
            return f"No {protocol.upper()} objects found in capture"

        lines = [f"Extracted {len(extracted)} object(s) to {output_dir}:"]
        for p in sorted(extracted):
            try:
                size = p.stat().st_size
            except OSError:
                size = -1
            lines.append(f"  {size:>10} bytes  {p.name}")
        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: Object export timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestExportObjects -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add export_objects for file extraction from HTTP/SMB/FTP/TFTP"
```

---

## Task 11: New tool `merge_pcap_files`

Merge multiple PCAP files with timestamp alignment, then analyse the combined capture.

**Files:**
- Modify: `server.py`
- Modify: `test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `test_server.py`:

```python
from server import merge_pcap_files

class TestMergePcapFiles:
    @patch("server.subprocess.run")
    def test_calls_mergecap(self, mock_subproc, tmp_path):
        f1 = tmp_path / "a.pcap"
        f2 = tmp_path / "b.pcap"
        f1.write_bytes(b"x")
        f2.write_bytes(b"x")
        out = tmp_path / "merged.pcap"

        ok = MagicMock()
        ok.returncode = 0
        ok.stdout = "merged output"
        ok.stderr = ""
        mock_subproc.return_value = ok

        result = merge_pcap_files(f"{f1},{f2}", str(out))
        calls = [str(c) for c in mock_subproc.call_args_list]
        assert any("mergecap" in c for c in calls)

    def test_missing_input_file_returns_error(self, tmp_path):
        out = tmp_path / "out.pcap"
        result = merge_pcap_files("/no/such/a.pcap,/no/such/b.pcap", str(out))
        assert "Error" in result

    def test_single_file_rejected(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"x")
        out = tmp_path / "out.pcap"
        result = merge_pcap_files(str(f), str(out))
        assert "Error" in result
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest test_server.py::TestMergePcapFiles -v
```

Expected: FAIL — `merge_pcap_files` not defined.

- [ ] **Step 3: Implement the tool**

Add to `server.py`:

```python
@mcp.tool()
def merge_pcap_files(
    input_files: str,
    output_file: str,
    display_filter: Optional[str] = None,
) -> str:
    """
    Merge multiple PCAP files in timestamp order and analyse the combined result.

    Uses mergecap (bundled with Wireshark) to combine captures from multiple
    network taps or capture sessions, then runs a packet summary on the merged
    file. Useful for correlating events across different capture points.

    Args:
        input_files: Comma-separated paths to input PCAP files (minimum 2)
        output_file: Path where the merged PCAP will be written
        display_filter: Optional display filter for the post-merge summary

    Returns:
        Merge status and packet summary of the combined capture
    """
    files = [f.strip() for f in input_files.split(",") if f.strip()]
    if len(files) < 2:
        return "Error: input_files must contain at least two comma-separated paths"

    missing = [f for f in files if not Path(f).exists()]
    if missing:
        return f"Error: files not found: {', '.join(missing)}"

    # Determine mergecap path relative to tshark
    tshark_path = Path(_TSHARK)
    if tshark_path.is_absolute():
        mergecap = str(tshark_path.parent / "mergecap")
    else:
        mergecap = "mergecap"

    try:
        merge_result = subprocess.run(
            [mergecap, "-w", output_file] + files,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )
        if merge_result.returncode != 0:
            return f"Error during merge: {merge_result.stderr}"

        if not Path(output_file).exists():
            return "Error: merge produced no output file"

        # Summary of merged file
        sum_args = ["-r", output_file, "-q"]
        if display_filter:
            sum_args.extend(["-Y", display_filter])

        summary = _run(*sum_args)
        summary_text = summary.stdout.strip() if summary.returncode == 0 else f"(summary error: {summary.stderr})"

        return (
            f"Merged {len(files)} files into {output_file}\n"
            f"Sources: {', '.join(files)}\n\n"
            f"=== Merged Capture Summary ===\n{summary_text or '(no packets)'}"
        )

    except subprocess.TimeoutExpired:
        return "Error: Merge timed out"
    except FileNotFoundError:
        return (
            f"Error: mergecap not found at '{mergecap}'. "
            "Ensure Wireshark is installed and mergecap is on PATH."
        )
    except Exception as e:
        return f"Error: {str(e)}"
```

- [ ] **Step 4: Run tests**

```
python -m pytest test_server.py::TestMergePcapFiles -v
```

Expected: PASS

- [ ] **Step 5: Run the full test suite to catch regressions**

```
python -m pytest test_server.py -v
```

Expected: All tests PASS (new + existing).

- [ ] **Step 6: Commit**

```bash
git add server.py test_server.py
git commit -m "feat: add merge_pcap_files for cross-pcap correlation and analysis"
```

---

## Final Verification

- [ ] **Run the complete test suite**

```
python -m pytest test_server.py -v --tb=short
```

Expected: All tests pass. No regressions in existing 16 tools.

- [ ] **Verify tool count**

```python
python -c "import server; tools = [a for a in dir(server) if not a.startswith('_')]; print(len([t for t in tools if callable(getattr(server, t)) and hasattr(getattr(server, t), '__wrapped__')]))"
```

Expected: 27 tools (16 original + 11 new).

- [ ] **Verify server starts cleanly**

```
python server.py --help 2>&1 | head -5
```

Expected: No import errors.

---

## Summary of Changes

| # | Tool | Type | Benefit |
|---|------|------|---------|
| 1 | `get_conversations` | Fix | SCTP conversation stats now work |
| 2 | `follow_stream` | Fix | SCTP stream reconstruction works |
| 3 | `get_traffic_timeseries` | New | Temporal burst/trend analysis |
| 4 | `get_flow_matrix` | New | Host-pair communication matrix |
| 5 | `analyze_dns` | New | DNS query patterns, NXDOMAIN, RTT |
| 6 | `aggregate_flows` | New | Multi-dimensional flow grouping |
| 7 | `get_tcp_performance` | New | RTT, retransmission, window analysis |
| 8 | `reconstruct_tcap_dialogue` | New | SS7 TCAP dialogue reconstruction |
| 9 | `analyze_map_operations` | New | MAP ops + IMSI/MSISDN tracking |
| 10 | `export_objects` | New | File extraction (HTTP/SMB/FTP/TFTP) |
| 11 | `merge_pcap_files` | New | Cross-PCAP merge and correlation |
