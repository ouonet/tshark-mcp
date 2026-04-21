#!/usr/bin/env python3
"""
TShark MCP Server

An MCP server that provides tools for analyzing network packets using TShark.
"""

import csv
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Allow overriding the tshark executable path via environment variable.
# Example: set TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
_TSHARK = os.environ.get("TSHARK_PATH", "tshark")
_NOT_FOUND_MSG = (
    f"Error: TShark not found at '{_TSHARK}'. "
    "Install Wireshark/TShark or set the TSHARK_PATH environment variable."
)


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run tshark with the given arguments."""
    return subprocess.run(
        [_TSHARK, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _tls_args(keylog_file: Optional[str]) -> list[str]:
    """Return tshark override args for TLS decryption if keylog_file is given."""
    if not keylog_file:
        return []
    if not Path(keylog_file).exists():
        raise FileNotFoundError(f"Key log file not found: {keylog_file}")
    return ["-o", f"tls.keylog_file:{keylog_file}"]


# Create the MCP server
mcp = FastMCP(
    "TShark Analyzer",
    instructions="""
MCP server for network packet analysis using TShark (Wireshark CLI).
Supports offline PCAP analysis, live capture, TLS decryption, and telecom/SS7 signaling.

## Tool Groups

### Basic Analysis
- `analyze_pcap_file` — packet summaries with optional display filter
- `get_packet_statistics` — protocol hierarchy breakdown
- `extract_packet_details` — full verbose detail for one packet
- `extract_fields` — extract any tshark field as TSV (e.g. ip.src, http.request.uri)
- `export_to_json` — export packets as JSON
- `run_tshark_command` — run any raw tshark command

### Traffic Aggregation & Statistics
- `get_conversations` — conversation stats; protocol: eth | ip | tcp | udp | sctp
- `get_flow_matrix` — host-pair matrix ranked by bytes (ip.src × ip.dst)
- `get_traffic_timeseries` — packets/bytes per time interval (burst detection)
- `aggregate_flows` — group flows by any field combo (e.g. ip.src,tcp.dstport)
- `get_packet_statistics` — protocol hierarchy (io,phs)

### Protocol-Specific Analysis
- `analyze_dns` — DNS query patterns, NXDOMAIN detection, response times
- `get_tcp_performance` — RTT, retransmissions, window size (diagnose network quality)
- `follow_stream` — reconstruct TCP / UDP / SCTP stream as ASCII
- `follow_tls_stream` — reconstruct decrypted TLS stream (needs keylog file)

### Telecom / SS7 Signaling (SCTP → M3UA → SCCP → TCAP → MAP)
- `reconstruct_tcap_dialogue` — group TCAP Begin/Continue/End by OTID/DTID
- `analyze_map_operations` — MAP operation frequency + IMSI/MSISDN tracking

### Live Capture
- `list_interfaces` — list capture interfaces
- `capture_live` — capture packets live
- `capture_process` — capture traffic for a specific PID
- `capture_and_decrypt` — capture + decrypt TLS in one step

### File Operations
- `filter_and_save` — filter PCAP and save to new file
- `export_objects` — extract files from HTTP/SMB/TFTP/IMF streams
- `merge_pcap_files` — merge multiple PCAPs with timestamp alignment

### TLS Decryption
- All analysis tools accept `keylog_file=` (SSLKEYLOGFILE format)
- IMPORTANT: For TLS decryption workflow or key extraction via debugger, call `tshark_reading_manual` FIRST

## Common Patterns

**Protocol filter examples**: `tcp`, `udp`, `sctp`, `dns`, `http`, `tls`, `gsm_map`, `tcap`, `telnet`

**Field extraction examples**:
- IP pair: `ip.src,ip.dst`
- HTTP: `http.request.method,http.request.uri,http.response.code`
- DNS: `dns.qry.name,dns.flags.rcode`
- TCP perf: `tcp.analysis.ack_rtt,tcp.window_size,tcp.analysis.retransmission`
- SS7/MAP: `gsm_map.opr.code,gsm_map.imsi,tcap.otid,tcap.dtid`
- TELNET: follow_stream with protocol="tcp" on port 23 traffic

## SS7 Analysis Workflow
1. `get_packet_statistics` — confirm SCTP/M3UA/SCCP/TCAP/MAP layers present
2. `reconstruct_tcap_dialogue` — see Begin→Continue→End chains
3. `analyze_map_operations` — operation frequency and IMSI activity
4. `aggregate_flows` with group_by="sccp.calling_party,sccp.called_party" — routing analysis
5. `extract_fields` with gsm_map fields for raw data
"""
)


@mcp.tool()
def tshark_reading_manual() -> str:
    """
    Get detailed workflow instructions on how to set up TLS/SSL decryption, 
    including extracting keys from memory via x64dbg.
    Call this tool BEFORE attempting to decrypt TLS traffic.
    """
    return """
## TLS/SSL Decryption Workflow

To decrypt HTTPS or other TLS traffic you need a key log file (SSLKEYLOGFILE).
Follow these steps in order — never skip step 1:

### Step 1 — Generate the key log file (user must do this BEFORE capturing)

Instruct the user to set the SSLKEYLOGFILE environment variable and then launch
the target application from that same shell:

  Windows CMD:
    set SSLKEYLOGFILE=C:\\captures\\keys.log
    start chrome

  Windows PowerShell:
    $env:SSLKEYLOGFILE = "C:\\captures\\keys.log"
    Start-Process chrome

  Linux / macOS:
    export SSLKEYLOGFILE=/tmp/keys.log
    google-chrome &

Supported: Chrome, Edge, Firefox, curl, Python (requests/httpx/aiohttp).
The file will be created automatically by the app when TLS sessions start.

### Step 2 — Capture traffic while the app is running

Option A — Capture to a file and decrypt afterwards (recommended):
  Use capture_live() to save to a pcap, then analyze_pcap_file() /
  follow_tls_stream() / extract_fields() with keylog_file= pointing at keys.log.

Option B — Capture and decrypt in one step:
  Use capture_and_decrypt(interface, keylog_file, output_pcap) which captures
  live traffic, saves it, and immediately returns decrypted TLS stream content.

### Step 3 — Analyze decrypted content

- follow_tls_stream(file_path, keylog_file, stream_index=0)
    → returns plaintext HTTP request/response for stream N
- extract_fields(file_path, "http.request.uri,http.host", keylog_file=...)
    → extracts specific fields from decrypted packets
- export_to_json(file_path, keylog_file=...)
    → full packet details including decrypted application data

### Important notes

- The key log file must exist before you call any tool with keylog_file=.
- If the capture and the key log file are from the same browser session,
  decryption will succeed. A key log file from a different session will not work.
- Use list_interfaces() to find the correct interface name before capturing.
- On Windows, interface names look like \\Device\\NPF_{GUID}. Pass them exactly.

## Extracting TLS Keys via Debugger (when SSLKEYLOGFILE is not supported)

If the target program does not support SSLKEYLOGFILE (e.g. a compiled binary,
embedded system client, or custom TLS implementation), session keys must be
extracted manually from process memory using a debugger such as x64dbg.

The key log file format expected by TShark is:
  CLIENT_RANDOM <64-char hex client_random> <96-char hex master_secret>
One line per TLS session. Write this file then pass it as keylog_file=.

### General workflow (use the x64dbg MCP for steps 1-4)

1. Start a packet capture with capture_live() saving to a pcap file.
2. Attach x64dbg to the target process.
3. Identify which TLS library the process uses (check imports with get_imports()).
4. Set a breakpoint after the TLS handshake function returns, then read the
   key material from memory (see library-specific instructions below).
5. Write the extracted keys to a .log file in CLIENT_RANDOM format.
6. Stop the capture, then call follow_tls_stream() or analyze_pcap_file()
   with keylog_file= pointing at the .log file.

### OpenSSL / BoringSSL key extraction

Target function: SSL_connect, SSL_do_handshake, or ssl3_send_finished.
Set a breakpoint at the return of one of these functions.

When the breakpoint hits, the first argument (RCX on x64 Windows, RDI on Linux)
is a pointer to the SSL* struct. Read the following fields:

  SSL* layout (OpenSSL 1.1.x / 3.x, offsets may vary by version and build):
    SSL->s3->client_random   : 32 bytes (find via get_memory_map + read_memory)
    SSL->session->master_key : 48 bytes
    SSL->session->master_key_length : should be 48

  Use x64dbg MCP:
    - disassemble() to confirm you are at the right return site
    - get_registers() to get the SSL* pointer from RCX/RDI
    - read_memory(address, size) to dump client_random and master_key bytes
    - Format as: CLIENT_RANDOM {client_random_hex} {master_key_hex}

  To find exact offsets for the build being debugged:
    - Search for the string "master key" in .rodata with find_strings()
    - Or break on SSL_SESSION_get_master_key and inspect the return buffer

### Windows SChannel key extraction

Target function: ncrypt.dll!SslGenerateMasterKey or
                 schannel.dll!CSsl3TlsClientContext::GenerateMasterKey

When the breakpoint hits:
  - The master secret buffer pointer is usually in RDX or R8 (check disassembly)
  - client_random is in the handshake context struct (follow the this pointer)
  - read_memory() to extract both 32-byte client_random and 48-byte master_secret

### NSS (used by Firefox, curl on some platforms)

Target function: ssl3_SendClientHelloExtensions or tls13_DeriveSecret
  - Break on ssl3_InitState, then walk sslSocket->ssl3.hs to find secrets
  - For TLS 1.3 use EXPORTER_SECRET line format instead of CLIENT_RANDOM

### Writing the key log file from extracted bytes

After extracting bytes with read_memory(), format and write:
  CLIENT_RANDOM {bytes_to_hex(client_random_32)} {bytes_to_hex(master_key_48)}

Repeat for each TLS session captured. Then use follow_tls_stream() to verify
decryption succeeded.
"""


@mcp.tool()
def run_tshark_command(command_args: str) -> str:
    """
    Run a TShark command with the given arguments.

    Args:
        command_args: The command line arguments to pass to tshark

    Returns:
        The output of the tshark command
    """
    try:
        safe_args = command_args.replace('\\', '\\\\')
        result = _run(*shlex.split(safe_args), timeout=30)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def analyze_pcap_file(
    file_path: str,
    display_filter: Optional[str] = None,
    keylog_file: Optional[str] = None,
    max_packets: int = 100,
) -> str:
    """
    Analyze a PCAP file using TShark.

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional display filter to apply
        keylog_file: Optional path to a TLS key log file (SSLKEYLOGFILE) for
                     decrypting TLS/SSL traffic
        max_packets: Maximum number of packets to output (default 100)

    Returns:
        Packet analysis output
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    try:
        args = ["-r", file_path] + _tls_args(keylog_file)
        if display_filter:
            args.extend(["-Y", display_filter])
        args.extend(["-c", str(max_packets)])

        result = _run(*args)
        if result.returncode == 0:
            return result.stdout or "No packets found matching the criteria"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Analysis timed out"
    except FileNotFoundError as e:
        msg = str(e)
        return f"Error: {msg}" if "Key log file" in msg else _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def get_packet_statistics(file_path: str) -> str:
    """
    Get statistics about packets in a PCAP file.

    Args:
        file_path: Path to the PCAP file

    Returns:
        Packet statistics
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    try:
        result = _run("-r", file_path, "-q", "-z", "io,phs")
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Statistics generation timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def extract_packet_details(file_path: str, packet_number: int) -> str:
    """
    Extract detailed information about a specific packet.

    Args:
        file_path: Path to the PCAP file
        packet_number: The packet number to analyze (1-based)

    Returns:
        Detailed packet information
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    try:
        result = _run("-r", file_path, "-V", "-Y", f"frame.number == {packet_number}", timeout=30)
        if result.returncode == 0:
            return result.stdout or f"No packet found with number {packet_number}"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Packet extraction timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def list_interfaces() -> str:
    """
    List available network interfaces for capture.

    Returns:
        List of network interfaces
    """
    try:
        result = _run("-D", timeout=10)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def extract_fields(
    file_path: str,
    fields: str,
    display_filter: Optional[str] = None,
    keylog_file: Optional[str] = None,
) -> str:
    """
    Extract specific fields from packets in a PCAP file.

    Args:
        file_path: Path to the PCAP file
        fields: Comma-separated field names (e.g. "ip.src,ip.dst,tcp.port").
                Use "http.request.uri" or "tls.app_data" for decrypted content.
        display_filter: Optional display filter to apply
        keylog_file: Optional path to a TLS key log file for decrypting TLS traffic

    Returns:
        Tab-separated field values, one packet per line
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    try:
        args = ["-r", file_path] + _tls_args(keylog_file)
        args.extend(["-T", "fields"])
        for field in fields.split(","):
            field = field.strip()
            if field:
                args.extend(["-e", field])
        if display_filter:
            args.extend(["-Y", display_filter])

        result = _run(*args)
        if result.returncode == 0:
            return result.stdout or "No matching packets found"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Field extraction timed out"
    except FileNotFoundError as e:
        msg = str(e)
        return f"Error: {msg}" if "Key log file" in msg else _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def export_to_json(
    file_path: str,
    display_filter: Optional[str] = None,
    max_packets: int = 50,
    keylog_file: Optional[str] = None,
) -> str:
    """
    Export packets from a PCAP file as JSON for structured analysis.

    Args:
        file_path: Path to the PCAP file
        display_filter: Optional display filter to apply
        max_packets: Maximum number of packets to export (default 50)
        keylog_file: Optional path to a TLS key log file for decrypting TLS traffic

    Returns:
        JSON-formatted packet data (decrypted if keylog_file is provided)
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    try:
        args = ["-r", file_path] + _tls_args(keylog_file)
        args.extend(["-T", "json", "-c", str(max_packets)])
        if display_filter:
            args.extend(["-Y", display_filter])

        result = _run(*args)
        if result.returncode == 0:
            return result.stdout or "No matching packets found"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: JSON export timed out"
    except FileNotFoundError as e:
        msg = str(e)
        return f"Error: {msg}" if "Key log file" in msg else _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def get_conversations(file_path: str, protocol: str = "tcp") -> str:
    """
    Get conversation statistics from a PCAP file.

    Args:
        file_path: Path to the PCAP file
        protocol: Protocol to analyze - one of: eth, ip, tcp, udp, sctp (default: tcp)

    Returns:
        Conversation statistics table
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    allowed = {"eth", "ip", "tcp", "udp", "sctp"}
    if protocol not in allowed:
        return f"Error: protocol must be one of {sorted(allowed)}"

    try:
        result = _run("-r", file_path, "-q", "-z", f"conv,{protocol}")
        if result.returncode == 0:
            return result.stdout or "No conversations found"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Conversation analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def follow_stream(
    file_path: str,
    protocol: str,
    stream_index: int = 0,
    keylog_file: Optional[str] = None,
) -> str:
    """
    Follow and reconstruct a TCP or UDP stream.

    Args:
        file_path: Path to the PCAP file
        protocol: Stream protocol - "tcp", "udp", or "sctp"
        stream_index: Stream index to follow (default: 0, the first stream)
        keylog_file: Optional path to a TLS key log file. When provided, use
                     follow_tls_stream instead for decrypted TLS content.

    Returns:
        Reconstructed stream content as ASCII text
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"

    if protocol not in ("tcp", "udp", "sctp"):
        return "Error: protocol must be 'tcp', 'udp', or 'sctp'"

    try:
        args = ["-r", file_path] + _tls_args(keylog_file)
        args.extend(["-q", "-z", f"follow,{protocol},ascii,{stream_index}"])

        result = _run(*args)
        if result.returncode == 0:
            return result.stdout or f"No stream {stream_index} found"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Stream follow timed out"
    except FileNotFoundError as e:
        msg = str(e)
        return f"Error: {msg}" if "Key log file" in msg else _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def follow_tls_stream(
    file_path: str,
    keylog_file: str,
    stream_index: int = 0,
) -> str:
    """
    Follow and reconstruct a decrypted TLS stream as plaintext.

    Requires a TLS key log file (SSLKEYLOGFILE). To generate one:
      - Chrome/Edge: launch with --ssl-key-log-file=C:/path/keys.log
      - Firefox: set environment variable SSLKEYLOGFILE=C:/path/keys.log
      - Python requests/httpx: set SSLKEYLOGFILE env var before running

    Args:
        file_path: Path to the PCAP file containing TLS traffic
        keylog_file: Path to the TLS key log file (SSLKEYLOGFILE format)
        stream_index: TLS stream index to follow (default: 0, the first stream)

    Returns:
        Decrypted TLS stream content as ASCII plaintext
    """
    if not Path(file_path).exists():
        return f"Error: File {file_path} does not exist"
    if not Path(keylog_file).exists():
        return f"Error: Key log file {keylog_file} does not exist"

    try:
        result = _run(
            "-r", file_path,
            "-o", f"tls.keylog_file:{keylog_file}",
            "-q",
            "-z", f"follow,tls,ascii,{stream_index}",
        )
        if result.returncode == 0:
            return result.stdout or f"No TLS stream {stream_index} found (check keylog file covers this session)"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Stream follow timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def capture_live(
    interface: str,
    packet_count: int = 50,
    display_filter: Optional[str] = None,
    duration: int = 10,
) -> str:
    """
    Capture live packets from a network interface.

    Args:
        interface: Network interface name (use list_interfaces to find names)
        packet_count: Number of packets to capture (default: 50, max: 500)
        display_filter: Optional display filter to apply
        duration: Maximum capture duration in seconds (default: 10, max: 60)

    Returns:
        Captured packet summary
    """
    packet_count = max(1, min(packet_count, 500))
    duration = max(1, min(duration, 60))

    args = ["-i", interface, "-c", str(packet_count), "-a", f"duration:{duration}"]
    if display_filter:
        args.extend(["-Y", display_filter])

    try:
        result = _run(*args, timeout=duration + 5)
        if result.returncode == 0:
            return result.stdout or "No packets captured"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Capture timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def capture_and_decrypt(
    interface: str,
    keylog_file: str,
    output_pcap: str,
    packet_count: int = 200,
    duration: int = 30,
    display_filter: Optional[str] = None,
) -> str:
    """
    Capture live TLS traffic and immediately show decrypted plaintext.

    This tool saves the capture to a PCAP file and then decrypts it using the
    provided TLS key log file. The application generating traffic must write its
    session keys to keylog_file during capture (set SSLKEYLOGFILE env var before
    launching Chrome, Firefox, curl, Python, etc.).

    Workflow:
      1. Set SSLKEYLOGFILE=C:/path/keys.log before launching the target app
      2. Call this tool pointing at the same keys.log
      3. Browse or make HTTPS requests in the target app
      4. The tool returns decrypted HTTP/application data

    Args:
        interface: Network interface to capture on (from list_interfaces)
        keylog_file: Path to the TLS key log file written by the target app
        output_pcap: Path where the captured PCAP will be saved for later analysis
        packet_count: Number of packets to capture (default: 200, max: 500)
        duration: Capture duration in seconds (default: 30, max: 60)
        display_filter: Optional display filter (e.g. "tls" or "tcp.port == 443")

    Returns:
        Summary of captured packets and decrypted TLS stream content
    """
    if not Path(keylog_file).exists():
        return f"Error: Key log file {keylog_file} does not exist"

    packet_count = max(1, min(packet_count, 500))
    duration = max(1, min(duration, 60))

    # Step 1: capture to pcap
    cap_args = [
        "-i", interface,
        "-c", str(packet_count),
        "-a", f"duration:{duration}",
        "-w", output_pcap,
    ]
    try:
        cap_result = _run(*cap_args, timeout=duration + 10)
        if cap_result.returncode != 0:
            return f"Error during capture: {cap_result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Capture timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"

    if not Path(output_pcap).exists():
        return "Error: Capture produced no output file"

    # Step 2: show packet summary with decryption
    summary_args = ["-r", output_pcap, "-o", f"tls.keylog_file:{keylog_file}"]
    if display_filter:
        summary_args.extend(["-Y", display_filter])

    try:
        summary = _run(*summary_args)
        summary_text = summary.stdout if summary.returncode == 0 else f"(summary error: {summary.stderr})"

        # Step 3: discover all unique TLS stream indices, then follow non-empty ones
        idx_result = _run(
            "-r", output_pcap,
            "-o", f"tls.keylog_file:{keylog_file}",
            "-T", "fields",
            "-e", "tls.stream",
        )
        seen: set[int] = set()
        stream_indices: list[int] = []
        for line in idx_result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                val = int(line)
                if val not in seen:
                    seen.add(val)
                    stream_indices.append(val)
        stream_indices.sort()

        streams: list[str] = []
        for idx in stream_indices[:10]:  # cap at 10 streams
            s = _run(
                "-r", output_pcap,
                "-o", f"tls.keylog_file:{keylog_file}",
                "-q",
                "-z", f"follow,tls,ascii,{idx}",
            )
            # "Node 0: :0" means the stream index exists but has no decrypted data
            if s.returncode == 0 and s.stdout.strip() and "Node 0: :0" not in s.stdout:
                streams.append(f"--- TLS Stream {idx} ---\n{s.stdout.strip()}")

        decrypted = "\n\n".join(streams) if streams else "(no decryptable TLS streams found)"
        return f"=== Capture Summary ===\n{summary_text}\n\n=== Decrypted TLS Content ===\n{decrypted}"

    except subprocess.TimeoutExpired:
        return "Error: Decryption timed out"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def filter_and_save(input_file: str, output_file: str, display_filter: str) -> str:
    """
    Filter packets from a PCAP file and save the result to a new PCAP file.

    Args:
        input_file: Path to the source PCAP file
        output_file: Path where the filtered PCAP will be saved
        display_filter: Display filter to select packets (e.g. "tcp.port == 80")

    Returns:
        Status message with packet count written
    """
    if not Path(input_file).exists():
        return f"Error: File {input_file} does not exist"

    try:
        result = _run("-r", input_file, "-Y", display_filter, "-w", output_file)
        if result.returncode == 0:
            count_result = _run("-r", output_file, "-q", timeout=30)
            return f"Saved to {output_file}\n{count_result.stderr.strip()}"
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Filter and save timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


def _get_process_connections(pid: int) -> tuple[set[int], set[str]]:
    """
    Return (local_ports, remote_ips) for the given process.

    Uses platform-native tools:
      Windows  — netstat -ano
      macOS    — lsof -i -P -n -p <pid>
      Linux    — ss -tnup (filtered by pid)

    Returns empty sets if the process has no open connections or the
    platform tool is unavailable.
    """
    local_ports: set[int] = set()
    remote_ips: set[str] = set()
    try:
        if sys.platform == "win32":
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                # TCP:  Proto  Local  Foreign  State  PID
                # UDP:  Proto  Local  Foreign        PID
                if not parts or parts[-1] != str(pid):
                    continue
                # local port
                m = re.search(r":(\d+)$", parts[1])
                if m:
                    p = int(m.group(1))
                    if p > 0:
                        local_ports.add(p)
                # remote IP (IPv4 or IPv6)
                if len(parts) >= 3:
                    m2 = re.search(r"^(.*?):(\d+)$", parts[2])
                    if m2:
                        ip = m2.group(1).strip("[]")
                        port = m2.group(2)
                        if ip not in ("0.0.0.0", "127.0.0.1", "::", "::1", "*") and port != "0":
                            remote_ips.add(ip)
        elif sys.platform == "darwin":
            r = subprocess.run(
                ["lsof", "-i", "-P", "-n", "-p", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                # connected: IP:PORT->IP:PORT
                m = re.search(
                    r"(.*?):(\d+)->(.*?):(\d+)", line
                )
                if m:
                    local_ports.add(int(m.group(2)))
                    remote_ips.add(m.group(3).strip("[]"))
                else:
                    # listening: *:PORT (LISTEN)
                    m2 = re.search(r"\*:(\d+)\s+\(LISTEN\)", line)
                    if m2:
                        local_ports.add(int(m2.group(1)))
        else:
            # Linux
            r = subprocess.run(
                ["ss", "-tnup"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                if f"pid={pid}," not in line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                # Local Address:Port  Peer Address:Port
                m = re.search(r":(\d+)$", parts[3])
                if m:
                    p = int(m.group(1))
                    if p > 0:
                        local_ports.add(p)
                m2 = re.search(r"^(.*?):(\d+)$", parts[4])
                if m2:
                    ip = m2.group(1).strip("[]")
                    if ip not in ("0.0.0.0", "127.0.0.1", "::", "::1", "*"):
                        remote_ips.add(ip)
    except Exception:
        pass
    return local_ports, remote_ips


@mcp.tool()
def list_processes(name_filter: Optional[str] = None) -> str:
    """
    List running processes with their PIDs.

    Use this to find the PID to pass to capture_process.

    Args:
        name_filter: Optional substring to filter process names (case-insensitive).
                     E.g. "chrome" or "python".

    Returns:
        Table of PID and process name for matching processes.
    """
    try:
        if sys.platform == "win32":
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            rows = []
            for parts in csv.reader(r.stdout.strip().splitlines()):
                if len(parts) >= 2:
                    name, pid = parts[0], parts[1]
                    if not name_filter or name_filter.lower() in name.lower():
                        rows.append(f"{pid:>8}  {name}")
            if not rows:
                return "No matching processes found"
            return "     PID  Name\n" + "\n".join(rows)
        else:
            r = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=15,
            )
            if name_filter:
                lines = [
                    ln for ln in r.stdout.splitlines()
                    if ln.startswith("USER") or name_filter.lower() in ln.lower()
                ]
                return "\n".join(lines) or "No matching processes found"
            return r.stdout or "No processes found"
    except subprocess.TimeoutExpired:
        return "Error: Process listing timed out"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def capture_process(
    pid: int,
    interface: str,
    output_pcap: str,
    duration: int = 30,
    packet_count: int = 200,
    keylog_file: Optional[str] = None,
) -> str:
    """
    Capture network traffic from a specific process by its PID.

    Snapshots the process's active connections at the moment capture starts,
    builds a BPF filter from those local ports, and captures only the matching
    traffic.  New connections opened after capture starts share the same ports
    and are included automatically.

    Use list_processes() to find the PID, and list_interfaces() to find the
    interface name.

    Args:
        pid: Process ID to capture traffic for.
        interface: Network interface to capture on (from list_interfaces).
        output_pcap: Path where the captured PCAP will be saved.
        duration: Capture duration in seconds (default: 30, max: 60).
        packet_count: Maximum packets to capture (default: 200, max: 500).
        keylog_file: Optional TLS key log file path (SSLKEYLOGFILE format).
                     When provided, decrypted TLS stream content is included
                     in the output.  The file must exist before calling this.

    Returns:
        Capture summary showing detected connections, packet list, and
        (when keylog_file is supplied) decrypted TLS stream content.
    """
    if keylog_file and not Path(keylog_file).exists():
        return f"Error: Key log file {keylog_file} does not exist"

    duration = max(1, min(duration, 60))
    packet_count = max(1, min(packet_count, 500))

    # --- Step 1: discover the process's open ports ---
    local_ports, remote_ips = _get_process_connections(pid)
    port_list = sorted(local_ports - {0})

    info_lines: list[str] = []
    if port_list:
        info_lines.append(
            f"PID {pid} — {len(port_list)} active local port(s): "
            + ", ".join(str(p) for p in port_list)
        )
    else:
        info_lines.append(
            f"PID {pid} — no active connections found; capturing all traffic on interface"
        )
    if remote_ips:
        info_lines.append("Remote IPs: " + ", ".join(sorted(remote_ips)))
    conn_info = "\n".join(info_lines)

    # --- Step 2: build BPF capture filter from local ports ---
    bpf = " or ".join(f"port {p}" for p in port_list) if port_list else None

    # --- Step 3: capture to pcap ---
    cap_args = [
        "-i", interface,
        "-c", str(packet_count),
        "-a", f"duration:{duration}",
        "-w", output_pcap,
    ]
    if bpf:
        cap_args.extend(["-f", bpf])

    try:
        cap_result = _run(*cap_args, timeout=duration + 10)
        if cap_result.returncode != 0:
            return f"Error during capture: {cap_result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Capture timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"

    if not Path(output_pcap).exists():
        return "Error: Capture produced no output file"

    # --- Step 4: analyse ---
    tls_args = _tls_args(keylog_file) if keylog_file else []
    try:
        summary_args = ["-r", output_pcap] + tls_args + ["-c", "100"]
        summary = _run(*summary_args)
        summary_text = (
            summary.stdout.strip()
            if summary.returncode == 0
            else f"(summary error: {summary.stderr})"
        )

        parts = [
            "=== Process Capture ===",
            conn_info,
            "",
            "=== Packet Summary ===",
            summary_text or "(no packets captured)",
        ]

        if keylog_file:
            # Discover all TLS stream indices then follow non-empty ones
            idx_result = _run(
                "-r", output_pcap,
                "-o", f"tls.keylog_file:{keylog_file}",
                "-T", "fields", "-e", "tls.stream",
            )
            seen: set[int] = set()
            stream_indices: list[int] = []
            for line in idx_result.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    val = int(line)
                    if val not in seen:
                        seen.add(val)
                        stream_indices.append(val)
            stream_indices.sort()

            streams: list[str] = []
            for idx in stream_indices[:10]:
                s = _run(
                    "-r", output_pcap,
                    "-o", f"tls.keylog_file:{keylog_file}",
                    "-q", "-z", f"follow,tls,ascii,{idx}",
                )
                if s.returncode == 0 and s.stdout.strip() and "Node 0: :0" not in s.stdout:
                    streams.append(f"--- TLS Stream {idx} ---\n{s.stdout.strip()}")

            decrypted = "\n\n".join(streams) if streams else "(no decryptable TLS streams found)"
            parts += ["", "=== Decrypted TLS Content ===", decrypted]

        return "\n".join(parts)

    except subprocess.TimeoutExpired:
        return "Error: Analysis timed out"
    except Exception as e:
        return f"Error: {str(e)}"


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

        flows: dict[tuple[str, str], list[int]] = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
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
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            qname, is_response, resp_time, resp_name, rcode = parts[:5]

            if is_response == "0":
                query_count += 1
                if qname:
                    domain_counts[qname] = domain_counts.get(qname, 0) + 1
            elif is_response == "1":
                response_count += 1
                if resp_time:
                    try:
                        response_times.append(float(resp_time))
                    except ValueError:
                        pass
                if rcode == "3" and qname:
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
            parts = line.split("\t")
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
            parts = line.split("\t")
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

    Typical protocol stack: SCTP -> M3UA -> SCCP -> TCAP -> MAP

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

        otid_to_dialogue: dict[str, list[dict]] = {}
        dtid_to_otid: dict[str, str] = {}

        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            ts, msg_type, otid, dtid, invoke_id, map_op = parts[:6]
            otid = otid.strip()
            dtid = dtid.strip()

            dialogue_key = None
            if otid and otid not in dtid_to_otid:
                if otid not in otid_to_dialogue:
                    otid_to_dialogue[otid] = []
                dialogue_key = otid
            if dtid and dtid in otid_to_dialogue:
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

    Typical protocol stack: SCTP -> M3UA -> SCCP -> TCAP -> MAP

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
            parts = line.split("\t")
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
                ops_str = ", ".join(
                    f"{op}:{n}" for op, n in sorted(ops.items(), key=lambda x: x[1], reverse=True)[:3]
                )
                lines.append(f"  IMSI {imsi}  ({total_imsi} msgs)  [{ops_str}]")

        return "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: MAP analysis timed out"
    except FileNotFoundError:
        return _NOT_FOUND_MSG
    except Exception as e:
        return f"Error: {str(e)}"


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


if __name__ == "__main__":
    mcp.run()
