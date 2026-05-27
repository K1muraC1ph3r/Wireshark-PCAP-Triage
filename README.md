# Wireshark PCAP Triage

```
██████╗  ██████╗ █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗     TRIAGE
██████╔╝██║     ███████║██████╔╝     v2.0
██╔═══╝ ██║     ██╔══██║██╔═══╝                       |\
██║     ╚██████╗██║  ██║██║                        ___|_\___
╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝                   ~~~~~~~~~~~~~~~~~~
```

Automated PCAP anomaly triage with packet-level evidence. Runs a battery of detection checks against a packet capture file using `tshark`, surfaces suspicious activity with severity rankings, and attaches sample packets (source/destination IPs, timestamps, URIs, query names) directly to each finding so the analyst can pivot to investigation without re-running queries.

---

## Table of Contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [What it detects](#what-it-detects)
- [Output structure](#output-structure)
- [Example output](#example-output)
- [Reading the findings](#reading-the-findings)
- [Exit codes](#exit-codes)
- [Tuning thresholds](#tuning-thresholds)
- [Limitations](#limitations)

---

## Why this exists

Wireshark and `tshark` are excellent for deep-dive packet analysis, but answering the question *"is there anything in this pcap worth investigating?"* still requires running dozens of display filters by hand. This tool automates that triage pass.

Unlike a full IDS (Suricata, Zeek), this is a **forensic triage tool** designed to:

- Run against existing pcap files
- Surface anomalies fast with severity rankings
- Provide enough evidence per finding to start investigation immediately
- Hand off to Wireshark for deep work (every finding includes the exact filter that produced it)

It is not a live-monitoring IDS, signature engine, or alerting platform.

---

## Features

- **Severity-ranked findings** (HIGH / MEDIUM / LOW) across DNS, HTTP, FTP, Kerberos, SMB, ICMP, ARP, TCP, and Telnet
- **Packet-level evidence** attached to every finding — frame number, ISO timestamp, full 5-tuple, and protocol-specific details (URI, query name, User-Agent, etc.)
- **Top Offenders cross-reference** — source IPs ranked across all findings, with multi-vector activity flagged
- **Reproducible** — every finding includes the exact Wireshark display filter that produced it
- **Multiple output formats** — colored terminal output (default), Markdown, JSON
- **Reference data section** — protocol hierarchy, conversation tables, URLs, DNS domains, TLS SNIs for situational awareness
- **Zero Python dependencies** — standard library only

---

## Requirements

| Component | Notes |
|-----------|-------|
| Python 3.9+ | Uses `list[str]` / `dict[k,v]` PEP 585 generics |
| `tshark` | Wireshark's CLI; tool shells out to it for all packet operations |
| Linux/macOS | Tested on Kali and Ubuntu; should work anywhere `tshark` does |

---

## Installation

### Ubuntu / Debian

```bash
sudo apt install tshark
git clone https://github.com/K1muraC1ph3r/Wireshark-PCAP-Triage.git
cd Wireshark-PCAP-Triage
chmod +x pcap_triage.py
```

### Kali Linux

```bash
sudo apt install wireshark-cli   # tshark is in this package on Kali
git clone https://github.com/K1muraC1ph3r/Wireshark-PCAP-Triage.git
cd Wireshark-PCAP-Triage
chmod +x pcap_triage.py
```

No `pip install` needed — stdlib only.

---

## Usage

### Basic

```bash
./pcap_triage.py capture.pcap
```

### With report outputs

```bash
./pcap_triage.py capture.pcap --md report.md
./pcap_triage.py capture.pcap --json report.json
./pcap_triage.py capture.pcap --md report.md --json report.json
```

### Tune evidence sample size

```bash
./pcap_triage.py capture.pcap --evidence 25
```

Default is 10 evidence packets per finding. Higher values produce fuller forensic reports at the cost of report size.

### Skip ASCII banners (cleaner for piping)

```bash
./pcap_triage.py capture.pcap --no-banner
```

### All options

```
positional arguments:
  pcap                 Path to the pcap file to analyze

options:
  -h, --help           show this help message and exit
  --json PATH          Write JSON report to the given path
  --md PATH            Write Markdown report to the given path
  --evidence N         Max evidence packets per finding (default: 10)
  --no-banner          Skip ASCII banners in terminal output
```

---

## What it detects

| Category | Detection | Severity |
|----------|-----------|----------|
| **DNS** | Query names > 100 chars (near-certain tunneling) | HIGH |
| | Query names 50-100 chars (possible tunneling) | MEDIUM |
| | NXDOMAIN burst (DGA indicator) | MEDIUM |
| | TXT record abuse (tunneling tool favorite) | MEDIUM |
| | NULL record queries (essentially always malicious) | HIGH |
| | dnscat2 string fingerprint | HIGH |
| **HTTP** | Scanner User-Agents (sqlmap, nikto, nmap, ffuf, gobuster, etc.) | HIGH |
| | Empty User-Agent (automation marker) | LOW |
| | SQLi payloads (`union`, `'or`, `1=1`, etc.) | HIGH |
| | XSS payloads (`<script`, `alert(`, `onerror`, etc.) | HIGH |
| | RCE payloads (`cmd=`, `exec(`, `/bin/sh`, `powershell`) | HIGH |
| | Path traversal (`../` in URI) | HIGH |
| | Webshell URIs (`shell.php`, `c99`, `r57`, etc.) | HIGH |
| | Directory brute force (404 burst) | MEDIUM |
| | Credential brute force (401 burst) | MEDIUM |
| | HTTP Basic auth (cleartext credentials) | MEDIUM |
| **FTP** | Failed-login burst (brute force) | MEDIUM |
| | Cleartext usernames | LOW |
| | Cleartext passwords | MEDIUM |
| | Anonymous login attempts | LOW |
| | File uploads via STOR | LOW |
| **Kerberos** | RC4 etype 23 (Kerberoasting / AS-REP roasting) | HIGH |
| | KRB-ERROR burst (preauth probing / enumeration) | MEDIUM |
| **SMB** | Access to C$ / ADMIN$ admin shares | HIGH |
| | Access to IPC$ | MEDIUM |
| **ICMP** | Oversized payloads (tunneling indicator) | HIGH |
| | Ping sweep (one source -> many destinations) | MEDIUM |
| | ICMP Redirect (MITM indicator) | HIGH |
| **ARP** | Cache poisoning (one IP claimed by multiple MACs) | HIGH |
| **TCP** | SYN scan (many ports from one source) | HIGH |
| | NULL scan (evasion technique) | HIGH |
| | XMAS scan (evasion technique) | HIGH |
| **Telnet** | Any usage (cleartext protocol exposure) | MEDIUM |

---

## Output structure

Every report has three sections in this order:

### 1. Findings

Severity-ranked alerts. Each finding includes:

- Severity tag and category
- One-line description (with top source IP embedded for brute force / scanner findings)
- Free-text evidence (e.g. sample ports for a scan, conflicting MACs for ARP poisoning)
- Sample evidence packets with frame number, timestamp, 5-tuple, and protocol-specific fields
- The exact Wireshark filter that produced the finding

### 2. Top Offenders

Source IPs aggregated across **all** findings, ranked by hit count. The number of distinct categories each IP appears in is shown alongside — an IP showing up in 3+ categories (e.g. port scan + brute force + SQLi) is flagged as multi-vector activity and gets visual emphasis.

This is the "where do I start" view when many findings fire.

### 3. Reference Data

Contextual pcap content — not flagged as alerts, but useful for situational awareness:

- Protocol hierarchy (what's in the pcap by volume)
- IPv4 / TCP / UDP conversation tables
- IP endpoints
- HTTP URLs (top 50) and Host headers (top 30)
- DNS domains queried (top 30)
- TLS SNI values (top 30) — visible even on HTTPS
- Kerberos accounts seen (users vs. machine accounts)

---

## Example output

### Terminal — a finding with embedded evidence

```
[MEDIUM] http-bruteforce: 487 HTTP 401 responses — likely auth brute force — top source: 192.168.1.50 (10 of 10 samples)
     evidence (showing 10 of 487):
       #1247  2026-05-27T14:23:11+00:00  192.168.1.50:54321 -> 10.0.0.5:80  uri=/admin host=target.local
       #1289  2026-05-27T14:23:11+00:00  192.168.1.50:54322 -> 10.0.0.5:80  uri=/admin host=target.local
       #1334  2026-05-27T14:23:12+00:00  192.168.1.50:54323 -> 10.0.0.5:80  uri=/login host=target.local
       ...
     filter: http.response.code == 401
```

### Terminal — Top Offenders block

```
  HITS    CATEGORIES                       SOURCE IP
  ------  ----------                       ---------------
      23  4                                192.168.1.50
          http-bruteforce, http-scanner, http-sqli, tcp-portscan
      18  2                                10.0.0.42
          http-bruteforce, http-automation
      11  1                                172.16.99.7
          dns-dga
```

The category count is colored red when 3+ — that's your multi-vector signal.

### JSON output (excerpt)

```json
{
  "pcap": "capture.pcap",
  "analyzed_at": "2026-05-27T14:30:00+00:00",
  "total_packets": 48291,
  "summary": {"HIGH": 4, "MEDIUM": 3, "LOW": 2},
  "top_offenders": [
    {"src_ip": "192.168.1.50", "hits": 23, "categories": ["http-bruteforce", "http-scanner", "http-sqli", "tcp-portscan"]}
  ],
  "findings": [
    {
      "severity": "MEDIUM",
      "category": "http-bruteforce",
      "message": "487 HTTP 401 responses — likely auth brute force — top source: 192.168.1.50 (10 of 10 samples)",
      "wireshark_filter": "http.response.code == 401",
      "total_packet_count": 487,
      "evidence_packets": [
        {
          "frame_number": "1247",
          "timestamp": "2026-05-27T14:23:11.123456+00:00",
          "src_ip": "192.168.1.50",
          "dst_ip": "10.0.0.5",
          "src_port": "54321",
          "dst_port": "80",
          "details": {"uri": "/admin", "host": "target.local"}
        }
      ]
    }
  ]
}
```

---

## Reading the findings

### Severity meanings

| Level | Meaning |
|-------|---------|
| **HIGH** | Active attack indicator or confirmed malicious activity. Investigate immediately. |
| **MEDIUM** | Suspicious activity warranting investigation — reconnaissance, brute force, weak protocols creating exposure. |
| **LOW** | Notable but expected — cleartext protocols in use, automation markers. Useful for posture review but not "drop everything" material. |

### Traffic direction caveats

Some findings reference *server responses* (HTTP 401, HTTP 404, FTP 530). In these packets, `src_ip` is the **server**, not the attacker — the attacker is at `dst_ip`. This is called out in the relevant detection functions, but worth knowing when reading evidence packets.

The Top Offenders aggregation does not currently distinguish, so a high-volume brute force will surface the target server in the rankings alongside the actual attacker. Use the evidence packets to confirm direction.

### Pivoting to Wireshark

Every finding ends with a `filter:` line containing a valid Wireshark display filter. Copy it into Wireshark's filter bar to see all matching packets, not just the evidence sample. Use **Go to Packet** (Ctrl+G) with the frame number from any evidence row to jump directly to a specific packet.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully, no HIGH-severity findings |
| `1` | Input file not found or other startup error |
| `2` | Completed successfully, but HIGH-severity findings present |

Useful for CI/automation pipelines that need to react to severity without parsing the report:

```bash
./pcap_triage.py capture.pcap --json report.json
if [ $? -eq 2 ]; then
    echo "HIGH-severity findings detected, escalating..."
    # forward report.json downstream
fi
```

---

## Tuning thresholds

All detection thresholds are named constants at the top of the script under the `CONSTANTS — DETECTION THRESHOLDS` section. Edit there to adjust for your environment — each has a comment explaining its rationale.

| Constant | Default | What it controls |
|----------|---------|------------------|
| `DNS_NAME_LEN_SUSPICIOUS` | 50 | Lower bound for "possible tunneling" |
| `DNS_NAME_LEN_CERTAIN` | 100 | Lower bound for "near-certain tunneling" |
| `DNS_NXDOMAIN_THRESHOLD` | 20 | NXDOMAIN count triggering DGA alert |
| `DNS_TXT_QUERY_THRESHOLD` | 50 | TXT query count triggering tunneling alert |
| `HTTP_BRUTEFORCE_404_THRESHOLD` | 50 | 404 count for directory brute force |
| `HTTP_BRUTEFORCE_401_THRESHOLD` | 20 | 401 count for credential brute force |
| `HTTP_EMPTY_UA_THRESHOLD` | 10 | Empty User-Agent count for automation flag |
| `FTP_BRUTEFORCE_THRESHOLD` | 5 | Failed FTP login count for brute force |
| `ICMP_PAYLOAD_SUSPICIOUS_BYTES` | 100 | ICMP payload size triggering tunneling alert |
| `ICMP_PING_SWEEP_DESTINATIONS` | 10 | Distinct destinations per source for sweep |
| `TCP_PORTSCAN_PORT_THRESHOLD` | 20 | Distinct ports per source for port scan |
| `KERBEROS_PREAUTH_ERROR_THRESHOLD` | 10 | KRB-ERROR count for enumeration alert |
| `DEFAULT_EVIDENCE_SAMPLE` | 10 | Packets per finding (CLI-overridable) |
| `TOP_OFFENDERS_COUNT` | 10 | How many offenders to display in summary |
| `TSHARK_TIMEOUT_SECONDS` | 300 | Per-query tshark timeout |

---

## Limitations

- **Not a live IDS.** Operates on existing pcap files. For live monitoring, see Suricata or Zeek.
- **Each detection makes 2 tshark calls** (count + evidence extraction). Large pcaps (multi-GB) will be slow. Consider pre-filtering with `editcap` or `tcpdump` if performance becomes an issue.
- **SMB null-session detection uses an SMB1 filter** (`smb.account == ""`). Will not catch SMB2/3 null sessions. Most environments are SMB2+ in 2026.
- **Encrypted traffic is mostly opaque.** TLS SNI is visible (and collected), but anything inside TLS requires decryption keys not within this tool's scope.
- **Detection logic is hand-maintained** — no signature feed. Update patterns in `SCANNER_USER_AGENTS`, `SQLI_URI_PATTERNS`, `WEBSHELL_URI_PATTERNS`, etc. as threats evolve.
- **Top Offenders aggregation includes server IPs** for response-based findings (HTTP 401/404, FTP 530). Cross-reference with evidence packets to confirm attacker direction.
- **DNS domain aggregation uses a naive last-two-labels heuristic** — oversimplifies for ccTLDs like `example.co.uk` (which becomes `co.uk`). Acceptable for triage; not authoritative.

---
