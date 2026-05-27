#!/usr/bin/env python3
"""
pcap_triage.py — Automated PCAP anomaly triage.

Runs a battery of detection checks against a packet capture file and surfaces
anomalies for analyst review. Output is structured in two sections:

    1. FINDINGS  — actionable alerts (HIGH / MEDIUM / LOW severity)
    2. REFERENCE — contextual data dump (conversations, URLs, hosts, etc.)

The tool wraps `tshark` (the Wireshark CLI) via subprocess. We chose tshark
over pyshark/scapy because:
    1. tshark is already installed wherever Wireshark is
    2. It's battle-tested on huge captures where Python parsers can choke
    3. Its display-filter syntax matches what the analyst sees in Wireshark,
       making findings reproducible by hand

Usage:
    ./pcap_triage.py capture.pcap
    ./pcap_triage.py capture.pcap --md report.md
    ./pcap_triage.py capture.pcap --json report.json
    ./pcap_triage.py capture.pcap --no-banner   # skip ASCII art

Requires:
    tshark (apt install wireshark-cli)
    Python 3.9+
"""

# ============================================================================
# IMPORTS
# ============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ============================================================================
# CONSTANTS — ASCII BANNERS
# ============================================================================
# Raw multi-line strings for branding output. Kept up here so they're easy
# to swap without hunting through the code.

# Top banner: block-letter title with a small shark fin cutting through
# water on the right. Clean, recognizable, renders well anywhere.
BANNER_TOP = r"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗  ██████╗ █████╗ ██████╗                                ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗     TRIAGE                    ║
║   ██████╔╝██║     ███████║██████╔╝     v1.0                      ║
║   ██╔═══╝ ██║     ██╔══██║██╔═══╝                                ║
║   ██║     ╚██████╗██║  ██║██║                       |\           ║
║   ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝                    ___|_\___       ║
║                                              ~~~~~~~~~~~~~~~~~~  ║
╚══════════════════════════════════════════════════════════════════╝
"""

# Separator banner: multiple shark fins cutting through water. Marks the
# boundary between the FINDINGS section (alerts) and the REFERENCE DATA
# section (raw pcap contents). The caption tells the analyst anything
# past this point is context, not an alert.
BANNER_SHARK = r"""
  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │                    REFERENCE DATA                        │
  │                                                          │
  │     contextual pcap content — not flagged as alerts      │
  │                                                          │
  │       |\         |\         |\         |\                │
  │    ___|_\______ _|_\______ _|_\______ _|_\___            │
  │   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~            │
  │                                                          │
  └──────────────────────────────────────────────────────────┘
"""

# Clean-result banner: shown when no findings are detected. A reassuring
# "all clear" message so the analyst doesn't have to hunt the report
# wondering if the checks ran.
BANNER_CLEAN = r"""
        ┌─────────────────────────────────────────────────────┐
        │                                                     │
        │   ✓  NO FINDINGS DETECTED — PCAP APPEARS CLEAN      │
        │                                                     │
        │       Reference data below for situational          │
        │       awareness and manual review.                  │
        │                                                     │
        └─────────────────────────────────────────────────────┘
"""

# Findings-detected banner: shown when alerts were raised. Visual cue
# that something needs analyst attention before reading further.
BANNER_FINDINGS = r"""
        ┌─────────────────────────────────────────────────────┐
        │                                                     │
        │   ⚠  FINDINGS DETECTED — REVIEW BELOW IMMEDIATELY   │
        │                                                     │
        └─────────────────────────────────────────────────────┘
"""


# ============================================================================
# CONSTANTS — DETECTION THRESHOLDS
# ============================================================================
# Thresholds are named and grouped here so they're easy to tune without
# hunting through detection logic. Each has a comment explaining the
# rationale — change them with intent, not by guessing.

# --- DNS thresholds ---------------------------------------------------------
# Normal DNS query names average 15–30 characters. Anything above 50 is
# unusual; above 100 is essentially diagnostic of tunneling (dnscat2,
# iodine, dnsexfiltrator all push close to the 253-char DNS protocol max).
DNS_NAME_LEN_SUSPICIOUS: int = 50
DNS_NAME_LEN_CERTAIN: int = 100

# Tunneling tools favor TXT and MX records because they allow arbitrary
# data in responses. Normal clients make a handful; tunneling generates
# thousands.
DNS_TXT_QUERY_THRESHOLD: int = 50

# NXDOMAIN bursts indicate a Domain Generation Algorithm — malware
# cycling through computed domain names trying to reach its C2.
DNS_NXDOMAIN_THRESHOLD: int = 20

# --- HTTP thresholds --------------------------------------------------------
# Directory brute-forcers (gobuster, ffuf, dirb) produce hundreds of 404s.
HTTP_BRUTEFORCE_404_THRESHOLD: int = 50

# Credential brute force against a protected resource produces 401s.
HTTP_BRUTEFORCE_401_THRESHOLD: int = 20

# Automation often omits the User-Agent header. A handful is normal noise;
# above this count it's worth knowing who's scripting against us.
HTTP_EMPTY_UA_THRESHOLD: int = 10

# --- FTP thresholds ---------------------------------------------------------
# 530 responses are failed logins. More than a few from one source is
# brute force.
FTP_BRUTEFORCE_THRESHOLD: int = 5

# --- ICMP thresholds --------------------------------------------------------
# Standard ping payloads are 32–64 bytes. Substantially larger payloads
# are a hallmark of ICMP tunneling tools (icmpsh, ptunnel, icmpdoor).
ICMP_PAYLOAD_SUSPICIOUS_BYTES: int = 100

# A single source pinging more than this many distinct hosts is doing
# host discovery (ping sweep).
ICMP_PING_SWEEP_DESTINATIONS: int = 10

# --- TCP scan threshold -----------------------------------------------------
# Legitimate clients connect to one or two ports on a host. A source
# hitting this many distinct ports with SYN-only packets is port scanning.
TCP_PORTSCAN_PORT_THRESHOLD: int = 20

# --- Kerberos threshold -----------------------------------------------------
# KDC_ERR_PREAUTH_REQUIRED responses are normal in small numbers, but
# bursts indicate enumeration of AS-REP roastable accounts.
KERBEROS_PREAUTH_ERROR_THRESHOLD: int = 10


# ============================================================================
# CONSTANTS — TSHARK FINGERPRINTS
# ============================================================================
# Known-bad strings to search for. Kept as module-level constants so they're
# discoverable, auditable, and easy to extend.

# Scanner / pentest tool User-Agent strings. Real attackers change UAs;
# lazy ones and automated scanners don't.
SCANNER_USER_AGENTS: list[str] = [
    "sqlmap",
    "nikto",
    "nmap",
    "ffuf",
    "gobuster",
    "wfuzz",
    "masscan",
    "burp",
    "acunetix",
    "wpscan",
    "dirbuster",
]

# SQL injection signatures. Wireshark's `contains` operator is
# case-insensitive, so upper/lower variants aren't needed.
SQLI_URI_PATTERNS: list[str] = [
    "union",
    "'or",
    "1=1",
    "select",
    "%27%20or",
]

# Reflected/stored XSS signatures.
XSS_URI_PATTERNS: list[str] = [
    "<script",
    "alert(",
    "onerror",
    "javascript:",
]

# Remote code execution / command injection signatures.
RCE_URI_PATTERNS: list[str] = [
    "cmd=",
    "exec(",
    "/bin/sh",
    "powershell",
]

# Common webshell filenames seen in compromise URIs.
WEBSHELL_URI_PATTERNS: list[str] = [
    "shell.php",
    "c99",
    "r57",
    "cmd.aspx",
    "wso.php",
]

# Administrative SMB shares — access from a non-admin host indicates
# lateral movement (PsExec, SMBExec, Impacket).
SMB_ADMIN_SHARES: list[str] = ["C$", "ADMIN$", "IPC$"]

# Maximum runtime for any single tshark invocation. Large pcaps with
# complex filters can be slow; this is a safety net for runaway runs.
TSHARK_TIMEOUT_SECONDS: int = 300


# ============================================================================
# CONSTANTS — TERMINAL FORMATTING
# ============================================================================


class TermColor:
    """ANSI escape codes for terminal output."""

    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ============================================================================
# DATA MODELS
# ============================================================================


class Severity(Enum):
    """Finding severity levels, ordered from most to least urgent.

    HIGH    — active attack indicator or confirmed malicious activity
    MEDIUM  — suspicious activity warranting investigation
    LOW     — notable but expected (e.g., cleartext protocols in use)
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def color(self) -> str:
        """Terminal color associated with this severity level."""
        return {
            Severity.HIGH: TermColor.RED,
            Severity.MEDIUM: TermColor.YELLOW,
            Severity.LOW: TermColor.BLUE,
        }[self]


@dataclass
class Finding:
    """A single detection result — actionable alert that needs analyst review.

    Every finding is self-contained: an analyst should be able to read one
    entry and understand what was detected, where, and how to verify it
    themselves in Wireshark.

    Attributes:
        severity: How serious this finding is (HIGH/MEDIUM/LOW).
        category: Short tag (e.g., "dns-tunneling") used for grouping.
        message: One-line description shown in terminal output.
        evidence: Optional raw output or details for additional context.
        wireshark_filter: The exact filter that produced this finding so
            the analyst can re-run it in Wireshark for verification.
    """

    severity: Severity
    category: str
    message: str
    evidence: Optional[str] = None
    wireshark_filter: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize for JSON output. Enum becomes its string value."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ReferenceBlock:
    """A block of contextual data extracted from the pcap.

    Reference data is not an alert — it's situational awareness. Things
    like conversation tables, URL lists, and protocol breakdowns go here.
    Displayed only in the lower half of the report, after the shark banner.

    Attributes:
        title: Section heading shown above the content.
        content: Raw text content (often tshark stats output).
        description: Optional short explanation of what this data shows.
    """

    title: str
    content: str
    description: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize for JSON output."""
        return asdict(self)


@dataclass
class TriageReport:
    """Container for a complete triage run.

    Holds metadata about the analysis (when, what file, packet count),
    the actionable findings discovered during checks, and the reference
    data blocks collected for context.
    """

    pcap_path: str
    analyzed_at: str
    total_packets: int = 0
    findings: list[Finding] = field(default_factory=list)
    reference_blocks: list[ReferenceBlock] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Append a finding and echo it to the terminal immediately.

        Echoing live (rather than batching at end-of-run) gives the analyst
        feedback as long-running tshark queries complete — important UX
        for big pcaps where the script may run for several minutes.
        """
        self.findings.append(finding)
        print_finding(finding)

    def add_reference(self, block: ReferenceBlock) -> None:
        """Append a reference data block. Not echoed live — rendered at end."""
        self.reference_blocks.append(block)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Return finding counts broken down by severity level.

        All severity levels appear in the result, including zero counts,
        so downstream report rendering doesn't need to handle missing keys.
        """
        counts: Counter = Counter(f.severity.value for f in self.findings)
        return {sev.value: counts.get(sev.value, 0) for sev in Severity}

    @property
    def has_findings(self) -> bool:
        """True if any actionable findings were recorded."""
        return len(self.findings) > 0


# ============================================================================
# TSHARK INTERFACE
# ============================================================================
# Thin wrappers around subprocess calls to tshark. Centralized so error
# handling, timeouts, and common arguments live in one place.


def run_tshark(
    pcap_path: str,
    display_filter: Optional[str] = None,
    fields: Optional[list[str]] = None,
    extra_args: Optional[list[str]] = None,
) -> list[str]:
    """Execute tshark and return non-empty stdout lines.

    Args:
        pcap_path: Path to the pcap file to analyze.
        display_filter: A Wireshark display filter (e.g., "dns and !mdns").
            Applied via tshark's -Y flag.
        fields: Field names to extract (e.g., ["ip.src", "ip.dst"]).
            Triggers -T fields output mode; results are tab-separated.
        extra_args: Additional tshark arguments (e.g., statistics flags
            like ["-q", "-z", "io,phs"]).

    Returns:
        Non-empty output lines. Empty list on timeout or missing tshark.
    """
    # -n disables name resolution: faster, more predictable, and avoids
    # leaking the analyst's DNS resolver to the network during analysis.
    command: list[str] = ["tshark", "-r", pcap_path, "-n"]

    if display_filter:
        command.extend(["-Y", display_filter])

    if fields:
        command.append("-T")
        command.append("fields")
        for field_name in fields:
            command.extend(["-e", field_name])

    if extra_args:
        command.extend(extra_args)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
            check=False,  # We handle non-zero exits ourselves
        )
        # Filter blank lines — tshark emits them around stats output
        return [line for line in result.stdout.splitlines() if line.strip()]

    except subprocess.TimeoutExpired:
        print(
            f"{TermColor.YELLOW}[WARN]{TermColor.RESET} "
            f"tshark timed out on filter: {display_filter or '(stats query)'}"
        )
        return []

    except FileNotFoundError:
        # tshark missing is fatal — every check needs it.
        print(
            f"{TermColor.RED}tshark not found. "
            f"Install with: sudo apt install wireshark-cli{TermColor.RESET}"
        )
        sys.exit(1)


def run_tshark_raw(pcap_path: str, extra_args: list[str]) -> str:
    """Run tshark and return raw stdout (preserving formatting).

    Used for statistics output where tshark's table formatting matters
    (e.g., `-z conv,ip` produces an aligned column table that we want
    to display as-is rather than re-parse).
    """
    command: list[str] = ["tshark", "-r", pcap_path, "-n", *extra_args]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
            check=False,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        print(f"{TermColor.RED}tshark not found.{TermColor.RESET}")
        sys.exit(1)


def count_matching_packets(pcap_path: str, display_filter: str) -> int:
    """Count packets matching a given display filter."""
    # Extracting frame.number gives minimal output for max speed when
    # all we need is the count.
    matches = run_tshark(
        pcap_path,
        display_filter=display_filter,
        fields=["frame.number"],
    )
    return len(matches)


# ============================================================================
# OUTPUT HELPERS
# ============================================================================


def print_banner(banner: str, color: str = TermColor.CYAN) -> None:
    """Print an ASCII banner with optional color tinting."""
    print(f"{color}{banner}{TermColor.RESET}")


def print_section(title: str) -> None:
    """Print a visually distinct section header to the terminal."""
    print(f"\n{TermColor.BOLD}=== {title} ==={TermColor.RESET}")


def print_status(message: str) -> None:
    """Print a dimmed status line (no severity, just progress info)."""
    print(f"{TermColor.DIM}  · {message}{TermColor.RESET}")


def print_finding(finding: Finding) -> None:
    """Render a finding to the terminal with appropriate color coding."""
    color = finding.severity.color
    print(
        f"{color}[{finding.severity.value}]{TermColor.RESET} "
        f"{TermColor.BOLD}{finding.category}{TermColor.RESET}: "
        f"{finding.message}"
    )

    if finding.evidence:
        # Indent + dim evidence so the main message stays scannable
        for line in str(finding.evidence).splitlines():
            print(f"     {TermColor.GREY}{line}{TermColor.RESET}")

    if finding.wireshark_filter:
        print(
            f"     {TermColor.GREY}filter: {finding.wireshark_filter}{TermColor.RESET}"
        )


def print_reference_block(block: ReferenceBlock) -> None:
    """Render a reference data block to the terminal."""
    print(f"\n{TermColor.BOLD}{TermColor.CYAN}── {block.title} ──{TermColor.RESET}")
    if block.description:
        print(f"{TermColor.DIM}{block.description}{TermColor.RESET}")
    print(block.content.rstrip())


# ============================================================================
# DETECTION CHECKS — return findings, alert on real signal
# ============================================================================


def check_dns_anomalies(pcap_path: str, report: TriageReport) -> None:
    """DNS detection: tunneling, DGA, suspicious query types, tool fingerprints."""
    print_status("checking DNS...")

    # Pull all query names once — downstream checks reuse this list.
    query_names = run_tshark(
        pcap_path,
        display_filter="dns.qry.name and !mdns",
        fields=["dns.qry.name"],
    )

    if not query_names:
        return

    # --- Long query names (tunneling) ---
    # Split into "suspicious" vs "certain" buckets so severity reflects
    # how confident we are this is malicious rather than just unusual.
    very_long_names = [name for name in query_names if len(name) > DNS_NAME_LEN_CERTAIN]
    moderately_long_names = [
        name for name in query_names if len(name) > DNS_NAME_LEN_SUSPICIOUS
    ]

    if very_long_names:
        longest_length = max(len(name) for name in very_long_names)
        sample = very_long_names[0][:120]
        if len(very_long_names[0]) > 120:
            sample += "..."

        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="dns-tunneling",
                message=(
                    f"{len(very_long_names)} DNS queries with names > "
                    f"{DNS_NAME_LEN_CERTAIN} chars — near-certain tunneling"
                ),
                evidence=f"longest: {longest_length} chars\nsample: {sample}",
                wireshark_filter=(
                    f"dns.qry.name.len > {DNS_NAME_LEN_CERTAIN} and !mdns"
                ),
            )
        )

    elif moderately_long_names:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="dns-tunneling",
                message=(
                    f"{len(moderately_long_names)} DNS queries with names > "
                    f"{DNS_NAME_LEN_SUSPICIOUS} chars — possible tunneling"
                ),
                wireshark_filter=(
                    f"dns.qry.name.len > {DNS_NAME_LEN_SUSPICIOUS} and !mdns"
                ),
            )
        )

    # --- NXDOMAIN burst (DGA indicator) ---
    nxdomain_count = count_matching_packets(pcap_path, "dns.flags.rcode == 3")
    if nxdomain_count > DNS_NXDOMAIN_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="dns-dga",
                message=(
                    f"{nxdomain_count} NXDOMAIN responses — possible Domain "
                    f"Generation Algorithm activity (malware hunting C2)"
                ),
                wireshark_filter="dns.flags.rcode == 3",
            )
        )

    # --- Suspicious record types ---
    # TXT and NULL records are tunneling favorites — they allow arbitrary
    # data in responses.
    txt_count = count_matching_packets(pcap_path, "dns.qry.type == 16 and !mdns")
    null_count = count_matching_packets(pcap_path, "dns.qry.type == 10")

    if txt_count > DNS_TXT_QUERY_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="dns-tunneling",
                message=f"{txt_count} TXT queries — tunneling tools favor TXT records",
                wireshark_filter="dns.qry.type == 16",
            )
        )

    if null_count > 0:
        # NULL records are essentially never used legitimately — any
        # presence warrants HIGH severity.
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="dns-tunneling",
                message=f"{null_count} NULL-type DNS queries — almost always malicious",
                wireshark_filter="dns.qry.type == 10",
            )
        )

    # --- Tool fingerprints ---
    if count_matching_packets(pcap_path, 'dns contains "dnscat"') > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="dns-c2",
                message="Dnscat2 string present in DNS traffic",
                wireshark_filter='dns contains "dnscat"',
            )
        )


def check_http_anomalies(pcap_path: str, report: TriageReport) -> None:
    """HTTP detection: scanners, injection attacks, brute force, basic auth."""
    print_status("checking HTTP...")

    if not count_matching_packets(pcap_path, "http.request"):
        return

    # --- Scanner User-Agents (one finding per match) ---
    for scanner_name in SCANNER_USER_AGENTS:
        wireshark_filter = f'http.user_agent contains "{scanner_name}"'
        match_count = count_matching_packets(pcap_path, wireshark_filter)
        if match_count > 0:
            report.add_finding(
                Finding(
                    severity=Severity.HIGH,
                    category="http-scanner",
                    message=f'{match_count} requests with "{scanner_name}" in User-Agent',
                    wireshark_filter=wireshark_filter,
                )
            )

    # --- Empty User-Agent (automation marker) ---
    empty_ua_count = count_matching_packets(
        pcap_path, "http.request and !http.user_agent"
    )
    if empty_ua_count > HTTP_EMPTY_UA_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.LOW,
                category="http-automation",
                message=f"{empty_ua_count} requests without User-Agent — likely automation",
                wireshark_filter="http.request and !http.user_agent",
            )
        )

    # --- Attack pattern matching ---
    # Aggregate per category to avoid finding-spam when multiple patterns
    # in a category match the same traffic.
    _check_uri_pattern_group(
        pcap_path,
        report,
        patterns=SQLI_URI_PATTERNS,
        category="http-sqli",
        description="SQLi patterns",
    )
    _check_uri_pattern_group(
        pcap_path,
        report,
        patterns=XSS_URI_PATTERNS,
        category="http-xss",
        description="XSS patterns",
    )
    _check_uri_pattern_group(
        pcap_path,
        report,
        patterns=RCE_URI_PATTERNS,
        category="http-rce",
        description="RCE patterns",
    )

    # --- Path traversal ---
    if count_matching_packets(pcap_path, 'http.request.uri contains "../"') > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="http-traversal",
                message='Path traversal pattern "../" detected in URIs',
                wireshark_filter='http.request.uri contains "../"',
            )
        )

    # --- Webshells (one finding per match — each is unambiguous signal) ---
    for shell_pattern in WEBSHELL_URI_PATTERNS:
        wireshark_filter = f'http.request.uri contains "{shell_pattern}"'
        if count_matching_packets(pcap_path, wireshark_filter) > 0:
            report.add_finding(
                Finding(
                    severity=Severity.HIGH,
                    category="http-webshell",
                    message=f'Webshell indicator "{shell_pattern}" found in URIs',
                    wireshark_filter=wireshark_filter,
                )
            )

    # --- Brute force indicators via response code patterns ---
    not_found_count = count_matching_packets(pcap_path, "http.response.code == 404")
    unauthorized_count = count_matching_packets(pcap_path, "http.response.code == 401")

    if not_found_count > HTTP_BRUTEFORCE_404_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="http-bruteforce",
                message=f"{not_found_count} HTTP 404 responses — likely directory brute force",
                wireshark_filter="http.response.code == 404",
            )
        )

    if unauthorized_count > HTTP_BRUTEFORCE_401_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="http-bruteforce",
                message=f"{unauthorized_count} HTTP 401 responses — likely auth brute force",
                wireshark_filter="http.response.code == 401",
            )
        )

    # --- Basic auth (Base64 credentials in cleartext) ---
    if count_matching_packets(pcap_path, "http.authorization") > 0:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="http-creds",
                message="HTTP Basic auth present — Base64 credentials sent in cleartext",
                wireshark_filter="http.authorization",
            )
        )


def _check_uri_pattern_group(
    pcap_path: str,
    report: TriageReport,
    patterns: list[str],
    category: str,
    description: str,
) -> None:
    """Internal helper: aggregate matches across a group of URI patterns.

    Aggregating into a single finding (instead of one per pattern) prevents
    finding-spam when the same attack traffic matches multiple patterns.
    """
    total_matches = sum(
        count_matching_packets(pcap_path, f'http.request.uri contains "{pattern}"')
        for pattern in patterns
    )

    if total_matches > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category=category,
                message=f"{total_matches} URI hits matching {description}",
                wireshark_filter=f'http.request.uri contains "{patterns[0]}" (and others)',
            )
        )


def check_ftp_anomalies(pcap_path: str, report: TriageReport) -> None:
    """FTP detection: brute force, anonymous access, cleartext credentials."""
    print_status("checking FTP...")

    if not count_matching_packets(pcap_path, "ftp"):
        return

    failed_login_count = count_matching_packets(pcap_path, "ftp.response.code == 530")

    if failed_login_count > FTP_BRUTEFORCE_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="ftp-bruteforce",
                message=f"{failed_login_count} failed FTP logins — possible brute force",
                wireshark_filter="ftp.response.code == 530",
            )
        )

    # --- Cleartext credentials ---
    usernames = run_tshark(
        pcap_path,
        display_filter='ftp.request.command == "USER"',
        fields=["ftp.request.arg"],
    )
    passwords = run_tshark(
        pcap_path,
        display_filter='ftp.request.command == "PASS"',
        fields=["ftp.request.arg"],
    )

    if usernames:
        unique_users = sorted(set(usernames))
        users_display = ", ".join(unique_users)[:200]
        report.add_finding(
            Finding(
                severity=Severity.LOW,
                category="ftp-creds",
                message=f"{len(usernames)} usernames sent in cleartext",
                evidence=f"unique users: {users_display}",
                wireshark_filter='ftp.request.command == "USER"',
            )
        )

    if passwords:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="ftp-creds",
                message=f"{len(passwords)} passwords sent in cleartext (FTP is unencrypted)",
                wireshark_filter='ftp.request.command == "PASS"',
            )
        )

    # --- Anonymous access ---
    if count_matching_packets(pcap_path, 'ftp.request.arg == "anonymous"') > 0:
        report.add_finding(
            Finding(
                severity=Severity.LOW,
                category="ftp-anon",
                message="Anonymous FTP login attempt observed",
                wireshark_filter='ftp.request.arg == "anonymous"',
            )
        )

    # --- Upload activity (potential webshell/exfil staging) ---
    upload_count = count_matching_packets(pcap_path, 'ftp.request.command == "STOR"')
    if upload_count > 0:
        report.add_finding(
            Finding(
                severity=Severity.LOW,
                category="ftp-upload",
                message=f"{upload_count} STOR commands — file uploads (possible staging)",
                wireshark_filter='ftp.request.command == "STOR"',
            )
        )


def check_kerberos_anomalies(pcap_path: str, report: TriageReport) -> None:
    """Kerberos detection: roasting, preauth probing, account enumeration."""
    print_status("checking Kerberos...")

    if not count_matching_packets(pcap_path, "kerberos"):
        return

    # --- RC4 encryption (Kerberoasting / AS-REP roasting) ---
    # Modern AD should issue AES tickets (etype 17/18). RC4 (etype 23)
    # in 2026 traffic = attacker downgrade-forcing to crack offline.
    rc4_count = count_matching_packets(pcap_path, "kerberos.etype == 23")
    if rc4_count > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="kerberos-roasting",
                message=(
                    f"{rc4_count} Kerberos packets with RC4 (etype 23) — "
                    f"Kerberoasting / AS-REP roasting indicator"
                ),
                wireshark_filter="kerberos.etype == 23",
            )
        )

    # --- KRB-ERROR burst (preauth probing for AS-REP roastable accounts) ---
    krb_error_count = count_matching_packets(pcap_path, "kerberos.msg_type == 30")
    if krb_error_count > KERBEROS_PREAUTH_ERROR_THRESHOLD:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="kerberos-enum",
                message=f"{krb_error_count} KRB-ERROR packets — possible preauth probing",
                wireshark_filter="kerberos.msg_type == 30",
            )
        )


def check_smb_anomalies(pcap_path: str, report: TriageReport) -> None:
    """SMB detection: admin share access (lateral movement), null sessions."""
    print_status("checking SMB...")

    if not count_matching_packets(pcap_path, "smb or smb2"):
        return

    # --- Administrative share access ---
    # C$ and ADMIN$ are higher-impact than IPC$ — separating severity
    # helps the analyst prioritize.
    for share_name in SMB_ADMIN_SHARES:
        wireshark_filter = f'smb2.tree contains "{share_name}"'
        match_count = count_matching_packets(pcap_path, wireshark_filter)
        if match_count > 0:
            severity = (
                Severity.HIGH if share_name in ("C$", "ADMIN$") else Severity.MEDIUM
            )
            report.add_finding(
                Finding(
                    severity=severity,
                    category="smb-lateral",
                    message=f"{match_count} SMB2 operations against admin share {share_name}",
                    wireshark_filter=wireshark_filter,
                )
            )

    # --- Null sessions (anonymous SMB) ---
    if count_matching_packets(pcap_path, 'smb.account == ""') > 0:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="smb-null",
                message="SMB null session detected (anonymous access)",
                wireshark_filter='smb.account == ""',
            )
        )


def check_icmp_anomalies(pcap_path: str, report: TriageReport) -> None:
    """ICMP detection: tunneling, ping sweeps, MITM redirects."""
    print_status("checking ICMP...")

    if not count_matching_packets(pcap_path, "icmp"):
        return

    # --- Oversized ICMP (tunneling) ---
    oversized_count = count_matching_packets(
        pcap_path,
        f"icmp and data.len > {ICMP_PAYLOAD_SUSPICIOUS_BYTES}",
    )
    if oversized_count > 5:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="icmp-tunnel",
                message=(
                    f"{oversized_count} ICMP packets with payload > "
                    f"{ICMP_PAYLOAD_SUSPICIOUS_BYTES} bytes — tunneling indicator"
                ),
                wireshark_filter=f"icmp and data.len > {ICMP_PAYLOAD_SUSPICIOUS_BYTES}",
            )
        )

    # --- Ping sweep detection ---
    # Pull (source, destination) pairs and count unique destinations per
    # source. A single host pinging many distinct destinations is sweeping.
    echo_request_lines = run_tshark(
        pcap_path,
        display_filter="icmp.type == 8",
        fields=["ip.src", "ip.dst"],
    )

    destinations_per_source: dict[str, set[str]] = defaultdict(set)
    for line in echo_request_lines:
        parts = line.split("\t")
        if len(parts) == 2:
            source_ip, destination_ip = parts
            destinations_per_source[source_ip].add(destination_ip)

    for source_ip, destinations in destinations_per_source.items():
        if len(destinations) > ICMP_PING_SWEEP_DESTINATIONS:
            report.add_finding(
                Finding(
                    severity=Severity.MEDIUM,
                    category="icmp-sweep",
                    message=(
                        f"{source_ip} pinged {len(destinations)} distinct hosts "
                        f"— ping sweep"
                    ),
                    wireshark_filter=f"icmp.type == 8 and ip.src == {source_ip}",
                )
            )

    # --- ICMP Redirect (MITM indicator) ---
    if count_matching_packets(pcap_path, "icmp.type == 5") > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="icmp-redirect",
                message="ICMP Redirect packets seen — possible man-in-the-middle attack",
                wireshark_filter="icmp.type == 5",
            )
        )


def check_arp_anomalies(pcap_path: str, report: TriageReport) -> None:
    """ARP detection: cache poisoning via duplicate IP-to-MAC mappings.

    The ARP poisoning signature is one IP being announced from two or
    more different MAC addresses. Normal networks have a strict 1:1
    mapping at any given moment.
    """
    print_status("checking ARP...")

    if not count_matching_packets(pcap_path, "arp"):
        return

    arp_replies = run_tshark(
        pcap_path,
        display_filter="arp.opcode == 2",
        fields=["arp.src.proto_ipv4", "arp.src.hw_mac"],
    )

    # Build IP -> {MAC, ...} mapping. Any IP claimed by multiple MACs
    # is suspect.
    ip_to_mac_addresses: dict[str, set[str]] = defaultdict(set)
    for line in arp_replies:
        parts = line.split("\t")
        if len(parts) == 2 and parts[0]:
            ip_address, mac_address = parts
            ip_to_mac_addresses[ip_address].add(mac_address)

    for ip_address, mac_addresses in ip_to_mac_addresses.items():
        if len(mac_addresses) > 1:
            report.add_finding(
                Finding(
                    severity=Severity.HIGH,
                    category="arp-poison",
                    message=(
                        f"IP {ip_address} announced by {len(mac_addresses)} "
                        f"different MAC addresses — ARP cache poisoning indicator"
                    ),
                    evidence=f"MACs: {', '.join(sorted(mac_addresses))}",
                    wireshark_filter="arp.opcode == 2",
                )
            )


def check_tcp_scan_anomalies(pcap_path: str, report: TriageReport) -> None:
    """TCP detection: SYN scans, NULL scans, XMAS scans."""
    print_status("checking TCP scan patterns...")

    # --- SYN scan detection ---
    syn_only_lines = run_tshark(
        pcap_path,
        display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        fields=["ip.src", "tcp.dstport"],
    )

    destination_ports_per_source: dict[str, set[str]] = defaultdict(set)
    for line in syn_only_lines:
        parts = line.split("\t")
        if len(parts) == 2 and parts[0]:
            source_ip, destination_port = parts
            destination_ports_per_source[source_ip].add(destination_port)

    for source_ip, ports in destination_ports_per_source.items():
        if len(ports) > TCP_PORTSCAN_PORT_THRESHOLD:
            report.add_finding(
                Finding(
                    severity=Severity.HIGH,
                    category="tcp-portscan",
                    message=(
                        f"{source_ip} hit {len(ports)} distinct ports with "
                        f"SYN-only packets — port scan"
                    ),
                    wireshark_filter=(
                        f"tcp.flags.syn == 1 and tcp.flags.ack == 0 "
                        f"and ip.src == {source_ip}"
                    ),
                )
            )

    # --- NULL scan (no flags set — evasion technique) ---
    null_scan_count = count_matching_packets(pcap_path, "tcp.flags == 0x000")
    if null_scan_count > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="tcp-null-scan",
                message=f"{null_scan_count} NULL-flag TCP packets — evasion scan",
                wireshark_filter="tcp.flags == 0x000",
            )
        )

    # --- XMAS scan (FIN+PSH+URG together — also evasion) ---
    xmas_filter = "tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1"
    xmas_scan_count = count_matching_packets(pcap_path, xmas_filter)
    if xmas_scan_count > 0:
        report.add_finding(
            Finding(
                severity=Severity.HIGH,
                category="tcp-xmas-scan",
                message=f"{xmas_scan_count} XMAS-flag packets — evasion scan",
                wireshark_filter=xmas_filter,
            )
        )


def check_telnet_usage(pcap_path: str, report: TriageReport) -> None:
    """Telnet detection: any usage flagged as cleartext exposure."""
    print_status("checking Telnet...")

    telnet_count = count_matching_packets(pcap_path, "telnet")
    if telnet_count > 0:
        report.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                category="telnet",
                message=(
                    f"{telnet_count} Telnet packets — cleartext protocol in use "
                    f"(credentials visible via Follow TCP Stream)"
                ),
                wireshark_filter="telnet",
            )
        )


# ============================================================================
# REFERENCE DATA COLLECTION — context for analyst, not alerts
# ============================================================================
# These functions don't generate findings; they collect contextual data
# (conversations, URLs, hosts, etc.) that helps the analyst understand
# the broader pcap content. Rendered AFTER findings in every report.


def collect_protocol_hierarchy(pcap_path: str, report: TriageReport) -> None:
    """Collect protocol breakdown (what's in the file by volume)."""
    print_status("collecting protocol hierarchy...")
    output = run_tshark_raw(pcap_path, ["-q", "-z", "io,phs"])
    if output.strip():
        report.add_reference(
            ReferenceBlock(
                title="Protocol Hierarchy",
                description="Breakdown of protocols by packet/byte count.",
                content=output,
            )
        )


def collect_ipv4_conversations(pcap_path: str, report: TriageReport) -> None:
    """Collect IPv4 conversation pairs (like Wireshark's Conversations dialog)."""
    print_status("collecting IPv4 conversations...")
    output = run_tshark_raw(pcap_path, ["-q", "-z", "conv,ip"])
    if output.strip():
        report.add_reference(
            ReferenceBlock(
                title="IPv4 Conversations",
                description="Top IP-to-IP conversations sorted by tshark default.",
                content=output,
            )
        )


def collect_tcp_conversations(pcap_path: str, report: TriageReport) -> None:
    """Collect TCP conversations (per-port granularity)."""
    print_status("collecting TCP conversations...")
    output = run_tshark_raw(pcap_path, ["-q", "-z", "conv,tcp"])
    if output.strip():
        report.add_reference(
            ReferenceBlock(
                title="TCP Conversations",
                description="Per-port TCP flows. Long durations + small bits/s = beaconing.",
                content=output,
            )
        )


def collect_udp_conversations(pcap_path: str, report: TriageReport) -> None:
    """Collect UDP conversations."""
    print_status("collecting UDP conversations...")
    output = run_tshark_raw(pcap_path, ["-q", "-z", "conv,udp"])
    if output.strip():
        report.add_reference(
            ReferenceBlock(
                title="UDP Conversations",
                description="Per-port UDP flows. Useful for DNS, SNMP, syslog patterns.",
                content=output,
            )
        )


def collect_endpoints(pcap_path: str, report: TriageReport) -> None:
    """Collect endpoint summary (every IP with traffic counts)."""
    print_status("collecting endpoints...")
    output = run_tshark_raw(pcap_path, ["-q", "-z", "endpoints,ip"])
    if output.strip():
        report.add_reference(
            ReferenceBlock(
                title="IP Endpoints",
                description="Every IP address that appeared in the capture.",
                content=output,
            )
        )


def collect_http_urls(pcap_path: str, report: TriageReport) -> None:
    """Collect HTTP URLs with hit counts.

    Builds a sorted list of (URL, count) pairs — exactly what the analyst
    wants to see when answering "where did this host go?".
    """
    print_status("collecting HTTP URLs...")

    # Pull host + URI pairs and combine into full URLs
    url_lines = run_tshark(
        pcap_path,
        display_filter="http.request",
        fields=["http.host", "http.request.uri"],
    )

    url_counter: Counter = Counter()
    for line in url_lines:
        parts = line.split("\t")
        if len(parts) == 2:
            host, uri = parts
            full_url = f"http://{host}{uri}" if host and uri else (host or uri)
            if full_url:
                url_counter[full_url] += 1

    if not url_counter:
        return

    # Format as "count\turl" sorted by count descending
    formatted_lines = [
        f"{count:>6}  {url}" for url, count in url_counter.most_common(50)
    ]
    header = f"{'COUNT':>6}  URL"
    content = header + "\n" + "\n".join(formatted_lines)

    report.add_reference(
        ReferenceBlock(
            title=f"HTTP URLs Hit ({len(url_counter)} unique, top 50 shown)",
            description="HTTP requests grouped by URL with hit counts.",
            content=content,
        )
    )


def collect_http_hosts(pcap_path: str, report: TriageReport) -> None:
    """Collect HTTP Host headers with hit counts."""
    print_status("collecting HTTP hosts...")

    host_lines = run_tshark(
        pcap_path,
        display_filter="http.request",
        fields=["http.host"],
    )

    host_counter: Counter = Counter(h for h in host_lines if h)
    if not host_counter:
        return

    formatted_lines = [
        f"{count:>6}  {host}" for host, count in host_counter.most_common(30)
    ]
    header = f"{'COUNT':>6}  HOST"
    content = header + "\n" + "\n".join(formatted_lines)

    report.add_reference(
        ReferenceBlock(
            title=f"HTTP Hosts ({len(host_counter)} unique, top 30 shown)",
            description="Hostnames seen in HTTP Host headers.",
            content=content,
        )
    )


def collect_dns_domains(pcap_path: str, report: TriageReport) -> None:
    """Collect DNS queried domains with hit counts."""
    print_status("collecting DNS domains...")

    query_lines = run_tshark(
        pcap_path,
        display_filter="dns.qry.name and !mdns",
        fields=["dns.qry.name"],
    )

    # Use the "registered domain" heuristic: last two labels. Oversimplifies
    # for domain.co.uk but works for triage.
    domain_counter: Counter = Counter()
    for name in query_lines:
        labels = name.strip(".").split(".")
        if len(labels) >= 2:
            registered = f"{labels[-2]}.{labels[-1]}"
            domain_counter[registered] += 1

    if not domain_counter:
        return

    formatted_lines = [
        f"{count:>6}  {domain}" for domain, count in domain_counter.most_common(30)
    ]
    header = f"{'COUNT':>6}  DOMAIN"
    content = header + "\n" + "\n".join(formatted_lines)

    report.add_reference(
        ReferenceBlock(
            title=f"DNS Domains Queried ({len(domain_counter)} unique, top 30 shown)",
            description="Registered domains queried via DNS (last two labels).",
            content=content,
        )
    )


def collect_tls_sni(pcap_path: str, report: TriageReport) -> None:
    """Collect TLS SNI values.

    SNI is sent unencrypted even in HTTPS, so this reveals which domains
    a client is contacting over TLS without needing decryption keys.
    """
    print_status("collecting TLS SNI values...")

    sni_lines = run_tshark(
        pcap_path,
        display_filter="tls.handshake.extensions_server_name",
        fields=["tls.handshake.extensions_server_name"],
    )

    sni_counter: Counter = Counter(s for s in sni_lines if s)
    if not sni_counter:
        return

    formatted_lines = [
        f"{count:>6}  {sni}" for sni, count in sni_counter.most_common(30)
    ]
    header = f"{'COUNT':>6}  SNI HOSTNAME"
    content = header + "\n" + "\n".join(formatted_lines)

    report.add_reference(
        ReferenceBlock(
            title=f"TLS SNI Values ({len(sni_counter)} unique, top 30 shown)",
            description="Server names from TLS handshakes — visible even on HTTPS.",
            content=content,
        )
    )


def collect_kerberos_accounts(pcap_path: str, report: TriageReport) -> None:
    """Collect user and machine accounts seen in Kerberos traffic."""
    print_status("collecting Kerberos accounts...")

    cname_strings = run_tshark(
        pcap_path,
        display_filter="kerberos.CNameString",
        fields=["kerberos.CNameString"],
    )
    if not cname_strings:
        return

    # Machine accounts end with "$"; user accounts don't.
    user_accounts = sorted({n for n in cname_strings if not n.endswith("$")})
    machine_accounts = sorted({n for n in cname_strings if n.endswith("$")})

    content_lines = []
    if user_accounts:
        content_lines.append(f"User Accounts ({len(user_accounts)}):")
        content_lines.extend(f"  {u}" for u in user_accounts)
    if machine_accounts:
        if content_lines:
            content_lines.append("")
        content_lines.append(f"Machine Accounts ({len(machine_accounts)}):")
        content_lines.extend(f"  {m}" for m in machine_accounts)

    report.add_reference(
        ReferenceBlock(
            title="Kerberos Accounts Seen",
            description="User and machine accounts that authenticated via Kerberos.",
            content="\n".join(content_lines),
        )
    )


# ============================================================================
# REPORT SERIALIZATION
# ============================================================================


def write_json_report(output_path: str, report: TriageReport) -> None:
    """Serialize the triage report to JSON for downstream tooling.

    Intended for integration with SOAR, SIEM enrichment pipelines, or
    post-processing scripts — not for human reading. Use the Markdown
    writer for that.
    """
    report_data = {
        "pcap": report.pcap_path,
        "analyzed_at": report.analyzed_at,
        "total_packets": report.total_packets,
        "summary": report.severity_counts,
        "findings": [finding.to_dict() for finding in report.findings],
        "reference_data": [block.to_dict() for block in report.reference_blocks],
    }
    Path(output_path).write_text(json.dumps(report_data, indent=2))


def write_markdown_report(output_path: str, report: TriageReport) -> None:
    """Serialize the triage report to Markdown for human review.

    Structured the same way as the terminal output: ASCII banners, findings
    section first, then reference data below the separator.
    """
    lines: list[str] = []

    # --- Top banner ---
    lines.append("```")
    lines.append(BANNER_TOP.rstrip())
    lines.append("```")
    lines.append("")

    # --- Metadata ---
    lines.append("# PCAP Triage Report")
    lines.append("")
    lines.append(f"**File:** `{report.pcap_path}`  ")
    lines.append(f"**Analyzed:** {report.analyzed_at}  ")
    lines.append(f"**Total packets:** {report.total_packets}  ")
    lines.append("")

    # --- Summary ---
    lines.append("## Summary")
    lines.append("")
    for severity_name, count in report.severity_counts.items():
        lines.append(f"- **{severity_name}**: {count}")
    lines.append("")

    # --- Findings section (or clean banner if none) ---
    if report.has_findings:
        lines.append("```")
        lines.append(BANNER_FINDINGS.rstrip())
        lines.append("```")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for finding in report.findings:
            lines.append(f"### [{finding.severity.value}] {finding.category}")
            lines.append("")
            lines.append(finding.message)
            lines.append("")
            if finding.evidence:
                lines.append("```")
                lines.append(str(finding.evidence))
                lines.append("```")
                lines.append("")
            if finding.wireshark_filter:
                lines.append(f"**Filter:** `{finding.wireshark_filter}`")
                lines.append("")
    else:
        lines.append("```")
        lines.append(BANNER_CLEAN.rstrip())
        lines.append("```")
        lines.append("")

    # --- Separator + Reference Data section ---
    lines.append("```")
    lines.append(BANNER_SHARK.rstrip())
    lines.append("```")
    lines.append("")
    lines.append("## Reference Data")
    lines.append("")
    lines.append(
        "_The data below is contextual information extracted from the "
        "pcap — conversations, URLs, hosts, and so on. It is not flagged "
        "as suspicious; it's here for situational awareness and manual "
        "deep-dive._"
    )
    lines.append("")

    for block in report.reference_blocks:
        lines.append(f"### {block.title}")
        lines.append("")
        if block.description:
            lines.append(f"_{block.description}_")
            lines.append("")
        lines.append("```")
        lines.append(block.content.rstrip())
        lines.append("```")
        lines.append("")

    Path(output_path).write_text("\n".join(lines))


# ============================================================================
# CLI / MAIN
# ============================================================================


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Automated PCAP anomaly triage. Runs detection checks against "
            "a packet capture and surfaces suspicious activity, followed "
            "by reference data extracted from the pcap."
        ),
        epilog="Example: ./pcap_triage.py capture.pcap --md report.md",
    )
    parser.add_argument(
        "pcap",
        help="Path to the pcap file to analyze",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="Write JSON report to the given path",
    )
    parser.add_argument(
        "--md",
        metavar="PATH",
        help="Write Markdown report to the given path",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip ASCII banners in terminal output",
    )
    return parser.parse_args()


def run_all_detection_checks(pcap_path: str, report: TriageReport) -> None:
    """Execute every detection check in order.

    Order matters slightly — protocol-specific checks first, then
    cross-cutting concerns (TCP scans look at flag patterns across all
    TCP traffic).
    """
    check_dns_anomalies(pcap_path, report)
    check_http_anomalies(pcap_path, report)
    check_ftp_anomalies(pcap_path, report)
    check_kerberos_anomalies(pcap_path, report)
    check_smb_anomalies(pcap_path, report)
    check_icmp_anomalies(pcap_path, report)
    check_arp_anomalies(pcap_path, report)
    check_tcp_scan_anomalies(pcap_path, report)
    check_telnet_usage(pcap_path, report)


def run_all_reference_collection(pcap_path: str, report: TriageReport) -> None:
    """Execute every reference data collector in order.

    These run after detection so the analyst sees findings first in
    terminal output. The collectors themselves don't generate findings.
    """
    collect_protocol_hierarchy(pcap_path, report)
    collect_ipv4_conversations(pcap_path, report)
    collect_tcp_conversations(pcap_path, report)
    collect_udp_conversations(pcap_path, report)
    collect_endpoints(pcap_path, report)
    collect_http_urls(pcap_path, report)
    collect_http_hosts(pcap_path, report)
    collect_dns_domains(pcap_path, report)
    collect_tls_sni(pcap_path, report)
    collect_kerberos_accounts(pcap_path, report)


def print_final_summary(report: TriageReport) -> None:
    """Render the final terminal summary: findings recap then reference data."""
    print_section("Summary")
    for severity_name, count in report.severity_counts.items():
        severity_enum = Severity(severity_name)
        color = severity_enum.color if count > 0 else TermColor.GREY
        print(f"  {color}{severity_name}{TermColor.RESET}: {count}")

    # --- Findings recap (or clean message) ---
    if report.has_findings:
        print_banner(BANNER_FINDINGS, color=TermColor.RED)
        print(f"\n{TermColor.BOLD}Findings (in detection order):{TermColor.RESET}\n")
        for finding in report.findings:
            print_finding(finding)
    else:
        print_banner(BANNER_CLEAN, color=TermColor.GREEN)

    # --- Reference data section ---
    print_banner(BANNER_SHARK, color=TermColor.CYAN)
    print(
        f"{TermColor.DIM}The data below is contextual information "
        f"extracted from the pcap. It is not flagged as suspicious; "
        f"it's here for situational awareness and manual deep-dive."
        f"{TermColor.RESET}"
    )

    for block in report.reference_blocks:
        print_reference_block(block)


def main() -> int:
    """Top-level entry point. Returns process exit code.

    Exit codes:
        0  — completed successfully, no HIGH findings
        1  — input file not found or other startup error
        2  — completed successfully, but HIGH-severity findings present
             (useful for CI/automation pipelines to react on)
    """
    args = parse_arguments()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"{TermColor.RED}File not found: {pcap_path}{TermColor.RESET}")
        return 1

    # --- Banner ---
    if not args.no_banner:
        print_banner(BANNER_TOP, color=TermColor.CYAN)

    # --- Build report container ---
    report = TriageReport(
        pcap_path=str(pcap_path),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )

    # Total packet count is metadata, useful in the report header
    report.total_packets = count_matching_packets(str(pcap_path), "frame")

    print(f"{TermColor.BOLD}PCAP Triage: {pcap_path}{TermColor.RESET}")
    print(f"{TermColor.GREY}Started: {report.analyzed_at}{TermColor.RESET}")
    print(f"{TermColor.GREY}Total packets: {report.total_packets}{TermColor.RESET}")

    # --- Run detection ---
    print_section("Running Detection Checks")
    run_all_detection_checks(str(pcap_path), report)

    # --- Collect reference data ---
    print_section("Collecting Reference Data")
    run_all_reference_collection(str(pcap_path), report)

    # --- Render final summary to terminal ---
    print_final_summary(report)

    # --- Optional report file outputs ---
    if args.json:
        write_json_report(args.json, report)
        print(f"\n{TermColor.GREEN}JSON report written:{TermColor.RESET} {args.json}")

    if args.md:
        write_markdown_report(args.md, report)
        print(f"{TermColor.GREEN}Markdown report written:{TermColor.RESET} {args.md}")

    # Non-zero exit code if HIGH findings present — lets upstream automation
    # (CI pipelines, alerting wrappers) react programmatically.
    high_count = report.severity_counts["HIGH"]
    return 2 if high_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
