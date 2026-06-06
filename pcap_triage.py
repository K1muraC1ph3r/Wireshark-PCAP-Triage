#!/usr/bin/env python3
"""
pcap_triage.py — fast first-pass triage of a PCAP using tshark.

Surfaces common offensive/IR signals (DNS tunneling, HTTP brute force and
suspicious URIs, FTP credentials, Kerberos account harvesting, SMB tree
access, ICMP sweeps, ARP spoofing, TCP SYN scans), plus two host-centric
signals added in v2.1: external C2 beaconing (regular-interval HTTP requests
to a routable IP) and host attribution (tying an internal IP to its MAC,
NetBIOS hostname, Kerberos user account(s) and SAMR full name(s)). It attaches
representative packet evidence to every finding and aggregates the worst
source IPs into a single "Top Offenders" view.

Why v2.1 exists: v2.0 was built to catch *scanning/attack* patterns and was
blind to the bread-and-butter IR case — a single internal box quietly
beaconing to a commodity-RAT C2 — and it never surfaced *who/what* that box
was, only counts. The two new detections close exactly that gap.

Usage:
    ./pcap_triage.py capture.pcap
    ./pcap_triage.py capture.pcap --md report.md
    ./pcap_triage.py capture.pcap --json report.json
    ./pcap_triage.py capture.pcap --md report.md --json report.json
    ./pcap_triage.py capture.pcap --evidence 25      # more samples per finding

Requires: tshark (Wireshark CLI) on PATH.
"""

import argparse
import ipaddress
import json
import shutil
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

VERSION = "2.1"
TSHARK_TIMEOUT = 120  # seconds per tshark invocation

# Field separator passed to `tshark -T fields -E separator`. Tab is safe because
# tshark escapes embedded tabs in field values.
SEP = "\t"


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #
@dataclass
class PacketEvidence:
    """A single representative packet behind a finding."""
    frame: int
    timestamp: str            # ISO-8601 UTC
    src_ip: str
    dst_ip: str
    src_port: str = ""
    dst_port: str = ""
    protocol: str = ""
    details: dict = field(default_factory=dict)

    def render(self) -> str:
        """One-line renderer for terminal/markdown density."""
        sp = f":{self.src_port}" if self.src_port else ""
        dp = f":{self.dst_port}" if self.dst_port else ""
        proto = f" [{self.protocol}]" if self.protocol else ""
        det = ""
        if self.details:
            det = " " + " ".join(
                f"{k}={v}" for k, v in self.details.items() if v not in ("", None)
            )
        return (
            f"#{self.frame} {self.timestamp} "
            f"{self.src_ip}{sp} -> {self.dst_ip}{dp}{proto}{det}".rstrip()
        )


@dataclass
class Finding:
    category: str
    severity: str             # info | low | medium | high | critical
    title: str
    message: str
    wireshark_filter: str
    evidence: list = field(default_factory=list)   # list[PacketEvidence]

    def top_source(self) -> str:
        """Most frequent source IP across this finding's evidence."""
        c = Counter(e.src_ip for e in self.evidence if e.src_ip)
        return c.most_common(1)[0][0] if c else ""


# --------------------------------------------------------------------------- #
# tshark helpers
# --------------------------------------------------------------------------- #
def _warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def run_tshark(pcap, display_filter="", fields=None, extra_args=None):
    """
    Run tshark in `-T fields` mode and return a list of rows, where each row is
    a list of field values (split on SEP). Returns [] on error/timeout.
    """
    fields = fields or []
    cmd = ["tshark", "-r", pcap, "-n"]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", f"separator={SEP}", "-E", "occurrence=f"]
    if extra_args:
        cmd += extra_args
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        _warn(f"tshark timed out after {TSHARK_TIMEOUT}s (filter: {display_filter or 'none'})")
        return []
    except FileNotFoundError:
        _warn("tshark not found on PATH — install Wireshark CLI tools.")
        sys.exit(2)
    if out.returncode != 0 and out.stderr.strip():
        _warn(f"tshark error (filter: {display_filter or 'none'}): {out.stderr.strip().splitlines()[-1]}")
    rows = []
    for line in out.stdout.splitlines():
        if line.strip() == "":
            continue
        rows.append(line.split(SEP))
    return rows


def run_tshark_raw(pcap, display_filter="", extra_args=None):
    """
    Run tshark and return raw stdout text (e.g. for -z statistics).
    Emits a timeout warning instead of silently returning empty output,
    matching run_tshark behavior.
    """
    cmd = ["tshark", "-r", pcap, "-n"]
    if display_filter:
        cmd += ["-Y", display_filter]
    if extra_args:
        cmd += extra_args
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        _warn(f"tshark timed out after {TSHARK_TIMEOUT}s (filter: {display_filter or 'none'})")
        return ""
    except FileNotFoundError:
        _warn("tshark not found on PATH — install Wireshark CLI tools.")
        sys.exit(2)
    return out.stdout


def _iso(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return epoch or ""


# Standard base fields pulled for every IP-based finding.
_BASE_FIELDS = [
    "frame.number", "frame.time_epoch",
    "ip.src", "ip.dst",
    "tcp.srcport", "udp.srcport",
    "tcp.dstport", "udp.dstport",
    "_ws.col.Protocol",
]
# Base fields for L2 (ARP) findings, which have no IP layer.
_L2_FIELDS = [
    "frame.number", "frame.time_epoch",
    "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "eth.src", "eth.dst",
    "_ws.col.Protocol",
]


def extract_packet_evidence(pcap, display_filter, extra_fields=None,
                            limit=10, l2=False):
    """
    Single helper every detection uses. Pulls the standard 5-tuple/identity
    fields plus any caller-requested protocol fields in one tshark call.
    Handles ARP's L2 addressing as a special case (l2=True).
    """
    extra_fields = extra_fields or []
    base = _L2_FIELDS if l2 else _BASE_FIELDS
    fields = base + extra_fields
    # NOTE (v2.1 fix): we deliberately do NOT pass `-c <limit>` here.
    # `tshark -c N` stops after reading the first N frames *from the file* and
    # only then applies the `-Y` display filter — so for any finding whose
    # packets live deep in the capture (e.g. C2 beacons starting at frame
    # 2638), `-c 10` read frames 1..10, matched none, and returned ZERO
    # evidence. We read every match and slice to `limit` in Python below; the
    # capture is small enough that the extra read cost is negligible.
    rows = run_tshark(pcap, display_filter, fields)

    evidence = []
    for r in rows[:limit]:
        # pad short rows so indexing is safe
        r = r + [""] * (len(fields) - len(r))
        details = {}
        for i, fname in enumerate(extra_fields):
            val = r[len(base) + i]
            if val:
                key = fname.split(".")[-1]
                details[key] = val
        if l2:
            ev = PacketEvidence(
                frame=int(r[0]) if r[0].isdigit() else 0,
                timestamp=_iso(r[1]),
                src_ip=r[2] or r[4],     # arp ip, fall back to eth mac
                dst_ip=r[3] or r[5],
                protocol=r[6],
                details=details,
            )
        else:
            ev = PacketEvidence(
                frame=int(r[0]) if r[0].isdigit() else 0,
                timestamp=_iso(r[1]),
                src_ip=r[2],
                dst_ip=r[3],
                src_port=r[4] or r[5],
                dst_port=r[6] or r[7],
                protocol=r[8],
                details=details,
            )
        evidence.append(ev)
    return evidence


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #
def _looks_like_ad_service_record(name: str) -> bool:
    """True for the long-but-benign names normal Windows/AD hosts emit
    constantly: SRV service lookups (_ldap._tcp...), the _msdcs zone, _sites
    locator records, and reverse-DNS PTR queries. These routinely exceed 50
    chars and were the reason v2.0 screamed 'DNS tunneling' at a clean domain.
    Real tunneling uses long *random-looking* labels under one attacker zone,
    not dotted service prefixes — so excluding these cuts noise without hiding
    actual exfil."""
    lowered = name.lower()
    if lowered.startswith("_"):                      # _ldap, _kerberos, _gc ...
        return True
    benign_markers = ("._tcp.", "._udp.", "._msdcs.", "._sites.",
                      ".in-addr.arpa", ".ip6.arpa")
    return any(marker in lowered for marker in benign_markers)


def detect_dns_tunneling(pcap, limit):
    """Long DNS query names suggest tunneling/exfil. Non-overlapping tiers:
       suspicious = 50 < len <= 100, certain = len > 100.
       Benign AD/SRV service records are excluded first (see helper)."""
    rows = run_tshark(pcap, "dns.flags.response == 0 && dns.qry.name",
                      ["dns.qry.name"])
    names = [r[0] for r in rows if r and r[0]]
    if not names:
        return None
    # Drop benign AD/SRV/PTR chatter before measuring length.
    names = [n for n in names if not _looks_like_ad_service_record(n)]
    suspicious = [n for n in names if 50 < len(n) <= 100]
    certain = [n for n in names if len(n) > 100]
    if not suspicious and not certain:
        return None

    severity = "high" if certain else "medium"
    # Pull all matches, drop benign service records, then keep `limit` samples.
    # (extract_packet_evidence slices to its limit arg, so request everything.)
    raw_ev = extract_packet_evidence(
        pcap, "dns.flags.response == 0 && dns.qry.name",
        extra_fields=["dns.qry.name"], limit=10**9,
    )
    ev = [e for e in raw_ev
          if not _looks_like_ad_service_record(e.details.get("name", ""))][:limit]
    top = Counter(e.src_ip for e in ev if e.src_ip).most_common(1)
    top_src = f" — top source: {top[0][0]}" if top else ""
    msg = (f"{len(certain)} query name(s) >100 chars and {len(suspicious)} "
           f"in the 50–100 band — possible DNS tunneling/exfil{top_src}")
    return Finding(
        category="dns",
        severity=severity,
        title="DNS tunneling indicators",
        message=msg,
        wireshark_filter="dns.flags.response == 0 && frame.len > 100 && dns.qry.name",
        evidence=ev,
    )


def detect_http_brute_force(pcap, limit):
    """Bursts of HTTP 401 responses indicate auth brute forcing."""
    rows = run_tshark(pcap, "http.response.code == 401", ["http.response.code"])
    count = len(rows)
    if count < 10:
        return None
    ev = extract_packet_evidence(
        pcap, "http.response.code == 401",
        extra_fields=["http.host", "http.request.uri"], limit=limit,
    )
    # On responses src is the server; offenders are the destinations, but for
    # consistency we surface whoever the requests came from where available.
    top = Counter(e.dst_ip for e in ev if e.dst_ip).most_common(1)
    top_src = f" — top source: {top[0][0]}" if top else ""
    sev = "high" if count >= 100 else "medium"
    return Finding(
        category="http",
        severity=sev,
        title="HTTP auth brute force",
        message=f"{count} HTTP 401 responses{top_src}",
        wireshark_filter="http.response.code == 401",
        evidence=ev,
    )


# URI substrings that strongly suggest scanning/exploitation attempts.
_URI_PATTERNS = [
    "../", "..%2f", "etc/passwd", "cmd=", "/bin/", "union+select",
    "union%20select", "<script", "%3cscript", "sqlmap", "nikto",
    ".php?id=", "wp-login", "/.git/", "/.env",
]


def _check_uri_pattern_group(pcap, limit):
    """Suspicious URI patterns. Emits a VALID Wireshark filter using proper
    'or' chaining (previous version emitted literal '(and others)')."""
    rows = run_tshark(pcap, "http.request", ["http.request.uri"])
    uris = [r[0] for r in rows if r and r[0]]
    if not uris:
        return None

    hit_patterns = sorted({
        p for p in _URI_PATTERNS
        for u in uris if p.lower() in u.lower()
    })
    if not hit_patterns:
        return None

    # Proper "or" chaining — every clause is a real contains() expression.
    clauses = [f'http.request.uri contains "{p}"' for p in hit_patterns]
    wfilter = " or ".join(clauses)

    ev = extract_packet_evidence(
        pcap, wfilter, extra_fields=["http.host", "http.request.uri"], limit=limit,
    )
    top = Counter(e.src_ip for e in ev if e.src_ip).most_common(1)
    top_src = f" — top source: {top[0][0]}" if top else ""
    return Finding(
        category="http",
        severity="medium",
        title="Suspicious HTTP URI patterns",
        message=(f"{len(hit_patterns)} suspicious URI pattern(s) seen "
                 f"({', '.join(hit_patterns)}){top_src}"),
        wireshark_filter=wfilter,
        evidence=ev,
    )


def detect_ftp_credentials(pcap, limit):
    """Cleartext FTP USER/PASS and transferred filenames."""
    rows = run_tshark(
        pcap,
        'ftp.request.command == "USER" || ftp.request.command == "PASS" '
        '|| ftp.request.command == "RETR" || ftp.request.command == "STOR"',
        ["ftp.request.command"],
    )
    if not rows:
        return None
    ev = extract_packet_evidence(
        pcap,
        'ftp.request.command == "USER" || ftp.request.command == "PASS" '
        '|| ftp.request.command == "RETR" || ftp.request.command == "STOR"',
        extra_fields=["ftp.request.command", "ftp.request.arg"], limit=limit,
    )
    top = Counter(e.src_ip for e in ev if e.src_ip).most_common(1)
    top_src = f" — top source: {top[0][0]}" if top else ""
    return Finding(
        category="ftp",
        severity="high",
        title="Cleartext FTP activity",
        message=f"{len(rows)} FTP credential/transfer command(s){top_src}",
        wireshark_filter="ftp.request.command",
        evidence=ev,
    )


def detect_kerberos_accounts(pcap, limit):
    """Kerberos account name harvesting (CNameString) — AS-REQ enumeration."""
    rows = run_tshark(pcap, "kerberos.CNameString", ["kerberos.CNameString"])
    accounts = sorted({r[0] for r in rows if r and r[0]})
    if not accounts:
        return None
    ev = extract_packet_evidence(
        pcap, "kerberos.CNameString",
        extra_fields=["kerberos.CNameString"], limit=limit,
    )
    top = Counter(e.src_ip for e in ev if e.src_ip).most_common(1)
    top_src = f" — top source: {top[0][0]}" if top else ""
    # v2.1: surface the actual names. v2.0 only reported a count, which is why
    # "brolf" never appeared in the report even though the tool "saw" it.
    shown = ", ".join(accounts[:10]) + ("…" if len(accounts) > 10 else "")
    return Finding(
        category="kerberos",
        severity="medium",
        title="Kerberos account names observed",
        message=(f"{len(accounts)} distinct Kerberos account name(s): "
                 f"{shown}{top_src}"),
        wireshark_filter="kerberos.CNameString",
        evidence=ev,
    )


def detect_smb_access(pcap, limit):
    """SMB tree connect paths (shares being accessed)."""
    rows = run_tshark(pcap, "smb.path || smb2.tree",
                      ["smb.path", "smb2.tree"])
    if not rows:
        return None
    ev = extract_packet_evidence(
        pcap, "smb.path || smb2.tree",
        extra_fields=["smb.path", "smb2.tree"], limit=limit,
    )
    top = Counter(e.src_ip for e in ev if e.src_ip).most_common(1)
    top_src = f" — top source: {top[0][0]}" if top else ""
    return Finding(
        category="smb",
        severity="low",
        title="SMB share access",
        message=f"{len(rows)} SMB tree connect(s){top_src}",
        wireshark_filter="smb.path || smb2.tree",
        evidence=ev,
    )


def detect_icmp_sweep(pcap, limit):
    """One source hitting many destinations over ICMP echo = host sweep."""
    rows = run_tshark(pcap, "icmp.type == 8", ["ip.src", "ip.dst"])
    if not rows:
        return None
    dst_by_src = defaultdict(set)
    for r in rows:
        if len(r) >= 2 and r[0] and r[1]:
            dst_by_src[r[0]].add(r[1])
    sweepers = {s: d for s, d in dst_by_src.items() if len(d) >= 5}
    if not sweepers:
        return None
    worst = max(sweepers, key=lambda s: len(sweepers[s]))
    sample_dsts = sorted(sweepers[worst])[:10]
    ev = extract_packet_evidence(
        pcap, f'icmp.type == 8 && ip.src == {worst}',
        extra_fields=["data.len"], limit=limit,
    )
    return Finding(
        category="icmp",
        severity="medium",
        title="ICMP host sweep",
        message=(f"{worst} echo-requested {len(sweepers[worst])} hosts "
                 f"— top source: {worst}; sample dsts: {', '.join(sample_dsts)}"),
        wireshark_filter=f"icmp.type == 8 && ip.src == {worst}",
        evidence=ev,
    )


def detect_arp_spoofing(pcap, limit):
    """Same IP claimed by more than one MAC = ARP spoofing / conflict."""
    rows = run_tshark(
        pcap, "arp.opcode == 2",
        ["arp.src.proto_ipv4", "arp.src.hw_mac"],
    )
    macs_by_ip = defaultdict(set)
    for r in rows:
        if len(r) >= 2 and r[0] and r[1]:
            macs_by_ip[r[0]].add(r[1])
    conflicts = {ip: m for ip, m in macs_by_ip.items() if len(m) > 1}
    if not conflicts:
        return None
    ip0 = sorted(conflicts)[0]
    ev = extract_packet_evidence(
        pcap, f'arp.opcode == 2 && arp.src.proto_ipv4 == {ip0}',
        extra_fields=["arp.src.hw_mac"], limit=limit, l2=True,
    )
    detail = "; ".join(
        f"{ip} claimed by {len(m)} MACs ({', '.join(sorted(m))})"
        for ip, m in sorted(conflicts.items())
    )
    return Finding(
        category="arp",
        severity="high",
        title="ARP spoofing / MAC conflict",
        message=f"{len(conflicts)} IP(s) with conflicting MACs — {detail}",
        wireshark_filter="arp.opcode == 2",
        evidence=ev,
    )


def detect_tcp_syn_scan(pcap, limit):
    """Many SYNs (no ACK) from one source to many ports = SYN scan."""
    rows = run_tshark(
        pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ["ip.src", "tcp.dstport"],
    )
    ports_by_src = defaultdict(set)
    for r in rows:
        if len(r) >= 2 and r[0] and r[1]:
            ports_by_src[r[0]].add(r[1])
    scanners = {s: p for s, p in ports_by_src.items() if len(p) >= 20}
    if not scanners:
        return None
    worst = max(scanners, key=lambda s: len(scanners[s]))
    sample_ports = sorted(scanners[worst], key=lambda p: int(p) if p.isdigit() else 0)[:15]
    ev = extract_packet_evidence(
        pcap, f"tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {worst}",
        extra_fields=["tcp.dstport"], limit=limit,
    )
    return Finding(
        category="tcp",
        severity="high",
        title="TCP SYN scan",
        message=(f"{worst} sent SYNs to {len(scanners[worst])} ports "
                 f"— top source: {worst}; sample ports: {', '.join(sample_ports)}"),
        wireshark_filter=f"tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {worst}",
        evidence=ev,
    )


# --------------------------------------------------------------------------- #
# v2.1 detections: host-centric IR signals
# --------------------------------------------------------------------------- #
# User-Agent substrings tied to commodity remote-control / RAT tooling. A match
# is high-confidence corroboration, NOT a precondition — a beacon with a blank
# or browser-spoofed UA is still a beacon. Extend this list as you encounter
# new families.
_SUSPECT_USER_AGENTS = [
    "netsupport manager",     # NetSupport RAT (abused commodity remote-control)
    "nsm",
]

# SAMR fields that carry a user's display ("full") name. Both are confirmed-real
# Wireshark field names (verified via `tshark -G fields`); UserInfo21 is the
# usual QueryUserInfo level, DispEntryGeneral shows up in EnumDomainUsers.
_SAMR_FULLNAME_FIELDS = [
    "samr.samr_UserInfo21.full_name",
    "samr.samr_DispEntryGeneral.full_name",
]


def _is_external_ipv4(ip: str) -> bool:
    """True only for a routable, internet-facing IPv4 address. Anything in
    RFC1918 / loopback / link-local / multicast / reserved is treated as
    'internal' so C2 detection looks at *egress to the internet* and ignores
    intra-LAN chatter (which other detections cover)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


# Beacon tuning knobs. A C2 heartbeat is defined by *regular spacing*, not
# volume, so we require a minimum number of requests AND that a majority of the
# inter-request gaps cluster tightly around the median.
_BEACON_MIN_REQUESTS = 6      # too few requests to call anything a cadence
_BEACON_MIN_INTERVAL = 1.0    # seconds; below this it's a burst, not a beacon
_BEACON_TOLERANCE = 0.25      # gaps within ±25% of the median count as "regular"
_BEACON_REGULARITY = 0.5      # ≥50% of gaps must be regular to flag

# Host-header suffixes for routine OS/telemetry/PKI traffic that is periodic by
# nature (Windows Update, telemetry, OCSP/CRL, Adobe/Mozilla updaters). A
# candidate destination whose Host headers are ALL benign is suppressed so we
# don't cry "C2" at Microsoft's CDN. Real C2 to a bare IP has an IP-literal (or
# absent) Host header, which never matches, so it survives this filter.
_BENIGN_BEACON_HOSTS = (
    "microsoft.com", "windowsupdate.com", "windows.com", "msftconnecttest.com",
    "msftncsi.com", "office.com", "office.net", "live.com", "microsoftonline.com",
    "azureedge.net", "akamaized.net", "digicert.com", "verisign.com",
    "sectigo.com", "letsencrypt.org", "adobe.com", "mozilla.org", "mozilla.net",
    "googleapis.com", "gstatic.com", "apple.com",
)


def _is_benign_host(host: str) -> bool:
    """True if a Host header is a known OS/telemetry/PKI endpoint (suffix match)."""
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in _BENIGN_BEACON_HOSTS)


def detect_c2_beaconing(pcap, limit):
    """Regular-interval HTTP requests to a routable (external) IP — the classic
    'check in every N seconds' pattern of a RAT/implant calling home.

    v2.0 was blind to this: it looked for scans and brute force, so a single
    infected host quietly POSTing to its C2 once a minute produced no finding
    at all. We reconstruct a per-destination request timeline, measure the
    spacing, and flag destinations whose gaps are suspiciously regular.
    """
    rows = run_tshark(
        pcap, "http.request",
        ["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
         "http.request.method", "http.host", "http.user_agent"],
    )
    # Bucket every outbound request to an external IP by destination.
    # Each entry: (epoch, src, dport, method, host, user_agent)
    per_dst = defaultdict(list)
    for r in rows:
        r = r + [""] * (7 - len(r))
        epoch, src, dst, dport, method, host, ua = r[:7]
        if not dst or not _is_external_ipv4(dst):
            continue
        try:
            per_dst[dst].append((float(epoch), src, dport, method, host, ua))
        except ValueError:
            continue

    # Score each candidate destination for beacon-like regularity.
    beacons = []  # (dst, n_requests, median_interval, regularity, indicators, top_src)
    for dst, events in per_dst.items():
        if len(events) < _BEACON_MIN_REQUESTS:
            continue
        # Suppress routine OS/telemetry/PKI: if every Host header for this
        # destination is a known-benign endpoint, it isn't C2. (A missing/empty
        # Host header does NOT qualify as benign — bare-IP C2 has no domain.)
        host_headers = [h for (_, _, _, _, h, _) in events if h]
        if host_headers and all(_is_benign_host(h) for h in host_headers):
            continue
        events.sort(key=lambda e: e[0])
        times = [e[0] for e in events]
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < _BEACON_MIN_REQUESTS - 1:
            continue
        median_gap = statistics.median(gaps)
        if median_gap < _BEACON_MIN_INTERVAL:
            continue  # a tight burst (e.g. a file download), not a heartbeat
        band = _BEACON_TOLERANCE * median_gap
        regular = sum(1 for g in gaps if abs(g - median_gap) <= band)
        regularity = regular / len(gaps)
        if regularity < _BEACON_REGULARITY:
            continue

        # Corroborating indicators that this external endpoint is hostile.
        hosts = {h for (_, _, _, _, h, _) in events if h}
        uas = {u for (_, _, _, _, _, u) in events if u}
        dports = {p for (_, _, p, _, _, _) in events if p}
        indicators = []
        if dst in hosts:                       # Host header is the bare IP
            indicators.append("IP-literal Host header")
        if "443" in dports:                    # cleartext HTTP on the TLS port
            indicators.append("cleartext HTTP on port 443")
        matched_ua = sorted(
            u for u in uas
            if any(s in u.lower() for s in _SUSPECT_USER_AGENTS)
        )
        if matched_ua:
            indicators.append(f"known-RAT user-agent ({'; '.join(matched_ua)})")

        top_src = Counter(s for (_, s, _, _, _, _) in events if s).most_common(1)
        beacons.append((
            dst, len(events), median_gap, regularity,
            indicators, top_src[0][0] if top_src else "",
        ))

    if not beacons:
        return None

    # Report the busiest beacon; note any others in the message.
    beacons.sort(key=lambda b: b[1], reverse=True)
    dst, n, gap, reg, indicators, top_src = beacons[0]

    # A known-RAT user-agent is near-certain; otherwise a regular external
    # beacon is still high severity.
    severity = "critical" if any("known-RAT" in i for i in indicators) else "high"

    ev = extract_packet_evidence(
        pcap, f"http.request and ip.dst == {dst}",
        extra_fields=["http.request.method", "http.request.full_uri",
                      "http.user_agent"],
        limit=limit,
    )
    ind_txt = f" [{'; '.join(indicators)}]" if indicators else ""
    others = (f"; {len(beacons) - 1} other external beacon destination(s)"
              if len(beacons) > 1 else "")
    src_txt = f"{top_src} -> " if top_src else ""
    return Finding(
        category="c2",
        severity=severity,
        title="External C2 beaconing",
        message=(f"{src_txt}{dst}: {n} HTTP requests at a regular "
                 f"~{gap:.0f}s interval ({reg * 100:.0f}% of gaps){ind_txt}"
                 f"{others}"),
        wireshark_filter=f"http.request and ip.dst == {dst}",
        evidence=ev,
    )


def _nbns_hostname_for(pcap):
    """Map internal IP -> NetBIOS machine name.

    With `-E occurrence=f` tshark renders nbns.name as bare 'HOST<20>' (no
    descriptive text), so we classify by the NetBIOS *suffix* byte rather than
    a description string:
        <20> = unique Server service  -> reliable machine name
        <00> = Workstation (unique) OR workgroup (group) -> ambiguous
        <1b>/<1c>/<1d>/<1e> = domain/browser roles -> workgroup, never a host
    A name seen with <20> is taken as the host name. Failing that, we accept a
    <00> name only if it never also appears with a group/browser suffix (which
    would mark it as the workgroup, e.g. EASYAS123)."""
    rows = run_tshark(pcap, "nbns.name", ["ip.src", "nbns.name"])
    GROUP_SUFFIXES = {"1b", "1c", "1d", "1e"}
    suffixes_by = defaultdict(lambda: defaultdict(set))   # ip -> base -> {suffix}
    for r in rows:
        if len(r) < 2 or not r[0] or not r[1]:
            continue
        ip = r[0]
        first = r[1].split(",")[0].strip()      # defensive: drop joined extras
        if "<" not in first or ">" not in first:
            continue
        base = first.split("<", 1)[0].strip()
        suffix = first.split("<", 1)[1].split(">", 1)[0].strip().lower()
        if base:
            suffixes_by[ip][base].add(suffix)

    resolved = {}
    for ip, bases in suffixes_by.items():
        # Prefer a name registered as a unique Server service (<20>).
        machine = [b for b, sfx in bases.items() if "20" in sfx]
        if not machine:
            # Fallback: a <00> name that is NOT also a group/browser name.
            machine = [b for b, sfx in bases.items()
                       if "00" in sfx and not (sfx & GROUP_SUFFIXES)]
        if machine:
            # Stable choice if several qualify.
            resolved[ip] = sorted(machine)[0]
    return resolved


def _mac_for(pcap, ip):
    """Most frequently observed source MAC for an internal IP."""
    rows = run_tshark(pcap, f"ip.src == {ip}", ["eth.src"])
    macs = Counter(r[0] for r in rows if r and r[0])
    return macs.most_common(1)[0][0] if macs else ""


def detect_host_identity(pcap, limit):
    """Attribution, not attack detection: tie internal IPs to MAC, hostname,
    Kerberos user account(s) and SAMR full name(s). Once another finding points
    at a suspicious internal IP, this answers the 'which machine / which user'
    questions an incident report has to fill in — the part v2.0 left as a bare
    count ('1 distinct Kerberos account name') instead of an actual identity.
    """
    # --- Kerberos user accounts, keyed by the client IP that presented them ---
    # Restrict to packets *toward* the KDC (dst port 88) so the user maps to the
    # requesting workstation, not the Domain Controller that echoes the name
    # back in AS-REP/TGS-REP.
    users_by_ip = defaultdict(set)
    for r in run_tshark(
        pcap,
        "kerberos.CNameString && (tcp.dstport == 88 || udp.dstport == 88)",
        ["ip.src", "kerberos.CNameString"],
    ):
        if len(r) >= 2 and r[0] and r[1]:
            users_by_ip[r[0]].add(r[1])

    # --- NetBIOS hostnames ---
    hostnames = _nbns_hostname_for(pcap)

    # --- SAMR full names (display names). Collected globally; the natural link
    #     to an account is the account name itself (e.g. brolf -> Becka Rolf). ---
    full_names = set()
    fullname_filter = " || ".join(_SAMR_FULLNAME_FIELDS)
    for r in run_tshark(pcap, fullname_filter, _SAMR_FULLNAME_FIELDS):
        for val in r:
            if val:
                full_names.add(val)

    # Build a profile for every internal IP we learned anything about.
    profile_ips = set(users_by_ip) | set(hostnames)
    profile_ips = {ip for ip in profile_ips if _is_internal_ipv4(ip)}
    if not profile_ips and not full_names:
        return None

    lines = []
    for ip in sorted(profile_ips):
        parts = [ip]
        mac = _mac_for(pcap, ip)
        if mac:
            parts.append(f"mac={mac}")
        if ip in hostnames:
            parts.append(f"host={hostnames[ip]}")
        if users_by_ip.get(ip):
            parts.append(f"users={','.join(sorted(users_by_ip[ip]))}")
        lines.append(" ".join(parts))
    msg = " | ".join(lines) if lines else "no per-host identity resolved"
    if full_names:
        msg += f" || full names observed: {', '.join(sorted(full_names))}"

    ev = extract_packet_evidence(
        pcap,
        "nbns.name || kerberos.CNameString || " + fullname_filter,
        extra_fields=["nbns.name", "kerberos.CNameString"] + _SAMR_FULLNAME_FIELDS,
        limit=limit,
    )
    return Finding(
        category="host",
        severity="info",
        title="Host / user attribution",
        message=msg,
        wireshark_filter=("nbns.name || kerberos.CNameString || "
                          + fullname_filter),
        evidence=ev,
    )


def _is_internal_ipv4(ip: str) -> bool:
    """Inverse of _is_external_ipv4, but specifically: a valid IPv4 that is
    private. Used to keep host profiles to LAN assets."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


DETECTIONS = [
    detect_dns_tunneling,
    detect_http_brute_force,
    _check_uri_pattern_group,
    detect_ftp_credentials,
    detect_kerberos_accounts,
    detect_smb_access,
    detect_icmp_sweep,
    detect_arp_spoofing,
    detect_tcp_syn_scan,
    detect_c2_beaconing,
    detect_host_identity,
]


# --------------------------------------------------------------------------- #
# Top offenders aggregation
# --------------------------------------------------------------------------- #
def aggregate_offenders(findings):
    """
    Aggregate source IPs from all finding evidence across all categories.
    Returns a list of dicts ranked by hit count; IPs appearing in 3+
    categories are flagged as multi-vector.
    """
    hits = Counter()
    cats = defaultdict(set)
    for f in findings:
        # 'host' is attribution/enrichment, not an attack vector — counting its
        # evidence would list every named LAN box as an "offender".
        if f.category == "host":
            continue
        for e in f.evidence:
            if e.src_ip:
                hits[e.src_ip] += 1
                cats[e.src_ip].add(f.category)
    offenders = []
    for ip, count in hits.most_common():
        categories = sorted(cats[ip])
        offenders.append({
            "ip": ip,
            "hits": count,
            "categories": categories,
            "multi_vector": len(categories) >= 3,
        })
    return offenders


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _banner():
    return f"pcap_triage v{VERSION} — Wireshark PCAP Triage"


def render_terminal(pcap, findings, offenders):
    lines = [_banner(), "=" * len(_banner()), f"File: {pcap}", ""]
    if not findings:
        lines.append("No findings.")
        print("\n".join(lines))
        return

    lines.append("== Top Offenders ==")
    if offenders:
        for o in offenders[:10]:
            flag = "  [MULTI-VECTOR]" if o["multi_vector"] else ""
            lines.append(f"  {o['ip']:<18} {o['hits']:>4} hits  "
                         f"({', '.join(o['categories'])}){flag}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("== Findings ==")
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
        lines.append(f"\n[{f.severity.upper()}] {f.title}")
        lines.append(f"  {f.message}")
        lines.append(f"  filter: {f.wireshark_filter}")
        if f.evidence:
            lines.append("  evidence:")
            for e in f.evidence:
                lines.append(f"    {e.render()}")
    print("\n".join(lines))


def render_markdown(pcap, findings, offenders, path):
    L = [f"# {_banner()}", "", f"**File:** `{pcap}`", ""]
    L += ["## Top Offenders", ""]
    if offenders:
        L += ["| Source IP | Hits | Categories | Multi-vector |",
              "|---|---|---|---|"]
        for o in offenders:
            mv = "**yes**" if o["multi_vector"] else "no"
            L.append(f"| {o['ip']} | {o['hits']} | {', '.join(o['categories'])} | {mv} |")
    else:
        L.append("_None._")
    L += ["", "## Findings", ""]
    if not findings:
        L.append("_No findings._")
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
        L += [f"### [{f.severity.upper()}] {f.title}", "",
              f"{f.message}", "",
              f"- **Wireshark filter:** `{f.wireshark_filter}`"]
        if f.evidence:
            L.append("- **Evidence:**")
            L.append("")
            L.append("```")
            for e in f.evidence:
                L.append(e.render())
            L.append("```")
        L.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(L))
    print(f"[+] Markdown report written to {path}", file=sys.stderr)


def render_json(pcap, findings, offenders, path):
    doc = {
        "tool": "pcap_triage",
        "version": VERSION,
        "file": pcap,
        "top_offenders": offenders,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "message": f.message,
                "wireshark_filter": f.wireshark_filter,
                "top_source": f.top_source(),
                "evidence": [asdict(e) for e in f.evidence],
            }
            for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
        ],
    }
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(f"[+] JSON report written to {path}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None):
    p = argparse.ArgumentParser(
        description="Fast first-pass triage of a PCAP using tshark.")
    p.add_argument("pcap", help="path to the .pcap/.pcapng file")
    p.add_argument("--md", metavar="FILE", help="write a Markdown report")
    p.add_argument("--json", metavar="FILE", help="write a JSON report")
    p.add_argument("--evidence", type=int, default=10, metavar="N",
                   help="evidence sample size per finding (default 10)")
    p.add_argument("--version", action="version",
                   version=f"pcap_triage {VERSION}")
    args = p.parse_args(argv)

    if shutil.which("tshark") is None:
        _warn("tshark not found on PATH — install Wireshark CLI tools.")
        return 2

    if args.evidence < 1:
        _warn("--evidence must be >= 1; using 1")
        args.evidence = 1

    findings = []
    for det in DETECTIONS:
        try:
            f = det(args.pcap, args.evidence)
        except Exception as exc:  # never let one detection abort the run
            _warn(f"{det.__name__} failed: {exc}")
            f = None
        if f:
            findings.append(f)

    offenders = aggregate_offenders(findings)

    render_terminal(args.pcap, findings, offenders)
    if args.md:
        render_markdown(args.pcap, findings, offenders, args.md)
    if args.json:
        render_json(args.pcap, findings, offenders, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
