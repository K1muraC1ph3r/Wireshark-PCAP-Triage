#!/usr/bin/env python3
"""
pcap_triage.py — fast first-pass triage of a PCAP using tshark.

Surfaces common offensive/IR signals (DNS tunneling, HTTP brute force and
suspicious URIs, FTP credentials, Kerberos account harvesting, SMB tree
access, ICMP sweeps, ARP spoofing, TCP SYN scans), attaches representative
packet evidence to every finding, and aggregates the worst source IPs into a
single "Top Offenders" view.

Usage:
    ./pcap_triage.py capture.pcap
    ./pcap_triage.py capture.pcap --md report.md
    ./pcap_triage.py capture.pcap --json report.json
    ./pcap_triage.py capture.pcap --md report.md --json report.json
    ./pcap_triage.py capture.pcap --evidence 25      # more samples per finding

Requires: tshark (Wireshark CLI) on PATH.
"""

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

VERSION = "2.0"
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
    rows = run_tshark(pcap, display_filter, fields, extra_args=["-c", str(max(limit, 1))])

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
def detect_dns_tunneling(pcap, limit):
    """Long DNS query names suggest tunneling/exfil. Non-overlapping tiers:
       suspicious = 50 < len <= 100, certain = len > 100."""
    rows = run_tshark(pcap, "dns.flags.response == 0 && dns.qry.name",
                      ["dns.qry.name"])
    names = [r[0] for r in rows if r and r[0]]
    if not names:
        return None
    suspicious = [n for n in names if 50 < len(n) <= 100]
    certain = [n for n in names if len(n) > 100]
    if not suspicious and not certain:
        return None

    severity = "high" if certain else "medium"
    ev = extract_packet_evidence(
        pcap, "dns.flags.response == 0 && dns.qry.name",
        extra_fields=["dns.qry.name"], limit=limit,
    )
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
    return Finding(
        category="kerberos",
        severity="medium",
        title="Kerberos account names observed",
        message=f"{len(accounts)} distinct Kerberos account name(s){top_src}",
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
