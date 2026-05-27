feat(triage): attach packet evidence and offender aggregation to findings

Findings previously surfaced only counts and Wireshark filters; an analyst
had to re-run the filter to learn who did it, when, or what URL was hit.
This change pulls representative packet samples directly into the report
and aggregates source IPs across findings, eliminating that pivot step
for the majority of investigations.

Key additions:

* PacketEvidence dataclass — captures frame number, ISO timestamp, full
  5-tuple, and a flexible details dict for protocol-specific fields
  (URI, query name, User-Agent, etc.). Includes a one-line renderer
  for terminal/markdown density.

* extract_packet_evidence() — single helper every detection now uses.
  Pulls the standard fields plus any caller-requested protocol fields
  in one tshark call. Handles ARP's L2 addressing as a special case.

* Top Offenders summary block — aggregates source IPs from all finding
  evidence across all categories, ranks by hit count, and flags IPs
  appearing in 3+ categories as multi-vector activity. Provides a
  single "where do I start" view between findings and reference data.

* Finding messages now embed top source IP inline — e.g. "487 HTTP 401
  responses — top source: 192.168.1.50". The most valuable signal for
  brute force and scanner findings is visible at first glance.

* New --evidence N CLI flag — controls evidence sample size per finding
  (default 10). Higher values useful for forensic deep-dives.

Refactored detections — each now attaches protocol-relevant evidence:
  - DNS: query names (the encoded tunnel data itself)
  - HTTP: URI, Host, User-Agent
  - FTP: usernames, passwords, filenames per command type
  - Kerberos: account names (CNameString)
  - SMB: tree path
  - ICMP: payload length; sweep findings include sample destinations
  - ARP: conflicting MAC per claim
  - TCP scans: sample ports for SYN scans

Bug fixes:

* _check_uri_pattern_group now emits a valid Wireshark filter using
  proper "or" chaining. Previous version output literal text
  "(and others)" that errored out when analysts tried to verify.

* DNS length tiering reworked to non-overlapping ranges (suspicious is
  now 50 < len <= 100, certain is len > 100). Previous logic dropped
  the moderate band entirely when very-long names existed.

* run_tshark_raw now emits a timeout warning instead of silently
  returning empty output, matching run_tshark behavior.

* Version bumped to 2.0 in banner.
