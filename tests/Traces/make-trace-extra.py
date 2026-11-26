#!/usr/bin/env python3
"""Generate tests/Traces/extra.pcap (requires scapy): ThreatDefence source
and CyberStrikeAI implant check-in pairing. Addresses match
tests/Files/threatdefence.tsv and tests/Files/feed.ndjson:
  10.2.0.0/16    local
  91.92.1.x    ThreatDefence rows
  45.33.1.10     listed by offensive.agency AND ThreatDefence
  77.88.2.x      unlisted Internet hosts
"""
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location(
    "mt", os.path.join(os.path.dirname(os.path.abspath(__file__)), "make-trace.py"))
mt = importlib.util.module_from_spec(spec)
sys.argv, argv = [sys.argv[0], os.devnull], sys.argv   # base trace -> /dev/null
spec.loader.exec_module(mt)
sys.argv = argv
mt.pkts.clear()
http, dns, tcp_session = mt.http, mt.dns, mt.tcp_session
TRUNC = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TOK = "X-Session-Token: " + "ab" * 32

# a. TP Outbound_To_Agent_Host: local -> ThreatDefence medium IP (ARTEX C2).
http("10.2.1.5", 41001, "91.92.1.10", 80)
# b. TP Inbound_From_Agent_Host: ThreatDefence high IP completes a handshake.
tcp_session("91.92.1.11", 53001, "10.2.1.80", 443, b"\x16\x03\x01\x00\x05hello")
# c. FP guard: low-confidence row.
http("10.2.1.5", 41002, "91.92.1.12", 80)
# d. FP guard: row past its review_by date.
http("10.2.1.5", 41003, "91.92.1.13", 80)
# e. FP guard: row whose context says VPN exit.
http("10.2.1.5", 41004, "91.92.1.14", 80)
# f. FP guard: a range row is never watched.
http("10.2.1.5", 41005, "91.92.1.70", 80)
# g. TP Agent_Domain_Contact: ThreatDefence high domain (skimmer host).
dns("10.2.1.7", 34001, "10.2.1.53", "cdn.skimmer-test.example", 0x2001)
# h. FP guard: generic service on td_ignore_indicators.
dns("10.2.1.7", 34002, "10.2.1.53", "webhook.site", 0x2002)
# i. Domain covered by a signature: one Agent_Running_Locally, no domain hit.
dns("10.2.1.8", 34003, "10.2.1.53", "update.pentagi.com", 0x2003)
# j. In both sources: one Outbound notice, offensive.agency agents, both contexts.
http("10.2.1.9", 41006, "45.33.1.10", 8787, host="45.33.1.10:8787")
# l. TP implant: truncated Chrome UA on POST /check_in; no weak finding.
http("10.2.1.6", 41007, "77.88.2.5", 80, method="POST", uri="/check_in",
     headers=[TRUNC, "Content-Length: 0"])
# m. TP implant: curl one-liner task poll with a 64-hex X-Session-Token.
http("10.2.1.10", 41008, "77.88.2.6", 8080, uri="/tasks?session_id=" + "ab" * 32,
     headers=["User-Agent: curl/8.5.0", TOK])
# n. FP guard: truncated UA on GET /check_in stays weak (Agent_Low_Confidence).
http("10.2.1.11", 41009, "77.88.2.7", 80, uri="/check_in", headers=[TRUNC])
# o. FP guard: X-Session-Token that is not 64 hex on POST /check_in: nothing.
http("10.2.1.12", 41010, "77.88.2.8", 80, method="POST", uri="/check_in",
     headers=["User-Agent: attendance-app/2.1", "X-Session-Token: s3ss10n", "Content-Length: 0"])

mt.wrpcap(sys.argv[1] if len(sys.argv) > 1 else "extra.pcap", mt.pkts)
