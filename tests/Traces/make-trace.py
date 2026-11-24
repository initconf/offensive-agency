#!/usr/bin/env python3
"""Generate tests/Traces/offensive-agency.pcap (requires scapy).

Every flow is synthetic. Addresses match tests/Files/feed.ndjson:
  10.1.0.0/16  local (RFC 1918, local by default in Zeek)
  45.33.1.x    feed-listed agent hosts
  77.88.1.x    unlisted Internet hosts

Each scenario is either a true positive that must produce exactly one
notice, or a must-not-fire case that guards a noise control.
"""
import sys
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap

pkts = []
t = [1764000000.0]   # 2025-11-24, fixed for reproducible output


def at(p):
    t[0] += 0.01
    p.time = t[0]
    pkts.append(p)


def tcp_session(src, sport, dst, dport, req=b"", resp=b"", established=True):
    e = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
    c, s = 1000, 5000
    at(e / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=c))
    if not established:
        return
    at(e / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1))
    at(e / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1))
    c += 1
    s += 1
    if req:
        at(e / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=c, ack=s) / req)
        c += len(req)
        at(e / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=s, ack=c))
    if resp:
        at(e / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=s, ack=c) / resp)
        s += len(resp)
        at(e / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=c, ack=s))
    at(e / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=c, ack=s))
    at(e / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=s, ack=c + 1))
    at(e / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1))


def http(src, sport, dst, dport, method="GET", uri="/", host="example.org", headers=()):
    req = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\n"
    for h in headers:
        req += h + "\r\n"
    req += "\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    tcp_session(src, sport, dst, dport, req.encode(), resp)


def dns(src, sport, dst, name, txid):
    e = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
    at(e / IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name)))


# 1. TP Outbound_To_Agent_Host: local -> listed ARTEX host on its console port.
http("10.1.1.5", 40001, "45.33.1.10", 8787, host="45.33.1.10:8787")
# 2. Same local host, same agent host again: deduplicated (no 2nd notice).
http("10.1.1.5", 40002, "45.33.1.10", 8787, host="45.33.1.10:8787")
# 3. TP Inbound_From_Agent_Host: listed PentAGI host completes a handshake.
tcp_session("45.33.1.11", 50001, "10.1.1.80", 443, b"\x16\x03\x01\x00\x05hello")
# 4. Same listed host hits a second local server: still one notice per remote.
tcp_session("45.33.1.11", 50002, "10.1.1.81", 443, b"\x16\x03\x01\x00\x05hello")
# 5. FP guard: listed host only SYN-scans (never established): nothing.
tcp_session("45.33.1.12", 50003, "10.1.1.82", 22, established=False)
# 6. TP Agent_Activity_Inbound: HexStrike User-Agent from an unlisted host.
http("77.88.1.1", 51001, "10.1.1.80", 80, uri="/login",
     headers=["User-Agent: HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"])
# 7. TP Agent_Implant_Or_Webshell: CyberStrikeAI web-shell manager.
http("77.88.1.2", 51002, "10.1.1.80", 80, method="POST", uri="/uploads/x.php",
     headers=["User-Agent: Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)",
              "Content-Type: application/x-www-form-urlencoded", "Content-Length: 0"])
# 8. TP Agent_Implant_Or_Webshell: implant beacon leaving a local host.
http("10.1.1.6", 40003, "77.88.1.5", 80, uri="/check_in",
     headers=["User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
              "X-Implant-Token: 0123456789abcdef"])
# 9. TP Agent_Domain_Contact: local client resolves a listed agent domain.
dns("10.1.1.7", 33001, "10.1.1.53", "artex.agent-console.example.net", 0x1001)
# 10. TP OAST_Callback_Lookup, then a 2nd random subdomain: one notice.
dns("10.1.1.8", 33002, "10.1.1.53", "a1b2c3.dnslog.cn", 0x1002)
dns("10.1.1.8", 33003, "10.1.1.53", "z9y8x7.dnslog.cn", 0x1003)
# 11. TP Agent_Running_Locally: PentAGI installer on a local host.
http("10.1.1.9", 40004, "77.88.1.6", 80, uri="/api/v1/proxy/updates/pentagi/check",
     method="POST", host="update.pentagi.com",
     headers=["User-Agent: PentAGI-Installer/1.2.0", "Content-Length: 0"])
# 12. FP guard: weak signature alone (truncated Chrome UA inbound): log only.
http("77.88.1.3", 51003, "10.1.1.80", 80,
     headers=["User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"])
# 13. FP guard: listed CDN front (IP not inserted) ...
http("10.1.1.10", 40005, "45.33.1.20", 80, host="www.ordinary-site.example.com")
# 14. ... but its agent domain is still watched (HTTP Host): TP Agent_Domain_Contact.
http("10.1.1.11", 40006, "45.33.1.20", 80, host="cdn-agent.example.org")
# 15. FP guard: cloud IP last seen 5 days before the feed's newest day.
http("10.1.1.12", 40007, "45.33.1.21", 443)
# 16. FP guard: host with only a "probable" detection.
http("10.1.1.13", 40008, "45.33.1.22", 8443)
# 17. FP guard: transit (neither end local) to a listed host: log only.
tcp_session("77.88.1.9", 52001, "45.33.1.10", 8787, b"x")

wrpcap(sys.argv[1] if len(sys.argv) > 1 else "offensive-agency.pcap", pkts)
