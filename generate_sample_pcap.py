"""
generate_sample_pcap.py
-----------------------
Creates a SAFE, SYNTHETIC capture file (sample_traffic.pcap).

Ethical note (IT Act 2000, Sections 43 & 66):
    Nothing here touches a real network. Packets are built in memory with
    scapy and written to a file. Only private RFC 1918 addresses
    (192.168.1.x and 10.0.0.x) and dummy data are used.

The capture contains five phases over about 60 seconds:
    1. Normal background traffic (DNS, HTTP, HTTPS-like TCP, ICMP, ARP, UDP)
    2. A port scan   : 10.0.0.66 -> 192.168.1.10, many different ports
    3. A SYN burst   : 10.0.0.99 -> 192.168.1.10:80, many SYNs, no ACKs
    4. A traffic spike (bulk transfer) so the timeline shows a peak
    Phases 2-4 are there so the dashboard's heuristics have something to flag.

Run:  python generate_sample_pcap.py
"""

import random
from scapy.all import (Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP,
                       Raw, wrpcap)

random.seed(42)  # fixed seed -> same file every run, so test results repeat

# ---- Dummy hosts (all private RFC 1918 addresses) ----
CLIENTS = ["192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23"]
WEB_SERVER = "192.168.1.10"
DNS_SERVER = "192.168.1.1"
EXT_HOST = "10.0.0.50"     # pretend "outside" host, still private
SCANNER = "10.0.0.66"
FLOODER = "10.0.0.99"

packets = []
BASE = 1_794_000_000   # arbitrary start time (Nov 2026) so dates look sensible


def mac(ip):
    """
    Invent a fixed fake MAC address from an IP (192.168.1.20 -> 02:00:c0:a8:01:14).
    Setting MACs ourselves stops scapy from sending real ARP requests on
    your network to discover them, so this script never touches a real network.
    """
    return "02:00:" + ":".join(f"{int(part):02x}" for part in ip.split("."))


def eth(src_ip, dst_ip):
    """Ethernet header with fake source and destination MAC addresses."""
    return Ether(src=mac(src_ip), dst=mac(dst_ip))


def add(pkt, t):
    """Stamp a packet with an explicit timestamp and store it."""
    pkt.time = BASE + t
    packets.append(pkt)


def tcp_session(client, server, dport, t, payload=b""):
    """Build a full TCP lifecycle: handshake, one data exchange, close."""
    sport = random.randint(40000, 60000)
    base = eth(client, server) / IP(src=client, dst=server)
    add(base / TCP(sport=sport, dport=dport, flags="S", seq=100), t)
    add(eth(server, client) / IP(src=server, dst=client) /
        TCP(sport=dport, dport=sport, flags="SA", seq=300, ack=101), t + 0.01)
    add(base / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=301),
        t + 0.02)
    if payload:
        add(base / TCP(sport=sport, dport=dport, flags="PA", seq=101,
                       ack=301) / Raw(payload), t + 0.03)
        add(eth(server, client) / IP(src=server, dst=client) /
            TCP(sport=dport, dport=sport, flags="PA", seq=301,
                ack=101 + len(payload)) /
            Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"), t + 0.05)
    add(base / TCP(sport=sport, dport=dport, flags="FA"), t + 0.08)
    add(eth(server, client) / IP(src=server, dst=client) /
        TCP(sport=dport, dport=sport, flags="FA"), t + 0.09)


def dns_query(client, name, t):
    """One DNS request + response pair."""
    sport = random.randint(40000, 60000)
    add(eth(client, DNS_SERVER) / IP(src=client, dst=DNS_SERVER) / UDP(sport=sport, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=name)), t)
    add(eth(DNS_SERVER, client) / IP(src=DNS_SERVER, dst=client) / UDP(sport=53, dport=sport) /
        DNS(qr=1, qd=DNSQR(qname=name),
            an=DNSRR(rrname=name, rdata="192.168.1.10")), t + 0.02)


# ---------- Phase 1: normal traffic, t = 0..60 s ----------
names = ["intranet.lab.local", "files.lab.local", "mail.lab.local"]
for i in range(40):
    t = random.uniform(0, 58)
    client = random.choice(CLIENTS)
    kind = random.choice(["dns", "http", "tls", "ssh", "icmp", "ntp", "arp"])
    if kind == "dns":
        dns_query(client, random.choice(names), t)
    elif kind == "http":
        tcp_session(client, WEB_SERVER, 80, t,
                    b"GET /index.html HTTP/1.1\r\nHost: intranet.lab.local\r\n\r\n")
    elif kind == "tls":
        # Raw bytes shaped like a TLS record header (content type 0x16)
        tcp_session(client, WEB_SERVER, 443, t,
                    b"\x16\x03\x01\x00\x05hello")
    elif kind == "ssh":
        tcp_session(client, EXT_HOST, 22, t, b"SSH-2.0-OpenSSH_9.6\r\n")
    elif kind == "icmp":
        add(eth(client, WEB_SERVER) / IP(src=client, dst=WEB_SERVER) / ICMP(type=8) /
            Raw(b"abcdefgh"), t)
        add(eth(WEB_SERVER, client) / IP(src=WEB_SERVER, dst=client) / ICMP(type=0) /
            Raw(b"abcdefgh"), t + 0.01)
    elif kind == "ntp":
        add(eth(client, EXT_HOST) / IP(src=client, dst=EXT_HOST) / UDP(sport=50123, dport=123)
            / Raw(b"\x1b" + b"\x00" * 47), t)
    else:
        add(Ether(src=mac(client), dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=mac(client), psrc=client, pdst=WEB_SERVER), t)

# ---------- Phase 2: port scan (t = 20..22 s) ----------
for i, port in enumerate(range(1, 41)):          # 40 different ports
    t = 20 + i * 0.05
    add(eth(SCANNER, WEB_SERVER) / IP(src=SCANNER, dst=WEB_SERVER) /
        TCP(sport=44444, dport=port, flags="S"), t)
    add(eth(WEB_SERVER, SCANNER) / IP(src=WEB_SERVER, dst=SCANNER) /
        TCP(sport=port, dport=44444, flags="RA"), t + 0.001)

# ---------- Phase 3: SYN burst (t = 35..36 s) ----------
for i in range(150):                              # 150 SYNs in ~1 second
    t = 35 + i * 0.0066
    add(eth(FLOODER, WEB_SERVER) / IP(src=FLOODER, dst=WEB_SERVER) /
        TCP(sport=random.randint(1025, 65000), dport=80, flags="S"), t)

# ---------- Phase 4: bulk transfer spike (t = 48..50 s) ----------
for i in range(200):
    t = 48 + i * 0.01
    add(eth(WEB_SERVER, CLIENTS[0]) / IP(src=WEB_SERVER, dst=CLIENTS[0]) /
        TCP(sport=80, dport=51000, flags="A") / Raw(b"X" * 1200), t)

packets.sort(key=lambda p: p.time)               # keep time order in the file
wrpcap("sample_traffic.pcap", packets)
print(f"Wrote {len(packets)} synthetic packets to sample_traffic.pcap")
