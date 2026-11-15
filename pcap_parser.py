"""
pcap_parser.py
--------------
Step 1 of the pipeline: read a .pcap/.pcapng file with pyshark and turn it
into ONE flat pandas DataFrame (one row per packet).

Everything after this step (statistics, charts, security checks) works on
that DataFrame only, so the parsing logic is kept in this single file.

How pyshark works (viva answer):
    pyshark does not parse packets itself. It starts the `tshark` program as a
    child process, tells it to dump every packet as XML, reads that XML and
    wraps each <packet> in a Python object with layers (pkt.ip, pkt.tcp ...).
"""

import asyncio
import pandas as pd
import pyshark

# TCP flag bits inside the 1-byte flags field of the TCP header.
TCP_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04,
                 "PSH": 0x08, "ACK": 0x10, "URG": 0x20}

# Columns of the DataFrame, defined once so empty results still have a shape.
COLUMNS = ["no", "time", "length", "src", "dst", "proto", "transport",
           "sport", "dport", "flags", "info"]


class PcapParseError(Exception):
    """Raised when the file is empty, corrupt or not a capture file."""


def classify_protocol(layer_names):
    """
    Decide the single 'protocol' label shown for a packet.

    layer_names is the list of layers tshark found, e.g.
    ['eth', 'ip', 'tcp', 'http']. We pick the most specific
    application protocol first, then fall back to the transport protocol.
    """
    names = set(layer_names)
    # Application layer protocols (most specific first)
    for app in ("dns", "http", "tls", "ssl", "ssh", "ntp"):
        if app in names:
            return "TLS" if app == "ssl" else app.upper()
    # Network / transport layer protocols
    if "icmp" in names or "icmpv6" in names:
        return "ICMP"
    if "arp" in names:
        return "ARP"
    if "tcp" in names:
        return "TCP"
    if "udp" in names:
        return "UDP"
    return "OTHER"


def flags_to_text(flag_value):
    """Convert the TCP flags number (e.g. 0x12) into text like 'SYN,ACK'."""
    active = [name for name, bit in TCP_FLAG_BITS.items() if flag_value & bit]
    return ",".join(active) if active else "NONE"


def _get_addresses(pkt, names):
    """Return (src, dst) for IPv4, IPv6 or ARP packets. '' if none."""
    if "ip" in names:
        return pkt.ip.src, pkt.ip.dst
    if "ipv6" in names:
        return pkt.ipv6.src, pkt.ipv6.dst
    if "arp" in names:
        return pkt.arp.src_proto_ipv4, pkt.arp.dst_proto_ipv4
    return "", ""


def _get_info(pkt, names):
    """Small human readable note for the packet inspector table."""
    try:
        if "dns" in names:
            return "DNS " + str(pkt.dns.qry_name)
        if "http" in names and hasattr(pkt.http, "request_method"):
            return f"HTTP {pkt.http.request_method} {pkt.http.request_uri}"
        if "arp" in names:
            return f"ARP who has {pkt.arp.dst_proto_ipv4}?"
    except AttributeError:
        pass
    return ""


def parse_pcap(path, max_packets=50000):
    """
    Read a capture file and return (DataFrame, skipped_count).

    max_packets protects the browser from huge files.
    """
    # Streamlit runs scripts in a worker thread that has no asyncio event
    # loop, and pyshark needs one. Create it here.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    rows, skipped = [], 0
    capture = None
    try:
        # keep_packets=False -> do not hold every packet in RAM
        capture = pyshark.FileCapture(path, keep_packets=False)
        for number, pkt in enumerate(capture, start=1):
            if number > max_packets:
                break
            try:
                names = [layer.layer_name for layer in pkt.layers]
                src, dst = _get_addresses(pkt, names)

                sport = dport = None
                flags = ""
                transport = "OTHER"
                if "tcp" in names:
                    transport = "TCP"
                    sport, dport = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
                    flags = flags_to_text(int(pkt.tcp.flags, 16))
                elif "udp" in names:
                    transport = "UDP"
                    sport, dport = int(pkt.udp.srcport), int(pkt.udp.dstport)
                elif "icmp" in names or "icmpv6" in names:
                    transport = "ICMP"
                elif "arp" in names:
                    transport = "ARP"

                rows.append({
                    "no": number,
                    "time": float(pkt.sniff_timestamp),   # epoch seconds
                    "length": int(pkt.length),            # bytes on the wire
                    "src": src, "dst": dst,
                    "proto": classify_protocol(names),
                    "transport": transport,
                    "sport": sport, "dport": dport,
                    "flags": flags,
                    "info": _get_info(pkt, names),
                })
            except (AttributeError, ValueError):
                skipped += 1      # a packet we could not read; count and go on
    except Exception as err:      # tshark missing, corrupt file, etc.
        raise PcapParseError(f"Could not read capture file: {err}") from err
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                pass

    if not rows:
        raise PcapParseError("No packets found. The file is empty or not a "
                             "valid .pcap/.pcapng capture.")
    return pd.DataFrame(rows, columns=COLUMNS), skipped
