"""
analysis.py
-----------
Step 2 of the pipeline: statistics and security heuristics.

Every function takes the packet DataFrame made by pcap_parser.py and returns
a small DataFrame or dict. No Streamlit and no pyshark here, so these
functions can be tested alone (see test_analysis.py).
"""

import numpy as np
import pandas as pd

# Well-known ports -> service names (a small subset of IANA's list).
SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}


def service_name(port):
    """Map a port number to a service name (ports >= 49152 are ephemeral)."""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    if port >= 49152:
        return "Ephemeral"
    return "Unknown"


# ---------------------------------------------------------------- 1. KPIs
def compute_kpis(df):
    """Headline numbers for the Overview tab."""
    duration = df["time"].max() - df["time"].min()
    unique_ips = set(df["src"]) | set(df["dst"])
    unique_ips.discard("")
    return {
        "total_packets": len(df),
        "total_bytes": int(df["length"].sum()),
        "duration_s": round(float(duration), 3),
        # packets per second = total packets / duration (guard divide by 0)
        "avg_pps": round(float(len(df) / duration), 2) if duration > 0 else float(len(df)),
        "avg_packet_size": round(float(df["length"].mean()), 1),
        "unique_ips": len(unique_ips),
    }


# ------------------------------------------------- 2. Protocol distribution
def protocol_distribution(df):
    """Packets, bytes and percentage per protocol label."""
    out = df.groupby("proto").agg(packets=("no", "count"),
                                  bytes=("length", "sum")).reset_index()
    out["percent"] = (out["packets"] / out["packets"].sum() * 100).round(2)
    return out.sort_values("packets", ascending=False).reset_index(drop=True)


# --------------------------------------------------------- 3. Top talkers
def top_talkers(df, n=10):
    """Return (top sources, top destinations, top IP pairs)."""
    # IPv4/IPv6 packets only: ARP frames are excluded, as in Wireshark's
    # Statistics > Endpoints/Conversations > IPv4 tabs
    ip_df = df[(df["src"] != "") & (df["transport"] != "ARP")]

    def rank(column):
        t = ip_df.groupby(column).agg(packets=("no", "count"),
                                      bytes=("length", "sum")).reset_index()
        return t.sort_values("packets", ascending=False).head(n)

    pairs = ip_df.groupby(["src", "dst"]).agg(
        packets=("no", "count"), bytes=("length", "sum")).reset_index()
    pairs = pairs.sort_values("bytes", ascending=False).head(n)
    return rank("src"), rank("dst"), pairs


def conversations(df, n=10):
    """
    Bidirectional conversations: A->B and B->A are merged into one row,
    which is how Wireshark's Statistics > Conversations > IPv4 counts them.
    """
    ip_df = df[(df["src"] != "") & (df["transport"] != "ARP")].copy()
    # sorted tuple makes (A,B) and (B,A) the same key
    ip_df["a"] = ip_df[["src", "dst"]].min(axis=1)
    ip_df["b"] = ip_df[["src", "dst"]].max(axis=1)
    conv = ip_df.groupby(["a", "b"]).agg(
        packets=("no", "count"), bytes=("length", "sum")).reset_index()
    return conv.sort_values("packets", ascending=False).head(n)


# -------------------------------------------------- 4. Ports and services
def port_analysis(df, transport, n=10):
    """Most used destination ports for 'TCP' or 'UDP', with service names."""
    sub = df[df["transport"] == transport].dropna(subset=["dport"])
    if sub.empty:
        return pd.DataFrame(columns=["port", "service", "packets", "bytes"])
    t = sub.groupby("dport").agg(packets=("no", "count"),
                                 bytes=("length", "sum")).reset_index()
    t = t.rename(columns={"dport": "port"})
    t["port"] = t["port"].astype(int)
    t["service"] = t["port"].map(service_name)
    return t.sort_values("packets", ascending=False).head(n).reset_index(drop=True)


def tcp_flag_distribution(df):
    """Count of TCP packets carrying each flag, plus handshake patterns."""
    tcp = df[df["transport"] == "TCP"]
    counts = {}
    for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
        # a packet 'has' the flag if the flag word is in its comma list
        counts[flag] = int(tcp["flags"].str.split(",").apply(
            lambda items, f=flag: f in items).sum())
    counts["SYN only (connection attempts)"] = int((tcp["flags"] == "SYN").sum())
    counts["SYN+ACK (replies)"] = int((tcp["flags"] == "SYN,ACK").sum())
    return pd.DataFrame({"flag": list(counts), "packets": list(counts.values())})


# ------------------------------------------------------------ 5. Timeline
def build_timeline(df, bin_seconds=1.0):
    """
    Group packets into time bins (default 1 second).
    Returns columns: second, packets, bytes. Empty bins are filled with 0
    so quiet periods show on the graph instead of being skipped.
    """
    start = df["time"].min()
    bins = ((df["time"] - start) // bin_seconds).astype(int)
    t = df.groupby(bins).agg(packets=("no", "count"),
                             bytes=("length", "sum"))
    full = range(0, int(bins.max()) + 1)
    t = t.reindex(full, fill_value=0).reset_index()
    t.columns = ["bin", "packets", "bytes"]
    t["second"] = t["bin"] * bin_seconds
    return t[["second", "packets", "bytes"]]


def detect_spikes(timeline, column="packets", sigma=3.0):
    """
    Statistical spike rule: a bin is a spike if its value is more than
    mean + sigma * standard deviation. (sigma=3 is the classic 3-sigma rule.)
    """
    mean, std = timeline[column].mean(), timeline[column].std(ddof=0)
    limit = mean + sigma * std
    return timeline[timeline[column] > limit].assign(threshold=round(limit, 1))


# ------------------------------------------------- Security heuristics
# Both detectors use a SLIDING time window, so an attack that happens to
# straddle a second/10-second boundary is not missed.

def detect_port_scan(df, min_ports=15, window_s=10.0):
    """
    Port scan heuristic (vertical scan):
        one source sends SYN-only packets to MANY DIFFERENT ports of the
        same target inside a short time window.
    Returns a DataFrame of suspects (empty if none).
    """
    cols = ["src", "dst", "distinct_ports", "first_seen_s"]
    syn = df[df["flags"] == "SYN"]
    start = df["time"].min()
    found = []
    for (src, dst), g in syn.groupby(["src", "dst"]):
        g = g.sort_values("time")
        times, ports = g["time"].tolist(), g["dport"].tolist()
        best, best_t = 0, 0.0
        for i in range(len(times)):
            # collect all ports probed in [times[i], times[i] + window_s)
            seen, j = set(), i
            while j < len(times) and times[j] < times[i] + window_s:
                seen.add(ports[j])
                j += 1
            if len(seen) > best:
                best, best_t = len(seen), times[i]
        if best >= min_ports:
            found.append((src, dst, best, round(best_t - start, 2)))
    out = pd.DataFrame(found, columns=cols)
    return out.sort_values("distinct_ports", ascending=False).reset_index(drop=True)


def detect_syn_flood(df, min_syn_per_s=100):
    """
    SYN flood heuristic:
        a target receives a very large number of SYN-only packets within
        any 1-second window (half-open connections that never complete).
    Returns one row per target that crossed the threshold.
    """
    cols = ["dst", "peak_syn_per_s", "first_seen_s", "top_source"]
    syn = df[df["flags"] == "SYN"]
    start = df["time"].min()
    found = []
    for dst, g in syn.groupby("dst"):
        g = g.sort_values("time")
        times = g["time"].to_numpy()
        # for every SYN, count how many SYNs arrive within the next 1 second
        ends = np.searchsorted(times, times + 1.0, side="left")
        counts = ends - np.arange(len(times))
        i = int(counts.argmax())
        if counts[i] >= min_syn_per_s:
            window = g.iloc[i:ends[i]]
            found.append((dst, int(counts[i]), round(times[i] - start, 2),
                          window["src"].value_counts().index[0]))
    return pd.DataFrame(found, columns=cols)
