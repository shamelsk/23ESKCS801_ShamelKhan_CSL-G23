"""
test_analysis.py - automated checks (run with: pytest -v)
Uses a tiny hand-made DataFrame so expected answers are known in advance.
"""
import pandas as pd
import pytest
import analysis as an
from pcap_parser import parse_pcap, PcapParseError


def make_df(rows):
    cols = ["no", "time", "length", "src", "dst", "proto", "transport",
            "sport", "dport", "flags", "info"]
    return pd.DataFrame(rows, columns=cols)


def small_capture():
    return make_df([
        [1, 0.0, 100, "192.168.1.2", "192.168.1.1", "DNS", "UDP", 5000, 53, "", ""],
        [2, 0.5, 200, "192.168.1.1", "192.168.1.2", "DNS", "UDP", 53, 5000, "", ""],
        [3, 1.0, 300, "192.168.1.2", "10.0.0.5", "TCP", "TCP", 6000, 80, "SYN", ""],
        [4, 2.0, 400, "10.0.0.5", "192.168.1.2", "TCP", "TCP", 80, 6000, "SYN,ACK", ""],
    ])


def test_kpis():
    k = an.compute_kpis(small_capture())
    assert k["total_packets"] == 4
    assert k["total_bytes"] == 1000
    assert k["duration_s"] == 2.0
    assert k["avg_pps"] == 2.0
    assert k["unique_ips"] == 3


def test_protocol_percent():
    d = an.protocol_distribution(small_capture()).set_index("proto")
    assert d.loc["DNS", "packets"] == 2
    assert d.loc["DNS", "percent"] == 50.0


def test_top_source():
    src, _, _ = an.top_talkers(small_capture(), 5)
    assert src.iloc[0]["src"] == "192.168.1.2" and src.iloc[0]["packets"] == 2


def test_service_map():
    assert an.service_name(443) == "HTTPS"
    assert an.service_name(60000) == "Ephemeral"
    assert an.service_name(1234) == "Unknown"


def test_port_scan_detected():
    rows = [[i, i * 0.1, 60, "10.0.0.66", "192.168.1.10", "TCP", "TCP",
             4444, 1000 + i, "SYN", ""] for i in range(30)]
    assert len(an.detect_port_scan(make_df(rows), min_ports=15)) == 1


def test_no_port_scan_on_few_ports():
    rows = [[i, i * 0.1, 60, "10.0.0.7", "192.168.1.10", "TCP", "TCP",
             4444, 80, "SYN", ""] for i in range(30)]   # same port repeated
    assert an.detect_port_scan(make_df(rows), min_ports=15).empty


def test_syn_flood_detected():
    rows = [[i, i * 0.005, 60, "10.0.0.99", "192.168.1.10", "TCP", "TCP",
             1000 + i, 80, "SYN", ""] for i in range(150)]
    assert len(an.detect_syn_flood(make_df(rows), 100)) == 1


def test_spike_detected():
    tl = pd.DataFrame({"second": range(10), "packets": [5] * 9 + [500],
                       "bytes": [1] * 10})
    assert list(an.detect_spikes(tl, "packets", 2.0)["second"]) == [9]


# ---- end-to-end tests that need tshark and the sample file ----
def test_sample_pcap_counts():
    df, _ = parse_pcap("sample_traffic.pcap")
    assert len(df) == 572                      # matches Wireshark's frame count
    assert df["length"].sum() == 272410        # matches Wireshark's byte count


def test_empty_file_rejected(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapParseError):
        parse_pcap(str(p))


def test_corrupt_file_rejected(tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"this is not a capture file" * 20)
    with pytest.raises(PcapParseError):
        parse_pcap(str(p))
