"""
app.py
------
Step 3 of the pipeline: the Streamlit user interface.

This file only DISPLAYS results. Parsing lives in pcap_parser.py and all
calculations live in analysis.py.

Run:  streamlit run app.py
"""

import os
import tempfile

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import analysis as an
from pcap_parser import parse_pcap, PcapParseError

st.set_page_config(page_title="PCAP Network Traffic Dashboard", layout="wide")


# ---- Parse once per uploaded file; Streamlit reuses the cached result ----
@st.cache_data(show_spinner="Parsing capture with pyshark/tshark ...")
def load_capture(file_bytes, suffix):
    """Save the upload to a temp file (tshark needs a path) and parse it."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        path = tmp.name
    try:
        return parse_pcap(path)
    finally:
        os.remove(path)               # do not leave capture data on disk


# ------------------------------------------------------------ Sidebar
st.sidebar.title("PCAP Dashboard")
st.sidebar.caption("Cyber Security Lab 7CS4-22 | Exp 4: Wireshark / tcpdump, TCP & UDP")
uploaded = st.sidebar.file_uploader("Upload .pcap / .pcapng", type=["pcap", "pcapng"])
top_n = st.sidebar.slider("Rows in Top-N tables", 5, 20, 10)
bin_s = st.sidebar.selectbox("Timeline bin size (seconds)", [1, 2, 5], index=0)
st.sidebar.subheader("Detection thresholds")
sigma = st.sidebar.slider("Spike rule: mean + k x std-dev", 1.0, 5.0, 2.0, 0.5)
min_ports = st.sidebar.slider("Port scan: min distinct ports", 5, 100, 15)
syn_limit = st.sidebar.slider("SYN flood: min SYN per second", 20, 500, 100)
st.sidebar.warning("Analyse only captures you own or generated yourself "
                   "(IT Act 2000, Sections 43 & 66).")

st.title("PCAP Network Traffic Dashboard")

if uploaded is None:
    st.info("Upload a capture file in the sidebar to begin. "
            "No file yet? Run `python generate_sample_pcap.py` to create a "
            "safe synthetic one.")
    st.stop()

# ------------------------------------------------------------ Load data
try:
    suffix = os.path.splitext(uploaded.name)[1]
    df, skipped = load_capture(uploaded.getvalue(), suffix)
except PcapParseError as err:
    st.error(str(err))
    st.stop()

if skipped:
    st.warning(f"{skipped} packet(s) could not be decoded and were skipped.")

tabs = st.tabs(["Overview", "Protocols", "Top Talkers",
                "Ports & Services", "Timeline & Alerts", "Packet Inspector"])

# ------------------------------------------------------------ Tab 1
with tabs[0]:
    k = an.compute_kpis(df)
    c = st.columns(5)
    c[0].metric("Total packets", f"{k['total_packets']:,}")
    c[1].metric("Data volume", f"{k['total_bytes']:,} B")
    c[2].metric("Duration", f"{k['duration_s']} s")
    c[3].metric("Avg packet rate", f"{k['avg_pps']} pkt/s")
    c[4].metric("Unique IPs", k["unique_ips"])
    st.caption(f"File: {uploaded.name} | average packet size {k['avg_packet_size']} bytes")

# ------------------------------------------------------------ Tab 2
with tabs[1]:
    dist = an.protocol_distribution(df)
    left, right = st.columns(2)
    left.plotly_chart(px.pie(dist, names="proto", values="packets",
                             title="Protocol share (by packets)"),
                      width="stretch")
    right.plotly_chart(px.bar(dist, x="proto", y="bytes",
                              title="Bytes per protocol"),
                       width="stretch")
    st.dataframe(dist, width="stretch", hide_index=True)

# ------------------------------------------------------------ Tab 3
with tabs[2]:
    src, dst, pairs = an.top_talkers(df, top_n)
    a, b = st.columns(2)
    a.subheader("Top source IPs")
    a.plotly_chart(px.bar(src, x="src", y="packets"), width="stretch")
    a.dataframe(src, hide_index=True, width="stretch")
    b.subheader("Top destination IPs")
    b.plotly_chart(px.bar(dst, x="dst", y="packets"), width="stretch")
    b.dataframe(dst, hide_index=True, width="stretch")
    st.subheader("Top IP-to-IP pairs (directional, by bytes)")
    st.dataframe(pairs, hide_index=True, width="stretch")
    st.subheader("Conversations (both directions merged, like Wireshark)")
    st.dataframe(an.conversations(df, top_n), hide_index=True,
                 width="stretch")

# ------------------------------------------------------------ Tab 4
with tabs[3]:
    t_col, u_col = st.columns(2)
    for col, name in ((t_col, "TCP"), (u_col, "UDP")):
        ports = an.port_analysis(df, name, top_n)
        col.subheader(f"Top {name} destination ports")
        if ports.empty:
            col.info(f"No {name} traffic in this capture.")
            continue
        ports["label"] = ports["port"].astype(str) + " (" + ports["service"] + ")"
        col.plotly_chart(px.bar(ports, x="label", y="packets"),
                         width="stretch")
        col.dataframe(ports.drop(columns="label"), hide_index=True,
                      width="stretch")
    st.subheader("TCP flag distribution")
    flags = an.tcp_flag_distribution(df)
    st.plotly_chart(px.bar(flags, x="flag", y="packets"), width="stretch")
    st.dataframe(flags, hide_index=True, width="stretch")

# ------------------------------------------------------------ Tab 5
with tabs[4]:
    tl = an.build_timeline(df, bin_s)
    spikes_p = an.detect_spikes(tl, "packets", sigma)
    spikes_b = an.detect_spikes(tl, "bytes", sigma)

    fig = px.line(tl, x="second", y="packets", title="Packets per bin")
    fig.add_trace(go.Scatter(x=spikes_p["second"], y=spikes_p["packets"],
                             mode="markers", name="Spike",
                             marker=dict(color="red", size=11)))
    st.plotly_chart(fig, width="stretch")

    fig2 = px.line(tl, x="second", y="bytes", title="Bytes per bin")
    fig2.add_trace(go.Scatter(x=spikes_b["second"], y=spikes_b["bytes"],
                              mode="markers", name="Spike",
                              marker=dict(color="red", size=11)))
    st.plotly_chart(fig2, width="stretch")

    st.subheader("Security alerts (heuristics)")
    scans = an.detect_port_scan(df, min_ports)
    floods = an.detect_syn_flood(df, syn_limit)
    if scans.empty and floods.empty and spikes_p.empty:
        st.success("No suspicious patterns found with the current thresholds.")
    if not scans.empty:
        st.error("Possible PORT SCAN: one source probing many ports of one target")
        st.dataframe(scans, hide_index=True, width="stretch")
    if not floods.empty:
        st.error("Possible SYN FLOOD: very high rate of SYN-only packets")
        st.dataframe(floods, hide_index=True, width="stretch")
    if not spikes_p.empty:
        st.warning("Traffic spike(s) above the statistical threshold")
        st.dataframe(spikes_p, hide_index=True, width="stretch")
    st.caption("These are heuristics. A flag means 'worth investigating', "
               "not proof of an attack.")

# ------------------------------------------------------------ Tab 6
with tabs[5]:
    f1, f2 = st.columns([1, 2])
    protos = f1.multiselect("Protocol", sorted(df["proto"].unique()))
    text = f2.text_input("Search (IP, port, flags or info text)")
    view = df
    if protos:
        view = view[view["proto"].isin(protos)]
    if text:
        # build one searchable string per row and look for the text in it
        hay = view.astype(str).agg(" ".join, axis=1)
        view = view[hay.str.contains(text, case=False, regex=False)]
    st.write(f"Showing {len(view):,} of {len(df):,} packets")
    st.dataframe(view, hide_index=True, width="stretch", height=400)

    st.download_button("Download packets (CSV)", view.to_csv(index=False),
                       "packets.csv", "text/csv")
    # Summary report = the main tables stacked into one CSV-style text file
    report = ["PCAP ANALYSIS REPORT", f"File: {uploaded.name}", "",
              "KPIs", pd.Series(an.compute_kpis(df)).to_csv(header=False), "",
              "Protocols", an.protocol_distribution(df).to_csv(index=False), "",
              "Conversations", an.conversations(df, top_n).to_csv(index=False), "",
              "TCP ports", an.port_analysis(df, "TCP", top_n).to_csv(index=False)]
    st.download_button("Download analysis report (TXT)", "\n".join(report),
                       "analysis_report.txt", "text/plain")
