# app.py
import streamlit as st
import pandas as pd
import time, json, random, hashlib, rsa
from datetime import datetime

# ------------------------------
# Helper crypto functions
# ------------------------------
def generate_keys(bits=512):
    return rsa.newkeys(bits)

def compute_hash(data_dict):
    # hash over sorted JSON of content keys only (exclude hash & signature)
    payload = json.dumps(data_dict, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()

def sign_payload(data_dict, privkey):
    payload = json.dumps(data_dict, sort_keys=True).encode()
    signature = rsa.sign(payload, privkey, 'SHA-256')
    return signature.hex()

def verify_signature(data_dict, signature_hex, pubkey):
    try:
        signature = bytes.fromhex(signature_hex)
        rsa.verify(json.dumps(data_dict, sort_keys=True).encode(), signature, pubkey)
        return True
    except Exception:
        return False

# ------------------------------
# Attack simulation functions
# ------------------------------
def tamper_packet(packet):
    # change a sensed value drastically
    packet = packet.copy()
    packet["temperature"] = round(random.uniform(50, 80), 2)
    return packet

def replay_packet(packet_history):
    if packet_history:
        return random.choice(packet_history).copy()
    return None

def spoof_node(packet):
    packet = packet.copy()
    packet["node_id"] = 999  # unknown ID
    return packet

# ------------------------------
# Node simulation utilities
# ------------------------------
NODES_DEFAULT = [
    {"id": 1, "location": (12.9716, 77.5946), "name": "Node-1 (Bengaluru)"},
    {"id": 2, "location": (13.0827, 80.2707), "name": "Node-2 (Chennai)"},
    {"id": 3, "location": (19.0760, 72.8777), "name": "Node-3 (Mumbai)"}
]

def create_packet(node):
    data = {
        "node_id": node["id"],
        "node_name": node.get("name", ""),
        "location": node["location"],
        "timestamp": int(time.time()),
        "temperature": round(random.uniform(20, 35), 2),
        "humidity": round(random.uniform(40, 90), 2),
        "energy_level": round(random.uniform(40, 100), 2)
    }
    return data

# ------------------------------
# Streamlit UI + State init
# ------------------------------
st.set_page_config(page_title="🔐 Secure WSN Dashboard (Single-file)", layout="wide")
st.title("🔐 Secure Wireless Sensor Network")

# session state for persistence
if "pubkey" not in st.session_state:
    pubkey, privkey = generate_keys(512)
    st.session_state.pubkey = pubkey
    st.session_state.privkey = privkey
    st.session_state.nodes = NODES_DEFAULT.copy()
    st.session_state.packet_history = []  # list of raw packets (dict)
    st.session_state.display_history = []  # evaluated packets with status
    st.session_state.logs = []
    st.session_state.running = False
    st.session_state.iteration = 0
    st.session_state.drop_prob = 0.05  # packet loss baseline
    st.session_state.latency_ms = []

# Sidebar controls
st.sidebar.header("Simulation Controls")
attack_mode = st.sidebar.selectbox("Attack Mode", ["None", "Tamper Data", "Replay Attack", "Node Spoofing"])
packet_rate = st.sidebar.slider("Packets per second (per node)", min_value=1, max_value=5, value=1)
batch_interval = 1.0 / packet_rate  # seconds between batches
show_nodes = st.sidebar.checkbox("Show node locations", value=False)
drop_prob = st.sidebar.slider("Simulated packet loss probability", 0.0, 0.5, value=float(st.session_state.drop_prob))
st.session_state.drop_prob = drop_prob

st.sidebar.markdown("---")
st.sidebar.markdown("**Actions**")
start_btn = st.sidebar.button("Start Simulation")
stop_btn = st.sidebar.button("Stop Simulation")
clear_btn = st.sidebar.button("Clear History & Logs")

# top row: summary KPIs
col1, col2, col3, col4 = st.columns([1,1,1,1])
with col1:
    total_packets = len(st.session_state.display_history)
    st.metric("Total packets processed", total_packets)
with col2:
    alerts = sum(1 for p in st.session_state.display_history if p.get("status") == "❌ Alert")
    st.metric("Security Alerts", alerts)
with col3:
    avg_latency = round((sum(st.session_state.latency_ms)/len(st.session_state.latency_ms)) if st.session_state.latency_ms else 0, 2)
    st.metric("Avg Latency (ms)", avg_latency)
with col4:
    loss_pct = round((st.session_state.get("lost_packets",0) / st.session_state.iteration * 100) if st.session_state.iteration>0 else 0, 2)
    st.metric("Packet Loss (%)", loss_pct)

st.markdown("---")

# layout containers
left_col, right_col = st.columns([2,1])
with left_col:
    data_placeholder = st.empty()
    charts_col = st.container()
with right_col:
    st.subheader("Attack Log")
    log_box = st.empty()
    st.subheader("QoS Controls / Info")
    st.write(f"Packet rate: **{packet_rate} pkt/s per node**")
    st.write(f"Attack Mode: **{attack_mode}**")
    st.write("You can change controls anytime. Click **Stop Simulation** to halt.")
    if show_nodes:
        st.subheader("Nodes")
        for n in st.session_state.nodes:
            st.write(f"- ID {n['id']}: {n['name']} @ {n['location']}")

# clear handler
if clear_btn:
    st.session_state.packet_history = []
    st.session_state.display_history = []
    st.session_state.logs = []
    st.session_state.iteration = 0
    st.session_state.latency_ms = []
    st.session_state.lost_packets = 0
    st.success("Cleared history & logs.")

# start/stop handlers
if start_btn:
    st.session_state.running = True
if stop_btn:
    st.session_state.running = False

# helper to evaluate packet (hash + signature + node auth)
def evaluate_packet(packet_raw):
    # Expected data (without hash & signature)
    content = {k:v for k,v in packet_raw.items() if k not in ("hash","signature")}
    # recompute hash
    recomputed_hash = compute_hash(content)
    valid_hash = recomputed_hash == packet_raw.get("hash")
    valid_signature = False
    try:
        valid_signature = verify_signature(content, packet_raw.get("signature",""), st.session_state.pubkey)
    except Exception:
        valid_signature = False
    # node auth
    node_ids = [n["id"] for n in st.session_state.nodes]
    authorized = packet_raw.get("node_id") in node_ids
    status = "✅ Secure" if (valid_hash and valid_signature and authorized) else "❌ Alert"
    return status, valid_hash, valid_signature, authorized

# single simulation tick (one batch across all nodes)
def simulation_tick():
    start_time = time.time()
    results = []
    for node in st.session_state.nodes:
        # create raw sensed data
        base = create_packet(node)
        # compute hash & signature using private key
        h = compute_hash(base)
        sig = sign_payload(base, st.session_state.privkey)
        packet = base.copy()
        packet["hash"] = h
        packet["signature"] = sig

        # simulate packet loss
        if random.random() < st.session_state.drop_prob:
            # dropped
            st.session_state.lost_packets = st.session_state.get("lost_packets", 0) + 1
            st.session_state.logs.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"Packet DROPPED from Node {node['id']}"))
            continue

        # optionally apply attack
        if attack_mode == "Tamper Data":
            packet = tamper_packet(packet)
        elif attack_mode == "Replay Attack":
            replayed = replay_packet(st.session_state.packet_history)
            if replayed:
                packet = replayed
        elif attack_mode == "Node Spoofing":
            packet = spoof_node(packet)

        # simulate network latency (ms)
        latency = random.uniform(20, 300)  # ms
        st.session_state.latency_ms.append(latency)

        # mark arrival time
        packet["recv_time"] = int(time.time())
        packet["sim_latency_ms"] = round(latency, 2)

        # store raw
        st.session_state.packet_history.append(packet)

        # evaluate security
        status, valid_hash, valid_sig, authorized = evaluate_packet(packet)
        display_pkt = packet.copy()
        display_pkt["status"] = status
        display_pkt["valid_hash"] = valid_hash
        display_pkt["valid_signature"] = valid_sig
        display_pkt["authorized"] = authorized
        results.append(display_pkt)

        # logging
        if status == "❌ Alert":
            reason = []
            if not valid_hash: reason.append("hash mismatch")
            if not valid_sig: reason.append("invalid signature")
            if not authorized: reason.append("unauthorized node")
            st.session_state.logs.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"ALERT Node {display_pkt['node_id']}: " + ", ".join(reason)))
    end_time = time.time()
    st.session_state.iteration += 1
    return results, (end_time - start_time)*1000.0

# Main simulation loop
tick_placeholder = st.empty()
if st.session_state.running:
    # run until stopped
    try:
        # We'll run a tick per batch_interval and update UI each tick.
        results, proc_time_ms = simulation_tick()
        if results:
            st.session_state.display_history.extend(results)

        # Limit display history size to avoid memory explosion
        if len(st.session_state.display_history) > 2000:
            st.session_state.display_history = st.session_state.display_history[-1000:]
        # Build DataFrame for display (latest 50)
        df = pd.DataFrame(st.session_state.display_history)
        if not df.empty:
            # format timestamps
            if "timestamp" in df.columns:
                df["ts"] = df["timestamp"].apply(lambda x: datetime.fromtimestamp(x).strftime("%H:%M:%S"))
            display_df = df[["node_id","node_name","ts","temperature","humidity","energy_level","sim_latency_ms","status"]].tail(50)
            data_placeholder.dataframe(display_df, use_container_width=True)
        else:
            data_placeholder.write("No packets yet.")

        # Charts: Temperature & Energy lines (per node)
        with charts_col:
            st.subheader("Live Charts")
            chart_df = pd.DataFrame(st.session_state.display_history)
            if not chart_df.empty:
                # pivot temp per node
                temp_pivot = chart_df.pivot_table(index=chart_df.index, columns="node_name", values="temperature").ffill().bfill()
                energy_pivot = chart_df.pivot_table(index=chart_df.index, columns="node_name", values="energy_level").ffill().bfill()
                # show charts
                c1, c2 = st.columns(2)
                with c1:
                    st.text("Temperature (latest readings)")
                    st.line_chart(temp_pivot.tail(100))
                with c2:
                    st.text("Energy Levels (%)")
                    st.line_chart(energy_pivot.tail(100))
                # status counts
                status_counts = chart_df["status"].value_counts().reindex(["✅ Secure","❌ Alert"]).fillna(0)
                st.bar_chart(status_counts)

        # Update logs
        if st.session_state.logs:
            logs_df = pd.DataFrame(st.session_state.logs, columns=["time","event"]).tail(30)
            log_box.dataframe(logs_df, use_container_width=True)
        else:
            log_box.write("No logs yet.")

        # small sleep to control rate
        time.sleep(batch_interval)
        # rerun to update UI (Streamlit will preserve session_state)
        st.experimental_rerun()
    except Exception as e:
        st.session_state.running = False
        st.error(f"Simulation stopped due to error: {e}")
else:
    # Not running: show last saved state
    df = pd.DataFrame(st.session_state.display_history)
    if not df.empty:
        if "timestamp" in df.columns:
            df["ts"] = df["timestamp"].apply(lambda x: datetime.fromtimestamp(x).strftime("%H:%M:%S"))
        display_df = df[["node_id","node_name","ts","temperature","humidity","energy_level","sim_latency_ms","status"]].tail(50)
        data_placeholder.dataframe(display_df, use_container_width=True)
    else:
        data_placeholder.write("Simulation is stopped. Click Start Simulation to begin producing live packets.")

    # show charts snapshot
    with charts_col:
        st.subheader("Charts snapshot")
        chart_df = pd.DataFrame(st.session_state.display_history)
        if not chart_df.empty:
            temp_pivot = chart_df.pivot_table(index=chart_df.index, columns="node_name", values="temperature").ffill().bfill()
            energy_pivot = chart_df.pivot_table(index=chart_df.index, columns="node_name", values="energy_level").ffill().bfill()
            st.text("Temperature (latest readings)")
            st.line_chart(temp_pivot.tail(100))
            st.text("Energy Levels (%)")
            st.line_chart(energy_pivot.tail(100))

    # show logs
    if st.session_state.logs:
        logs_df = pd.DataFrame(st.session_state.logs, columns=["time","event"]).tail(30)
        log_box.dataframe(logs_df, use_container_width=True)
    else:
        log_box.write("No logs yet.")

st.markdown("---")
st.caption("Single-file demo: custom hashing + RSA signing, attack simulation (tamper/replay/spoof), QoS simulation (latency, packet loss), and live visualization. Good for demonstration and learning — extendable to multi-process / Colab sender for a true distributed demo.")
