import re
import time
import random

import streamlit as st
import plotly.graph_objects as go

from graph_intelligence.graph_intelligence import CNITopologyGraph
from graph_intelligence.agent_mesh import ReActAgentMesh, map_mitre_attack
from soar_automation.soar_orchestrator import CNISoarOrchestrator
from resilience_twin.digital_twin import CyberResilienceDigitalTwin
from behavioral_engine.sliding_window import SlidingWindowCache
from behavioral_engine.feature_extractor import FeatureExtractor
from behavioral_engine.adaptive_model import AdaptiveAnomalyDetector
from agentless_pipeline.simulator.test_normalizer import normalize_zeek_conn, validate_ocsf_record

st.set_page_config(page_title="CNI Cyber Resilience Platform", page_icon="\U0001F6E1", layout="wide")

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
CRIT_COLOR = {"Low": "#4ade80", "Medium": "#fbbf24", "High": "#f87171"}
ACTION_STYLE = {
    "monitor_and_log": ("#4ade80", "MONITORING \u2014 no active threat"),
    "autonomous_edge_isolation": ("#f87171", "AUTONOMOUS ISOLATION EXECUTED"),
    "rate_limiting_bandwidth_throttling": ("#fbbf24", "THROTTLED \u2014 awaiting human approval"),
}

st.markdown("""
<style>
.stApp { background: radial-gradient(circle at 20% 0%, #0d1520 0%, #05080c 60%); }
h1, h2, h3 { font-family: 'Courier New', monospace !important; letter-spacing: 0.5px; }
[data-testid="stMetricValue"] { font-family: 'Courier New', monospace; }
.ops-banner {
  padding: 14px 22px; border-radius: 10px; font-family: 'Courier New', monospace;
  font-size: 18px; font-weight: 700; margin-bottom: 18px; letter-spacing: 1px;
}
.term {
  background: #05080c; border: 1px solid #1c2a3a; border-radius: 8px; padding: 16px;
  font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.55;
  height: 380px; overflow-y: auto; color: #c7d3de;
}
.term .thought { color: #38bdf8; }
.term .action { color: #fbbf24; }
.term .obs { color: #4ade80; }
.cursor { display:inline-block; width:8px; height:14px; background:#38bdf8; animation: blink 1s steps(1) infinite; }
@keyframes blink { 50% { opacity: 0; } }
.badge {
  display:inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px;
  font-family: 'Courier New', monospace; border: 1px solid currentColor;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Pipeline (pure logic, no Streamlit calls -> testable in isolation)
# ---------------------------------------------------------------------------
def build_topology(mid_crit, downstream):
    """downstream: list of (name, crit) tuples hanging off the pivot asset."""
    graph = CNITopologyGraph()
    graph.add_asset("Exam_Portal_Web", anomaly_weight=0.0, dynamic_crit="Low")
    graph.add_asset("Core_Segment_Router", anomaly_weight=0.0, dynamic_crit=mid_crit)
    graph.add_communication("Exam_Portal_Web", "Core_Segment_Router", protocol="http")
    for name, crit in downstream:
        graph.add_asset(name, anomaly_weight=0.0, dynamic_crit=crit)
        graph.add_communication("Core_Segment_Router", name, protocol="modbus")
    return graph


def run_incident(anomaly_score, mid_crit, downstream):
    graph = build_topology(mid_crit, downstream)
    src, mid = "Exam_Portal_Web", "Core_Segment_Router"

    # Phase 3: register the live score on the compromised assets and reason over the graph
    graph.add_asset(src, anomaly_weight=anomaly_score, dynamic_crit="Low")
    graph.add_asset(mid, anomaly_weight=anomaly_score, dynamic_crit=mid_crit)
    mesh = ReActAgentMesh(graph)
    reasoning_logs, report = mesh.run(src)

    # Phase 4: SOAR containment decision on the pivot asset
    soar = CNISoarOrchestrator(graph)
    decision = soar.orchestrate_containment(mid)

    # Phase 5: digital twin comparison of the two real playbooks
    twin = CyberResilienceDigitalTwin(graph)
    path, sim_logs = twin.simulate_attack_propagation(src)
    isolation = twin.evaluate_playbook_impact(mid, "autonomous_edge_isolation")
    throttling = twin.evaluate_playbook_impact(mid, "rate_limiting_bandwidth_throttling")

    mitre_rows = [(node, map_mitre_attack(node if node != src else "web compromise"))
                  for node in [src] + graph.get_downstream_subgraph(src)]

    return {
        "graph": graph, "src": src, "mid": mid, "downstream": downstream,
        "reasoning_logs": reasoning_logs, "report": report, "decision": decision,
        "path": path, "sim_logs": sim_logs, "isolation": isolation, "throttling": throttling,
        "mitre_rows": mitre_rows,
    }


def run_phase1_phase2_live_test():
    """Genuinely chains Phase 1 (the real OCSF normalizer + schema validator
    from agentless_pipeline) into Phase 2 (sliding window + feature extractor
    + adaptive detector), on freshly generated raw sensor telemetry -- proves
    both phases are live code, not mocks, independent of the incident
    simulator above."""
    cache, extractor, detector = SlidingWindowCache(), FeatureExtractor(), AdaptiveAnomalyDetector(mode="learning")
    src = "10.0.5.20"
    now = time.time()
    raw_events = []
    for i in range(15):
        ts = now - (20 - i) * 8
        raw_events.append({"ts": ts, "id": {"orig_h": src, "orig_p": random.randint(1024, 65535),
                                             "resp_h": "10.0.2.5", "resp_p": random.choice([80, 443])},
                            "proto": "tcp"})
    scan_port = random.randint(20000, 40000)
    raw_events.append({"ts": now, "id": {"orig_h": src, "orig_p": random.randint(1024, 65535),
                                          "resp_h": "10.0.2.5", "resp_p": scan_port}, "proto": "tcp"})

    score, errors, normalized = 0.0, [], None
    for raw in raw_events:
        # Phase 1: real Vector-VRL-equivalent normalizer + OCSF schema validator
        normalized = normalize_zeek_conn(raw)
        errors = validate_ocsf_record(normalized)
        # Phase 2: real sliding window -> feature extraction -> adaptive scoring
        cache.add_event(src, normalized)
        window_events = cache.get_events(src, normalized["time"] / 1000.0)
        feats = extractor.extract_features(window_events, normalized)
        score = detector.score(feats)
    return raw_events[-1], normalized, errors, scan_port, score


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def render_graph(result):
    graph, src, mid, downstream = result["graph"], result["src"], result["mid"], result["downstream"]
    pos = {src: (0.5, 2.0), mid: (0.5, 1.0)}
    n = max(len(downstream), 1)
    for i, (name, _crit) in enumerate(downstream):
        pos[name] = ((i + 0.5) / n, 0.0)

    fig = go.Figure()
    annotations = []
    for u in graph.graph.nodes:
        for v in graph.graph.successors(u):
            if u in pos and v in pos:
                annotations.append(dict(
                    x=pos[v][0], y=pos[v][1], ax=pos[u][0], ay=pos[u][1],
                    xref="x", yref="y", axref="x", ayref="y",
                    showarrow=True, arrowhead=3, arrowsize=1.4, arrowwidth=1.6,
                    arrowcolor="#38bdf8", opacity=0.85,
                ))
    xs, ys, colors, sizes, labels, hover = [], [], [], [], [], []
    for node, (x, y) in pos.items():
        data = graph.graph.nodes.get(node, {})
        crit = str(data.get("dynamic_crit", "low")).capitalize()
        weight = float(data.get("anomaly_weight", 0.0))
        xs.append(x); ys.append(y)
        colors.append(CRIT_COLOR.get(crit, "#94a3b8"))
        sizes.append(46 + weight * 40)
        labels.append(node.replace("_", "<br>"))
        hover.append(f"{node}<br>Criticality: {crit}<br>Anomaly weight: {weight:.2f}")

    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text", text=labels, textposition="bottom center",
        textfont=dict(color="#c7d3de", size=11), hovertext=hover, hoverinfo="text",
        marker=dict(size=sizes, color=colors, line=dict(width=2, color="#05080c")),
    ))
    fig.update_layout(
        annotations=annotations, showlegend=False, height=380,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False, range=[-0.15, 1.15]), yaxis=dict(visible=False, range=[-0.3, 2.3]),
    )
    return fig


# ---------------------------------------------------------------------------
# Sidebar: incident controls
# ---------------------------------------------------------------------------
st.sidebar.title("\U0001F39B\uFE0F Incident Simulator")
preset = st.sidebar.selectbox(
    "Scenario", ["Reconnaissance sweep (low)", "Lateral movement (medium)", "SCADA breach (critical)", "Custom"]
)

if preset == "Reconnaissance sweep (low)":
    anomaly_score, mid_crit = 0.35, "Medium"
    downstream = [("Print_Server", "Low")]
elif preset == "Lateral movement (medium)":
    anomaly_score, mid_crit = 0.82, "High"
    downstream = [("Legacy_SCADA_Asset", "High"), ("HMI_Workstation", "High"), ("PLC_Controller_2", "High")]
elif preset == "SCADA breach (critical)":
    anomaly_score, mid_crit = 0.93, "High"
    downstream = []
else:
    anomaly_score = st.sidebar.slider("Simulated anomaly score (Phase 2 output)", 0.0, 1.0, 0.80, 0.01)
    mid_crit = st.sidebar.selectbox("Pivot asset criticality", ["Low", "Medium", "High"], index=2)
    n_downstream = st.sidebar.slider("Downstream high-value assets", 0, 6, 3)
    downstream = [(f"Downstream_Asset_{i+1}", "High") for i in range(n_downstream)]

launch = st.sidebar.button("\U0001F6A8 Launch simulated intrusion", width='stretch')
st.sidebar.caption("Graph traversal, blast-radius math, the SOAR decision matrix, and the digital-twin "
                    "comparison below all run against the real Phase 3-5 code -- nothing on this page "
                    "past the sidebar is hardcoded.")

params = (preset, anomaly_score, mid_crit, tuple(downstream))
st.session_state.setdefault("history", [])
if "result" not in st.session_state or launch or st.session_state.get("params") != params:
    st.session_state.result = run_incident(anomaly_score, mid_crit, downstream)
    st.session_state.params = params
    st.session_state.animate = True
    d = st.session_state.result["decision"]
    st.session_state.history.append({
        "Time": time.strftime("%H:%M:%S"),
        "Scenario": preset,
        "Anomaly": round(d["anomaly_weight"], 2),
        "Blast radius": round(d["blast_radius_score"], 2),
        "Action": ACTION_STYLE.get(d["containment_action"], (None, d["containment_action"]))[1],
    })
    st.session_state.history = st.session_state.history[-20:]
result = st.session_state.result

# ---------------------------------------------------------------------------
# Header + status banner
# ---------------------------------------------------------------------------
st.markdown("## \U0001F6E1\uFE0F CNI Cyber Resilience Platform")
st.caption("Autonomous IT/OT threat detection, reasoning, and response \u2014 live command center")

action = result["decision"]["containment_action"]
color, label = ACTION_STYLE.get(action, ("#94a3b8", action))
st.markdown(
    f'<div class="ops-banner" style="background:{color}22; border:1px solid {color}; color:{color};">'
    f'\u25CF {label}</div>', unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Anomaly score", f'{result["decision"]["anomaly_weight"]:.2f}')
c2.metric("Blast radius", f'{result["decision"]["blast_radius_score"]:.2f}')
c3.metric("Assets in topology", len(list(result["graph"].graph.nodes)))
recovery = result["isolation"]["recovery_window_hours"] if action == "autonomous_edge_isolation" else result["throttling"]["recovery_window_hours"]
c4.metric("Est. recovery window", f"{recovery:.2f} hrs")

with st.expander(f"\U0001F5C2\uFE0F Incident log ({len(st.session_state.history)} this session)"):
    if st.session_state.history:
        st.dataframe(list(reversed(st.session_state.history)), width='stretch', hide_index=True)
    else:
        st.caption("No incidents logged yet.")

st.divider()

# ---------------------------------------------------------------------------
# Topology + live agent reasoning
# ---------------------------------------------------------------------------
col1, col2 = st.columns([1.1, 1])
with col1:
    st.markdown("#### \U0001F310 Live topology & attack path")
    st.plotly_chart(render_graph(result), width='stretch', config={"displayModeBar": False})
    legend = "".join(f'<span class="badge" style="color:{c}; margin-right:10px;">{k}</span>' for k, c in CRIT_COLOR.items())
    st.markdown(legend, unsafe_allow_html=True)

with col2:
    st.markdown("#### \U0001F9E0 ReAct agent \u2014 live reasoning")
    clean_logs = [strip_ansi(l) for l in result["reasoning_logs"]]
    shown = "".join(
        f'<div class="{"thought" if l.startswith("Thought") else "action" if l.startswith("Action") else "obs"}">{l}</div>'
        for l in clean_logs
    )
    cursor = '<span class="cursor"></span>' if st.session_state.get("animate") else ""
    st.markdown(f'<div class="term">{shown}{cursor}</div>', unsafe_allow_html=True)
    st.session_state.animate = False

st.divider()

# ---------------------------------------------------------------------------
# Digital twin comparison
# ---------------------------------------------------------------------------
st.markdown("#### \u2696\uFE0F Digital twin \u2014 response tradeoff")
iso, thr = result["isolation"], result["throttling"]
tw1, tw2 = st.columns([1, 1])
with tw1:
    fig = go.Figure(data=[
        go.Bar(name="Downstream loss %", x=["Isolation", "Throttling"],
               y=[iso["downstream_loss_percentage"], thr["downstream_loss_percentage"]],
               marker_color=["#f87171", "#4ade80"]),
    ])
    fig.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10),
                       paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                       font=dict(color="#c7d3de"), title="Downstream assets cut off (%)")
    st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})
with tw2:
    fig2 = go.Figure(data=[
        go.Bar(name="Recovery hours", x=["Isolation", "Throttling"],
               y=[iso["recovery_window_hours"], thr["recovery_window_hours"]],
               marker_color=["#f87171", "#4ade80"]),
    ])
    fig2.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10),
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#c7d3de"), title="Recovery window (hours)")
    st.plotly_chart(fig2, width='stretch', config={"displayModeBar": False})

st.markdown("#### \U0001F3AF MITRE ATT&CK mapping")
st.dataframe(
    {"Asset": [r[0] for r in result["mitre_rows"]], "Technique / tactic": [r[1] for r in result["mitre_rows"]]},
    width='stretch', hide_index=True,
)

with st.expander("\U0001F4C4 Full tactical warning report"):
    st.markdown(result["report"])

with st.expander("\U0001F52C Live Phase 1 \u2192 Phase 2 pipeline test (independent of the scenario above)"):
    st.caption("Generates raw Zeek-style connection telemetry, runs it through the real OCSF normalizer "
               "and schema validator (agentless_pipeline), then the real sliding-window + "
               "feature-extractor + adaptive-anomaly-detector pipeline (behavioral_engine) \u2014 right "
               "now, in this process. Note: this normalizer path doesn't carry byte volume through from "
               "Zeek conn logs, so scoring here draws on timing and port-diversity drift, not payload size.")
    if st.button("Generate & score sample telemetry"):
        raw, normalized, errors, scan_port, score = run_phase1_phase2_live_test()
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Raw sensor telemetry (Zeek conn log)**")
            st.json(raw)
        with col_b:
            st.markdown("**Normalized OCSF (real Phase 1 output)**")
            st.json(normalized)
        st.write(f"Schema validation: {'\u2705 PASSED' if not errors else '\u274C ' + str(errors)}")
        st.write(f"Scan probe to port `{scan_port}` \u2192 live Phase 2 anomaly score: **{score:.4f}** "
                 f"({'ANOMALOUS' if score > 0.75 else 'NORMAL'})")

st.divider()
with st.expander("\U0001F4CA Why this matters"):
    m1, m2, m3 = st.columns(3)
    m1.metric("Median attacker dwell time (2025)", "14 days", help="Mandiant M-Trends 2026")
    m2.metric("Avg. critical-infra breach cost", "$4.82M", help="IBM Cost of a Data Breach Report 2025")
    m3.metric("Faster containment saves", "$1.14M", help="IBM 2025 \u2014 breaches contained under 200 days vs. longer")
    st.caption("Sources: Mandiant M-Trends 2026, IBM Cost of a Data Breach Report 2025. This platform's "
               "graph traversal, blast-radius scoring, and containment decision run in milliseconds, not "
               "days \u2014 that gap is what this prototype targets.")

st.divider()
st.caption("Prototype by Bhumi \u2014 5-phase autonomous CNI cyber resilience platform "
           "(agentless telemetry \u2192 behavioral detection \u2192 graph intelligence \u2192 SOAR \u2192 digital twin).")