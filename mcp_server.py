# mcp_server.py
# FastMCP bridge exposing Phases 2-5 (behavioral engine, graph intelligence,
# SOAR, digital twin) as tools an LLM agent can call.
#
# This corrects several mismatches between the Gemini draft and the actual
# module code (wrong class names, wrong method names, wrong argument counts).
# See the inline "FIX:" comments for what changed and why.

import json
import time

from fastmcp import FastMCP

# FIX: the real class names differ from what Gemini imported.
#   DynamicFeatureExtractor   -> FeatureExtractor
#   DynamicSlidingWindow      -> SlidingWindowCache
#   DeterministicReActMesh    -> ReActAgentMesh
#   AutomatedResponseOrchestrator -> CNISoarOrchestrator
#   CNIResilienceDigitalTwin  -> CyberResilienceDigitalTwin
from behavioral_engine.feature_extractor import FeatureExtractor
from behavioral_engine.sliding_window import SlidingWindowCache
from behavioral_engine.adaptive_model import AdaptiveAnomalyDetector
from graph_intelligence.graph_intelligence import CNITopologyGraph
from graph_intelligence.agent_mesh import ReActAgentMesh
from soar_automation.soar_orchestrator import CNISoarOrchestrator
from resilience_twin.digital_twin import CyberResilienceDigitalTwin

mcp = FastMCP("CNI-Cyber-Resilience-Platform")

# Global state instances, shared across every tool call in this process.
# This is what makes the graph "live" instead of rebuilt per call.
graph_matrix = CNITopologyGraph()
cache = SlidingWindowCache()
extractor = FeatureExtractor()
# FIX: AdaptiveAnomalyDetector takes a `mode` kwarg, not `baseline_threshold`
# (that parameter doesn't exist on the class and would raise TypeError).
anomaly_detector = AdaptiveAnomalyDetector(mode="learning")
soar_engine = CNISoarOrchestrator(graph_matrix)


@mcp.tool()
def score_telemetry_anomaly(raw_json_payload: str) -> str:
    """
    Scores a single OCSF/raw JSON log for behavioral anomaly drift.
    Maintains a per-asset sliding window and continuously updates the
    baseline, so repeated calls for the same asset get more accurate
    over time.
    """
    try:
        event = json.loads(raw_json_payload)

        # FIX: FeatureExtractor has no `.extract()` method. Asset-ID guessing
        # is already implemented correctly on the class itself as
        # `get_asset_id`, so reuse it instead of re-deriving it by hand.
        asset_id = FeatureExtractor.get_asset_id(event)

        # FIX: real pipeline is add_event -> get_events -> extract_features
        # -> score. `push_and_prune` / `get_window_matrix` don't exist.
        current_time_sec = time.time()
        cache.add_event(asset_id, event)
        window_events = cache.get_events(asset_id, current_time_sec)
        features = extractor.extract_features(window_events, event)

        # FIX: no separate fit_baseline() call needed — score() already
        # calls fit_incremental() internally while mode == "learning".
        score = anomaly_detector.score(features)

        return json.dumps({
            "asset_id": asset_id,
            "anomaly_score": round(float(score), 4),
            "status": "ANOMALOUS" if score > 0.75 else "NORMAL"
        })
    except Exception as e:
        return f"Telemetry parsing error: {str(e)}"


@mcp.tool()
def correlate_graph_attack_path(
    source_ip: str,
    target_ip: str,
    anomaly_score: float,
    source_crit: str = "Low",
    target_crit: str = "High",
) -> str:
    """
    Registers a source -> target compromise edge in the live topology graph
    and runs the ReAct agent mesh to produce a MITRE-ATT&CK-mapped tactical
    warning report. Criticality is "Low" / "Medium" / "High", not a float.
    """
    try:
        # FIX: CNITopologyGraph doesn't expose add_node/add_edge directly —
        # those live on the inner .graph object. Use the class's own public
        # API instead, which also validates/normalizes criticality strings.
        graph_matrix.add_asset(source_ip, anomaly_weight=anomaly_score, dynamic_crit=source_crit)
        graph_matrix.add_asset(target_ip, anomaly_weight=anomaly_score, dynamic_crit=target_crit)
        graph_matrix.add_communication(source_ip, target_ip)

        # FIX: class is ReActAgentMesh, method is run(start_node) and it
        # returns a (reasoning_logs, report) tuple — not a single report
        # from execute_reasoning_loop(), which doesn't exist.
        mesh = ReActAgentMesh(graph_matrix)
        reasoning_logs, report = mesh.run(source_ip)
        return report
    except Exception as e:
        return f"Graph correlation error: {str(e)}"


@mcp.tool()
def orchestrate_blast_radius_containment(
    asset_id: str,
    anomaly_score: float = None,
    dynamic_crit: str = "Medium",
) -> str:
    """
    Calculates the bounded blast radius for `asset_id` and decides a
    containment action (autonomous isolation vs. throttling with human
    approval). If the asset isn't already in the graph (or you want to
    update its score first), pass anomaly_score/dynamic_crit and it will
    be registered before the decision runs.
    """
    try:
        if anomaly_score is not None:
            graph_matrix.add_asset(asset_id, anomaly_weight=anomaly_score, dynamic_crit=dynamic_crit)

        # FIX: orchestrate_containment(asset_id) takes ONE argument. It reads
        # anomaly_weight straight off the graph node rather than accepting
        # source_ip/target_ip/anomaly_score as separate parameters.
        result = soar_engine.orchestrate_containment(asset_id)
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"SOAR orchestration error: {str(e)}"


@mcp.tool()
def run_digital_twin_sandbox_simulation(entry_node: str) -> str:
    """
    Clones the live topology into an isolated sandbox, simulates how an
    attacker would propagate from entry_node, then compares the resilience
    impact of isolating vs. throttling that node.
    """
    try:
        # FIX: class is CyberResilienceDigitalTwin, and
        # simulate_attack_propagation() takes no `steps` argument — it runs
        # until propagation naturally halts and returns (path, logs), not
        # an object with a `.simulation_logs` attribute.
        twin = CyberResilienceDigitalTwin(graph_matrix)
        path, sim_logs = twin.simulate_attack_propagation(entry_node)

        # FIX: evaluate_playbook_impact() only recognizes the literal
        # strings "autonomous_edge_isolation" and
        # "rate_limiting_bandwidth_throttling" — "ADAPTIVE_BANDWIDTH_
        # THROTTLING" silently fell through to the no-op branch. Compare
        # both real playbooks so the report shows the actual tradeoff.
        isolation_impact = twin.evaluate_playbook_impact(entry_node, "autonomous_edge_isolation")
        throttling_impact = twin.evaluate_playbook_impact(entry_node, "rate_limiting_bandwidth_throttling")

        return json.dumps({
            "attack_path": path,
            "simulation_logs": sim_logs,
            "playbook_comparison": {
                "autonomous_edge_isolation": isolation_impact,
                "rate_limiting_bandwidth_throttling": throttling_impact,
            }
        }, indent=2)
    except Exception as e:
        return f"Digital twin error: {str(e)}"


if __name__ == "__main__":
    mcp.run()