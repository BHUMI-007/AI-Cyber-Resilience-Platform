# test_phase4.py
# Automated validation suite for Phase 4 SOAR Containment Orchestration

import sys
import os
import json

# Add the scratch workspace to python sys.path to enable importing CNITopologyGraph from graph_intelligence
scratch_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(scratch_dir)

try:
    from graph_intelligence.graph_intelligence import CNITopologyGraph
    from soar_orchestrator import CNISoarOrchestrator
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def run_test():
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}     PHASE 4 AUTONOMOUS INCIDENT RESPONSE ORCHESTRATOR (SOAR)        {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")

    # 1. Initialize CNITopologyGraph and seed CNI assets
    # We configure a topology of 5 nodes:
    # Core Segment Router -> Legacy SCADA Asset -> Core Segment Router (Loop)
    # Core Segment Router -> Workstation A (Leaf)
    # Core Segment Router -> Workstation B (Leaf)
    # Compromised Web Endpoint -> Core Segment Router
    
    graph = CNITopologyGraph()
    
    print(f"\n{BOLD}[STEP 1] Seeding CNI Topology Node Parameters...{RESET}")
    # High Criticality Hub Assets
    graph.add_asset("Compromised Web Endpoint", anomaly_weight=0.85, dynamic_crit="High")
    graph.add_asset("Core Segment Router", anomaly_weight=0.80, dynamic_crit="High")
    graph.add_asset("Legacy SCADA Asset", anomaly_weight=0.95, dynamic_crit="High")
    
    # Low Criticality Leaf Asset
    graph.add_asset("Workstation A", anomaly_weight=0.90, dynamic_crit="Low")  # Scenario A target (Low Blast Radius)
    
    # We configure Workstation B as High Criticality to increase the Core Segment Router's overall blast radius
    graph.add_asset("Workstation B", anomaly_weight=0.15, dynamic_crit="High")
    print(f"{GREEN}[SUCCESS] CNI Node properties seeded.{RESET}")

    print(f"\n{BOLD}[STEP 2] Seeding Directed Edges (Communication Topology)...{RESET}")
    # Establish links
    graph.add_communication("Compromised Web Endpoint", "Core Segment Router", protocol="http")
    graph.add_communication("Core Segment Router", "Legacy SCADA Asset", protocol="modbus")
    graph.add_communication("Legacy SCADA Asset", "Core Segment Router", protocol="tcp")  # Loop back
    graph.add_communication("Core Segment Router", "Workstation A", protocol="smb")
    graph.add_communication("Core Segment Router", "Workstation B", protocol="smb")
    print(f"{GREEN}[SUCCESS] Communication vectors established.{RESET}")

    # 2. Initialize SOAR Orchestrator
    soar = CNISoarOrchestrator(graph)

    # 3. Scenario A Validation: Low Blast Radius, High Risk
    # Asset: Workstation A
    # Criteria: Anomaly = 0.90 (High), Crit = Low, Reachable nodes = [] (Blast score = ~0.02)
    # Expected Action: autonomous_edge_isolation, human_validation_required: False
    print(f"\n{BOLD}[STEP 3] Executing Scenario A (Low Blast Radius / High Threat Risk)...{RESET}")
    asset_a = "Workstation A"
    telemetry_a = soar.orchestrate_containment(asset_a)
    
    # Verify outputs
    print(f"  Target Asset: `{asset_a}`")
    print(f"  Blast Radius Score: {telemetry_a['blast_radius_score']:.4f}")
    print(f"  Containment Action: {telemetry_a['containment_action']}")
    print(f"  Human Validation Flag: {telemetry_a['human_validation_required']}")
    print(f"  Telemetry Details: {telemetry_a['details']}")
    
    # Assert correctness
    assert telemetry_a["containment_action"] == "autonomous_edge_isolation", "Scenario A must trigger autonomous isolation!"
    assert telemetry_a["human_validation_required"] is False, "Scenario A must NOT require human validation!"
    print(f"{GREEN}[SUCCESS] Scenario A checks passed successfully.{RESET}")

    # 4. Scenario B Validation: High Blast Radius, High Risk
    # Asset: Core Segment Router
    # Criteria: Anomaly = 0.80 (High), Crit = High, Reachable nodes = [SCADA, Workstation A, Workstation B] (Blast score = ~0.61)
    # Since it is a critical hub node, its blast radius score is high (>= 0.50).
    # Expected Action: rate_limiting_bandwidth_throttling, human_validation_required: True
    print(f"\n{BOLD}[STEP 4] Executing Scenario B (High Blast Radius / High Threat Risk)...{RESET}")
    asset_b = "Core Segment Router"
    telemetry_b = soar.orchestrate_containment(asset_b)
    
    # Verify outputs
    print(f"  Target Asset: `{asset_b}`")
    print(f"  Blast Radius Score: {telemetry_b['blast_radius_score']:.4f}")
    print(f"  Containment Action: {telemetry_b['containment_action']}")
    print(f"  Human Validation Flag: {telemetry_b['human_validation_required']}")
    print(f"  Telemetry Details: {telemetry_b['details']}")
    
    # Assert correctness
    assert telemetry_b["containment_action"] == "rate_limiting_bandwidth_throttling", "Scenario B must trigger rate-limiting!"
    assert telemetry_b["human_validation_required"] is True, "Scenario B must require human-in-the-loop validation!"
    print(f"{GREEN}[SUCCESS] Scenario B checks passed successfully.{RESET}")

    # 5. Check Crash-Proof Guardrails with None/Malformed inputs
    print(f"\n{BOLD}[STEP 5] Testing Exception Containment and Null Safety...{RESET}")
    try:
        telemetry_none = soar.orchestrate_containment(None)
        telemetry_bad = soar.orchestrate_containment("Non_Existent_Asset")
        
        # Verify output formats are standard dictionaries and contain all parameters
        for key in ["asset_id", "anomaly_weight", "blast_radius_score", "containment_action", "human_validation_required", "execution_status"]:
            assert key in telemetry_none, f"Missing telemetry key '{key}' in fallback output!"
            assert key in telemetry_bad, f"Missing telemetry key '{key}' in fallback output!"
            
        print(f"  Fallback output keys verified. Null inputs handled without crashes.")
        print(f"{GREEN}[SUCCESS] Exception containment check passed.{RESET}")
    except Exception as ex:
        print(f"  {RED}[FAIL] Crash detected on null inputs: {ex}{RESET}")
        sys.exit(1)

    print(f"\n{GREEN}[SUCCESS] Phase 4 SOAR Orchestrator validation complete.{RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}\n")

if __name__ == "__main__":
    run_test()
