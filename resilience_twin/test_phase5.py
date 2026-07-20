# test_phase5.py
# Automated validation suite for Phase 5 Cyber Resilience Digital Twin

import sys
import os
import json

# Add the scratch workspace to python sys.path to enable importing CNITopologyGraph from graph_intelligence
scratch_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(scratch_dir)

try:
    from graph_intelligence.graph_intelligence import CNITopologyGraph
    from digital_twin import CyberResilienceDigitalTwin
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
    print(f"{BOLD}{CYAN}                 PHASE 5 CYBER RESILIENCE DIGITAL TWIN                {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")

    # 1. Initialize CNITopologyGraph and seed dynamic CNI assets
    # We configure a topology of 5 nodes:
    # Compromised Web Endpoint (Low crit) -> Core Segment Router (Medium crit)
    # Core Segment Router -> Legacy SCADA Asset (High crit)
    # Legacy SCADA Asset -> PLC Controller (High crit)
    # PLC Controller -> Core Segment Router (Loop)
    # Core Segment Router -> Workstation A (Low crit)
    
    graph = CNITopologyGraph()
    
    print(f"\n{BOLD}[STEP 1] Seeding CNI Topology Node Parameters...{RESET}")
    graph.add_asset("Compromised Web Endpoint", anomaly_weight=0.85, dynamic_crit="Low")
    graph.add_asset("Core Segment Router", anomaly_weight=0.70, dynamic_crit="Medium")
    graph.add_asset("Legacy SCADA Asset", anomaly_weight=0.95, dynamic_crit="High")
    graph.add_asset("PLC Controller", anomaly_weight=0.10, dynamic_crit="High")
    graph.add_asset("Workstation A", anomaly_weight=0.15, dynamic_crit="Low")
    print(f"{GREEN}[SUCCESS] Node properties seeded.{RESET}")

    print(f"\n{BOLD}[STEP 2] Creating Cyclic Communication Edges...{RESET}")
    graph.add_communication("Compromised Web Endpoint", "Core Segment Router", protocol="http")
    graph.add_communication("Core Segment Router", "Legacy SCADA Asset", protocol="modbus")
    graph.add_communication("Legacy SCADA Asset", "PLC Controller", protocol="modbus")
    graph.add_communication("PLC Controller", "Core Segment Router", protocol="tcp")  # Loop back
    graph.add_communication("Core Segment Router", "Workstation A", protocol="smb")
    print(f"{GREEN}[SUCCESS] Cyclic graph communication edges configured.{RESET}")

    # 2. Instantiate the Digital Twin sandbox cloning
    print(f"\n{BOLD}[STEP 3] Mirroring Live Topology into Isolated Sandbox Map...{RESET}")
    twin = CyberResilienceDigitalTwin(graph)
    print(f"{GREEN}[SUCCESS] Sandbox environment isolated.{RESET}")

    # 3. Simulate Attack Propagation based on descending criticality
    # Path should traverse: Web Endpoint (Low) -> Core Router (Medium) -> SCADA (High) -> PLC (High) -> Stop (Visited)
    print(f"\n{BOLD}[STEP 4] Simulating Unsupervised Attack Propagation Path...{RESET}")
    start_node = "Compromised Web Endpoint"
    path, sim_logs = twin.simulate_attack_propagation(start_node)
    
    print(f"\n{BOLD}--- PROPAGATION SIMULATION STEP LOGS ---{RESET}")
    for log in sim_logs:
        print(f"  {log}")
    print(f"{BOLD}----------------------------------------{RESET}")
    
    print(f"  Simulated Threat Actor Path: {' -> '.join([f'`{n}`' for n in path])}")
    
    # Assert correct criticality-based progression and loop termination
    expected_path = ["Compromised Web Endpoint", "Core Segment Router", "Legacy SCADA Asset", "PLC Controller"]
    assert path == expected_path, f"Simulation path mismatch! Got {path}, expected {expected_path}"
    print(f"{GREEN}[SUCCESS] Attack propagation followed descending criticality rules safely.{RESET}")

    # 4. Evaluate Playbook Impacts on Core Segment Router
    target_asset = "Core Segment Router"
    print(f"\n{BOLD}[STEP 5] Evaluating Playbook Impacts on Asset '{target_asset}'...{RESET}")
    
    # A. Isolation Playbook
    metrics_iso = twin.evaluate_playbook_impact(target_asset, "autonomous_edge_isolation")
    print(f"\n  {BOLD}Isolation Playbook Impact Metrics:{RESET}")
    print(f"    - Downstream Loss Percentage: {metrics_iso['downstream_loss_percentage']:.2f}%")
    print(f"    - Recovery Window: {metrics_iso['recovery_window_hours']:.2f} Hours")
    print(f"    - Details: {metrics_iso['details']}")
    
    # B. Throttling Playbook
    metrics_throttle = twin.evaluate_playbook_impact(target_asset, "rate_limiting_bandwidth_throttling")
    print(f"\n  {BOLD}Throttling Playbook Impact Metrics:{RESET}")
    print(f"    - Downstream Loss Percentage: {metrics_throttle['downstream_loss_percentage']:.2f}%")
    print(f"    - Recovery Window: {metrics_throttle['recovery_window_hours']:.2f} Hours")
    print(f"    - Details: {metrics_throttle['details']}")

    # Validation assertions to confirm high vs. low loss and recovery times
    assert metrics_iso["downstream_loss_percentage"] > metrics_throttle["downstream_loss_percentage"], "Isolation must cause higher downstream loss!"
    assert metrics_iso["recovery_window_hours"] > metrics_throttle["recovery_window_hours"], "Isolation must require longer recovery window!"
    
    assert metrics_throttle["downstream_loss_percentage"] == 0.00, "Throttling node loss count must be 0%!"
    print(f"\n{GREEN}[SUCCESS] Playbook metrics successfully verified. Playbook impact rankings conform to target parameters.{RESET}")

    # 5. Check Crash-Proof Guardrails with None/Malformed inputs
    print(f"\n{BOLD}[STEP 6] Verifying Exception Containment on Malformed Strings...{RESET}")
    try:
        # Space-padded inputs and invalid actions
        bad_target = "  Core Segment Router  "
        telemetry_bad = twin.evaluate_playbook_impact(bad_target, "  autonomous_edge_isolation  ")
        
        # Verify sanitization stripped spaces and scored correctly
        assert telemetry_bad["target_node"] == "Core Segment Router", "Target node was not correctly stripped!"
        assert telemetry_bad["downstream_loss_percentage"] == metrics_iso["downstream_loss_percentage"]
        
        # None inputs
        telemetry_none = twin.evaluate_playbook_impact(None, "UNKNOWN_ACTION")
        assert telemetry_none["downstream_loss_percentage"] == 100.0, "Malformed none-type action failed fallback!"
        
        print(f"  String sanitization and type-casting confirmed. Zero crashes occurred.")
        print(f"{GREEN}[SUCCESS] Crash-proof checks passed.{RESET}")
    except Exception as ex:
        print(f"  {RED}[FAIL] Exception occurred during malformed inputs check: {ex}{RESET}")
        sys.exit(1)

    print(f"\n{GREEN}[SUCCESS] Phase 5 Cyber Twin validation complete.{RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}\n")

if __name__ == "__main__":
    run_test()
