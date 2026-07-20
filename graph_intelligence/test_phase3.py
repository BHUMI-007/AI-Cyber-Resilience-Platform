# test_phase3.py
# Verification script for Graph Intelligence & MITRE ATT&CK Agent Pipeline

import sys
from graph_intelligence import CNITopologyGraph
from agent_mesh import ReActAgentMesh

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def run_test():
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}     PHASE 3 GRAPH INTELLIGENCE & MITRE ATT&CK AGENT PIPELINE        {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")

    # 1. Initialize CNITopologyGraph
    graph = CNITopologyGraph()

    # 2. Seed network assets with dynamic criticality and anomaly weights
    print(f"\n{BOLD}[STEP 1] Seeding CNI Network Assets & Criticalities...{RESET}")
    graph.add_asset("Compromised Web Endpoint", anomaly_weight=0.85, dynamic_crit="Low")
    graph.add_asset("Core Segment Router", anomaly_weight=0.60, dynamic_crit="Medium")
    graph.add_asset("Legacy SCADA Asset", anomaly_weight=0.95, dynamic_crit="High")
    print(f"{GREEN}[SUCCESS] Node properties seeded.{RESET}")

    # 3. Configure a cyclic lateral jump scenario to verify loop-safety
    # Path: Web Endpoint -> Core Segment Router -> Legacy SCADA Asset -> Core Segment Router (Loop)
    print(f"\n{BOLD}[STEP 2] Creating Cyclic Communication Edges (SPAN/Netflow data)...{RESET}")
    graph.add_communication("Compromised Web Endpoint", "Core Segment Router", protocol="http")
    graph.add_communication("Core Segment Router", "Legacy SCADA Asset", protocol="modbus")
    graph.add_communication("Legacy SCADA Asset", "Core Segment Router", protocol="tcp") # Loop edge back to Router
    print(f"{GREEN}[SUCCESS] Directed cyclic edges configured safely.{RESET}")

    # 4. Test BFS Downstream Tracing directly to confirm cycle isolation
    print(f"\n{BOLD}[STEP 3] Verifying BFS Loop-Safety & Downstream Path Extraction...{RESET}")
    start_node = "Compromised Web Endpoint"
    downstream = graph.get_downstream_subgraph(start_node)
    print(f"  Start Node: '{start_node}'")
    print(f"  Downstream Reachable Nodes (Loop Isolated, Start Node Filtered): {downstream}")
    
    # Assertions for correctness
    assert start_node not in downstream, "Start node must be filtered from downstream risk list to avoid self-reference!"
    assert "Core Segment Router" in downstream, "Core Segment Router must be present in downstream list!"
    assert "Legacy SCADA Asset" in downstream, "Legacy SCADA Asset must be present in downstream list!"
    print(f"{GREEN}[SUCCESS] Loop-safety verified. BFS terminated successfully without infinite loops.{RESET}")

    # 5. Run ReAct Agent Mesh Reasoning Loop
    print(f"\n{BOLD}[STEP 4] Executing ReAct Agent Mesh Reasoning Loop...{RESET}")
    agent = ReActAgentMesh(graph)
    reasoning_logs, report = agent.run(start_node)

    # Print Agent Logs
    print(f"\n{BOLD}--- REACT AGENT EXECUTION LOGS ---{RESET}")
    print(reasoning_logs)
    print(f"{BOLD}----------------------------------{RESET}")

    # Print Warning Report
    print(f"\n{BOLD}--- ANALYTICAL TACTICAL WARNING REPORT ---{RESET}")
    print(report)
    print(f"{BOLD}------------------------------------------{RESET}")

    print(f"\n{GREEN}[SUCCESS] Phase 3 Graph Intelligence validation complete.{RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}\n")

if __name__ == "__main__":
    run_test()
