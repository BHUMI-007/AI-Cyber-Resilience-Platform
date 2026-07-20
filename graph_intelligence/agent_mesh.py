# agent_mesh.py
# LangChain-style Agent Mesh tools and ReAct reasoning engine with string sanitization

import json

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ==========================================
# 1. Tool Implementations (With String Sanitization)
# ==========================================

def check_footprint_map(topology_graph):
    """
    Tool: check_footprint_map
    Returns the network topology map, sanitizing strings and casting metrics.
    """
    try:
        results = []
        # Access nodes dynamically
        for node_id, data in topology_graph.graph.nodes.items():
            # Apply strict string casting and sanitization (.strip() and .lower())
            sanitized_id = str(node_id).strip()
            crit = str(data.get("dynamic_crit", "low")).strip().lower()
            weight = float(data.get("anomaly_weight", 0.0))
            
            results.append({
                "asset": sanitized_id,
                "dynamic_crit": crit,
                "anomaly_weight": weight
            })
        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error in check_footprint_map: {str(e)}"


def trace_downstream_impact(topology_graph, start_node):
    """
    Tool: trace_downstream_impact
    Identifies all reachable downstream nodes from a starting node.
    Applies strict string sanitization to prevent matching errors.
    """
    try:
        # Cast, strip, and sanitize starting node parameter
        sanitized_start = str(start_node).strip()
        impacted_nodes = topology_graph.get_downstream_subgraph(sanitized_start)
        return json.dumps(impacted_nodes)
    except Exception as e:
        return f"Error in trace_downstream_impact: {str(e)}"


def map_mitre_attack(signature):
    """
    Tool: map_mitre_attack
    Maps threat event names/signatures to MITRE ATT&CK ICS/IT Tactics & Techniques.
    Sanitizes values against whitespace anomalies.
    """
    try:
        # Cast to string, strip, and lowercase signature parameter
        sig_clean = str(signature).strip().lower()
        
        # Explicit mappings
        if "web" in sig_clean or "compromise" in sig_clean:
            return "T1190 (Exploit Public-Facing Application) -> Initial Access"
        elif "router" in sig_clean or "scan" in sig_clean or "lateral" in sig_clean:
            return "T1046 (Network Service Discovery) -> Discovery / T1090 (Proxy) -> Lateral Movement"
        elif "scada" in sig_clean or "modbus" in sig_clean or "dnp3" in sig_clean or "iec104" in sig_clean:
            return "T0836 (Modify Parameter) -> Impact / T0858 (Service Stop) -> Inhibit Response Function"
            
        return "T1059 (Command and Scripting Interpreter) -> Execution"
    except Exception as e:
        return f"Error in map_mitre_attack: {str(e)}"


# ==========================================
# 2. ReAct Agent Reasoning Loop
# ==========================================

class ReActAgentMesh:
    """
    Deterministic ReAct Agent Mesh mimicking LangGraph/LangChain execution.
    Runs tool calls in sequence (Thought -> Action -> Observation) to generate warnings.
    """
    def __init__(self, topology_graph):
        self.topology = topology_graph

    def run(self, start_compromise):
        """
        Runs the ReAct cycle starting from the initial compromised node.
        """
        sanitized_start = str(start_compromise).strip()
        logs = []
        
        # --- Step 1: Footprint Check ---
        logs.append(f"{BOLD}Thought:{RESET} I need to check the active topology footprint map to understand the network assets, their criticalities, and anomaly weights.")
        logs.append(f"{BOLD}Action:{RESET} check_footprint_map()")
        footprint_obs = check_footprint_map(self.topology)
        logs.append(f"{BOLD}Observation:{RESET}\n{footprint_obs}")
        
        # --- Step 2: Downstream Propagation ---
        logs.append(f"{BOLD}Thought:{RESET} I will trace all downstream nodes connected to the compromised asset '{sanitized_start}' to map the threat propagation path.")
        logs.append(f"{BOLD}Action:{RESET} trace_downstream_impact(start_node='{sanitized_start}')")
        downstream_obs = trace_downstream_impact(self.topology, sanitized_start)
        logs.append(f"{BOLD}Observation: Impacted downstream nodes: {downstream_obs}{RESET}")
        
        # Parse downstream nodes safely
        try:
            nodes_list = json.loads(downstream_obs)
        except Exception:
            nodes_list = []

        # --- Step 3: MITRE ATT&CK Mapping ---
        logs.append(f"{BOLD}Thought:{RESET} Now I must map each compromised/at-risk asset signature to the MITRE ATT&CK framework to categorize the techniques.")
        mapped_mitre = {}
        for node in [sanitized_start] + nodes_list:
            logs.append(f"{BOLD}Action:{RESET} map_mitre_attack(signature='{node}')")
            mitre_info = map_mitre_attack(node)
            mapped_mitre[node] = mitre_info
            logs.append(f"{BOLD}Observation: Node '{node}' maps to: {mitre_info}{RESET}")

        # --- Step 4: Analytical Tactical Warning Report Generation ---
        logs.append(f"{BOLD}Thought:{RESET} I have complete visibility. I will generate a CNI Analytical Tactical Warning Report detailing risk paths and remediations.")
        
        # Compile Report
        report = self._generate_report(sanitized_start, nodes_list, mapped_mitre)
        
        return "\n\n".join(logs), report

    def _generate_report(self, start_node, downstream_nodes, mitre_mappings):
        """
        Generates the formatted Markdown Tactical Warning Report relative to dynamic baseline metrics.
        """
        # Parse graph data for node statistics
        all_nodes = [start_node] + downstream_nodes
        mitre_rows = ""
        risk_rows = ""
        
        highest_risk_node = start_node
        highest_weight = 0.0
        
        for node in all_nodes:
            # Safely fetch node properties
            node_data = self.topology.graph.nodes.get(node, {})
            crit = str(node_data.get("dynamic_crit", "low")).strip().upper()
            weight = float(node_data.get("anomaly_weight", 0.0))
            
            if weight > highest_weight:
                highest_weight = weight
                highest_risk_node = node
                
            mitre_rows += f"| {node} | {mitre_mappings.get(node, 'Unknown')} |\n"
            risk_rows += f"| {node} | {crit} | {weight:.4f} |\n"

        report_md = f"""# CNI TACTICAL WARNING REPORT
**Incident Category:** Multi-Stage Lateral Compromise Detection
**Timestamp:** 2026-07-10T14:05:37+03:00
**Threat Origin Asset:** `{start_node}` (Anomaly Weight: {self.topology.graph.nodes.get(start_node, {}).get('anomaly_weight', 0.0)})

---

## 1. Multi-Stage Lateral Propagation Path
The threat agent initiated an exploit at the perimeter and is traversing CNI segments:
`{start_node}` --> {" --> ".join([f"`{n}`" for n in downstream_nodes])}

---

## 2. MITRE ATT&CK Mapping
| Impacted Asset | MITRE ATT&CK Technique / Tactic |
| :--- | :--- |
{mitre_rows}

---

## 3. Dynamic Risk Classification & Asset Criticality
All risk scoring is dynamically updated relative to baseline metrics:
| Asset Node | Dynamic Criticality | Anomaly Weight |
| :--- | :--- | :--- |
{risk_rows}

---

## 4. Analytical Containment Recommendations
- **Asset Isolation**: Isolate high-risk asset `{highest_risk_node}` immediately. It has the highest anomaly weight of **{highest_weight:.4f}** and threatens adjacent CNI controllers.
- **Perimeter Block**: Shut down traffic flow from `{start_node}` to core segment routers to halt further lateral movement.
- **Telemetry Verification**: Run Phase 2 anomaly detectors on the downstream sub-graph to verify if other devices are exhibiting stealthy beacon behaviors.
"""
        return report_md
