# soar_orchestrator.py
# Autonomous Incident Response Orchestrator (SOAR) with bounded blast radius math

import time

class CNISoarOrchestrator:
    """
    Autonomous CNI Incident Response Orchestrator.
    Calculates operational blast radius, matches threats against a containment matrix,
    and outputs structured containment telemetry logs.
    """
    def __init__(self, topology_graph):
        self.topology = topology_graph

    def _get_criticality_value(self, crit_str):
        """
        Helper method mapping categorical criticality levels to numerical weights.
        """
        try:
            clean_crit = str(crit_str).strip().lower()
            if clean_crit == "high":
                return 3.0
            elif clean_crit == "medium":
                return 2.0
            return 1.0  # Default "low"
        except Exception:
            return 1.0

    def calculate_runtime_blast_radius(self, asset_id):
        """
        Calculates the operational blast radius score of an asset.
        Raw score:
            Raw Blast = C_target * (1 + sum(C_downstream))
        
        Normalizes the raw score strictly between 0.0 and 1.0 relative to the total graph size:
            Max Possible Blast = C_max * (1 + C_max * (M - 1))
            Normalized Blast = min(1.0, Raw Blast / Max Possible Blast)
        """
        try:
            asset_str = str(asset_id).strip()
            if asset_str not in self.topology.graph.nodes:
                return 0.0

            # 1. Fetch target asset properties
            target_data = self.topology.graph.nodes.get(asset_str, {})
            c_target = self._get_criticality_value(target_data.get("dynamic_crit", "low"))

            # 2. Trace downstream dependencies using BFS
            downstream_nodes = self.topology.get_downstream_subgraph(asset_str)
            
            # Sum downstream criticalities
            downstream_crit_sum = 0.0
            for node in downstream_nodes:
                node_data = self.topology.graph.nodes.get(node, {})
                downstream_crit_sum += self._get_criticality_value(node_data.get("dynamic_crit", "low"))

            # Calculate raw blast radius
            raw_blast = c_target * (1.0 + downstream_crit_sum)

            # 3. Calculate dynamic maximum possible blast radius of the current graph
            # M = total count of nodes
            m_nodes = len(self.topology.graph.nodes)
            c_max = 3.0 # High criticality multiplier
            
            # Theoretical max blast radius for a graph of size M
            max_possible_blast = c_max * (1.0 + c_max * (m_nodes - 1)) if m_nodes > 0 else 3.0

            # Normalize and wrap inside a min(1.0, value) to guarantee boundary safety
            normalized_blast = raw_blast / (max_possible_blast + 1e-9)
            
            return min(1.0, max(0.0, normalized_blast))

        except Exception:
            # Crash-proof isolation: return safe boundary default
            return 0.0

    def orchestrate_containment(self, asset_id):
        """
        SOAR Containment Decision Matrix.
        Evaluates risk parameters and outputs a structured containment execution dictionary.
        """
        try:
            asset_str = str(asset_id).strip()
            if asset_str not in self.topology.graph.nodes:
                return {
                    "asset_id": asset_str,
                    "anomaly_weight": 0.0,
                    "blast_radius_score": 0.0,
                    "containment_action": "monitor_and_log",
                    "human_validation_required": False,
                    "execution_status": "ignored",
                    "timestamp": time.time(),
                    "details": "Asset not found in CNI topology."
                }

            # Fetch threat risk parameters
            asset_data = self.topology.graph.nodes.get(asset_str, {})
            anomaly_weight = float(asset_data.get("anomaly_weight", 0.0))
            
            # Calculate bounded blast radius [0.0 - 1.0]
            blast_radius = self.calculate_runtime_blast_radius(asset_str)

            # Containment Decision Logic Matrix
            # High threat trigger threshold = 0.70
            # High blast radius boundary = 0.50
            if anomaly_weight >= 0.70:
                if blast_radius < 0.50:
                    action = "autonomous_edge_isolation"
                    status = "active"
                    validation_req = False
                    details = f"Threat risk is high ({anomaly_weight:.2f}) and blast radius is low ({blast_radius:.4f}). Executing immediate autonomous port isolation."
                else:
                    action = "rate_limiting_bandwidth_throttling"
                    status = "pending_approval"
                    validation_req = True
                    details = f"Threat risk is high ({anomaly_weight:.2f}) but blast radius is high ({blast_radius:.4f}). Isolation aborted; applying dynamic rate-limiting. Emitted validation flag for operator review."
            else:
                action = "monitor_and_log"
                status = "monitored"
                validation_req = False
                details = f"Threat risk is low/moderate ({anomaly_weight:.2f}). No active block required. Log and monitor."

            return {
                "asset_id": asset_str,
                "anomaly_weight": anomaly_weight,
                "blast_radius_score": blast_radius,
                "containment_action": action,
                "human_validation_required": validation_req,
                "execution_status": status,
                "timestamp": time.time(),
                "details": details
            }

        except Exception as e:
            # Crash-proof fallback dictionary to ensure pipeline never halts
            return {
                "asset_id": str(asset_id),
                "anomaly_weight": 0.0,
                "blast_radius_score": 0.0,
                "containment_action": "monitor_and_log",
                "human_validation_required": True,
                "execution_status": "error_fallback",
                "timestamp": time.time(),
                "details": f"SOAR Execution Exception: {str(e)}. Defaulted to safe monitoring state."
            }
