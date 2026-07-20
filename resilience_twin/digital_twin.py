# digital_twin.py
# CNI Cyber Resilience Digital Twin with topology deep copy cloning

import copy
import time

class CyberResilienceDigitalTwin:
    """
    Cyber Resilience Digital Twin.
    Clones the network topology into an isolated virtual sandbox,
    runs attack propagation path simulations, and evaluates playbook impacts.
    """
    def __init__(self, topology_graph):
        # Perform deep copy of live topology to create isolated virtual sandbox map
        try:
            self.sandbox_graph = copy.deepcopy(topology_graph)
            print("[INFO] CyberResilienceDigitalTwin initialized. Sandbox cloned successfully.")
        except Exception as e:
            # Fallback to direct reference if deep copy fails, ensuring crash-proof execution
            self.sandbox_graph = topology_graph
            print(f"[WARNING] Deep copy failed ({str(e)}). Defaulted to direct reference.")

    def _get_criticality_value(self, crit_str):
        """
        Helper mapping dynamic criticality to numeric weights. Low = 1.0, Med = 2.0, High = 3.0.
        """
        try:
            clean_crit = str(crit_str).strip().lower()
            if clean_crit == "high":
                return 3.0
            elif clean_crit == "medium":
                return 2.0
            return 1.0
        except Exception:
            return 1.0

    def simulate_attack_propagation(self, start_node):
        """
        Simulates unsupervised threat propagation along communication vectors in the sandbox map.
        Steps through adjacent nodes in descending order of dynamic criticality properties.
        """
        logs = []
        path = []
        try:
            sanitized_start = str(start_node).strip()
            if sanitized_start not in self.sandbox_graph.graph.nodes:
                logs.append(f"Start node '{sanitized_start}' not found in sandbox.")
                return path, logs

            current_node = sanitized_start
            path.append(current_node)
            visited = {current_node}
            
            step = 1
            logs.append(f"Simulation Start: Threat actor originates at compromised host '{current_node}'")
            
            while True:
                # 1. Fetch successors
                successors = list(self.sandbox_graph.graph.successors(current_node))
                
                # Filter out already visited nodes to prevent cycles
                unvisited_successors = [node for node in successors if str(node).strip() not in visited]
                
                if not unvisited_successors:
                    logs.append(f"Step {step}: No unvisited downstream neighbor nodes. Threat propagation halted.")
                    break

                # 2. Sort unvisited neighbors by dynamic criticality (descending), then anomaly weight (descending)
                def sort_key(n):
                    node_data = self.sandbox_graph.graph.nodes.get(n, {})
                    crit_val = self._get_criticality_value(node_data.get("dynamic_crit", "low"))
                    weight = float(node_data.get("anomaly_weight", 0.0))
                    return (crit_val, weight)

                unvisited_successors.sort(key=sort_key, reverse=True)
                
                # Log successor evaluation list
                eval_log = f"Step {step}: Current Node '{current_node}' -> Evaluated Neighbors: "
                eval_details = []
                for node in unvisited_successors:
                    node_data = self.sandbox_graph.graph.nodes.get(node, {})
                    crit = str(node_data.get("dynamic_crit", "low")).strip().upper()
                    weight = float(node_data.get("anomaly_weight", 0.0))
                    eval_details.append(f"'{node}' (Crit: {crit}, Anomaly: {weight:.2f})")
                eval_log += ", ".join(eval_details)
                logs.append(eval_log)

                # 3. Step to the highest criticality neighbor
                next_node = unvisited_successors[0]
                next_node_data = self.sandbox_graph.graph.nodes.get(next_node, {})
                next_crit = str(next_node_data.get("dynamic_crit", "low")).strip().upper()
                
                visited.add(next_node)
                path.append(next_node)
                
                logs.append(f"Step {step} Decision: Threat actor jumps to highest criticality adjacent asset: '{next_node}' (Crit: {next_crit})")
                current_node = next_node
                step += 1

            return path, logs

        except Exception as e:
            logs.append(f"Exception during simulation: {str(e)}")
            return path, logs

    def evaluate_playbook_impact(self, target_node, containment_action):
        """
        Evaluates the operational resilience impact of a playbook action on a target node.
        Computes Downstream Loss % and Recovery Window (in Hours) dynamically.
        Uses float casts and round(..., 2) wrappers to ensure clean floating-point structure.
        """
        try:
            if target_node is None or containment_action is None:
                raise ValueError("Target node or containment action cannot be None")

            sanitized_target = str(target_node).strip()
            action_clean = str(containment_action).strip().lower()

            if sanitized_target not in self.sandbox_graph.graph.nodes:
                return {
                    "target_node": sanitized_target,
                    "containment_action": containment_action,
                    "downstream_loss_percentage": 0.0,
                    "recovery_window_hours": 0.0,
                    "details": "Target asset not found in sandbox topology."
                }

            # Fetch graph node properties
            node_data = self.sandbox_graph.graph.nodes.get(sanitized_target, {})
            c_target = self._get_criticality_value(node_data.get("dynamic_crit", "low"))
            
            # Explicit float casts for counts
            n_total = float(len(self.sandbox_graph.graph.nodes))

            if action_clean == "autonomous_edge_isolation":
                # Get downstream sub-graph reachable from this isolated node
                downstream_nodes = self.sandbox_graph.get_downstream_subgraph(sanitized_target)
                n_downstream = float(len(downstream_nodes))
                
                # Loss % represents percentage of CNI assets cut off from the isolated node
                loss_pct = (n_downstream / (n_total + 1e-9)) * 100.0
                
                # Recovery window scales with asset criticality (isolation requires physical interface restoration)
                recovery_window = 2.0 * c_target
                details = f"Autonomous isolation of '{sanitized_target}' fully cuts off {int(n_downstream)} downstream nodes ({loss_pct:.2f}% of CNI network). Recovery requires physical re-imaging."

            elif action_clean == "rate_limiting_bandwidth_throttling":
                # Throttling keeps the asset online (0 lost nodes)
                loss_pct = 0.0
                
                # Recovery window is low (throttling parameters can be dynamically adjusted over API)
                recovery_window = 0.5 * c_target
                details = f"Rate-limiting applied. Zero nodes lost from operation (0.00% network loss). Recovery is soft-configurable."

            else:
                loss_pct = 0.0
                recovery_window = 0.0
                details = "No active containment action. Operational metrics unaffected."

            return {
                "target_node": sanitized_target,
                "containment_action": containment_action,
                "downstream_loss_percentage": round(float(loss_pct), 2),
                "recovery_window_hours": round(float(recovery_window), 2),
                "details": details
            }

        except Exception as e:
            # Crash-proof fallback execution dictionary
            return {
                "target_node": str(target_node),
                "containment_action": str(containment_action),
                "downstream_loss_percentage": 100.0,
                "recovery_window_hours": 99.99,
                "details": f"Resilience calculation exception: {str(e)}"
            }
