# graph_intelligence.py
# CNI Directed Graph Topology analyzer with cycle-isolation and dynamic properties

import time

# 1. Attempt to import networkx for graph computations
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

class MockDiGraph:
    """
    Standard-library directed graph implementation mirroring the NetworkX DiGraph API.
    Used as an offline/agent sandbox fallback.
    """
    def __init__(self):
        self._nodes = {}  # node -> dict of properties
        self._adj = {}    # node -> dict of (neighbor -> edge_properties)
        self._pred = {}   # node -> dict of (predecessor -> edge_properties)

    @property
    def nodes(self):
        return self._nodes

    @property
    def adj(self):
        return self._adj

    def add_node(self, node_for_adding, **attr):
        if node_for_adding not in self._nodes:
            self._nodes[node_for_adding] = {}
            self._adj[node_for_adding] = {}
            self._pred[node_for_adding] = {}
        self._nodes[node_for_adding].update(attr)

    def add_edge(self, u_of_edge, v_of_edge, **attr):
        self.add_node(u_of_edge)
        self.add_node(v_of_edge)
        if v_of_edge not in self._adj[u_of_edge]:
            self._adj[u_of_edge][v_of_edge] = {}
        self._adj[u_of_edge][v_of_edge].update(attr)
        if u_of_edge not in self._pred[v_of_edge]:
            self._pred[v_of_edge][u_of_edge] = {}
        self._pred[v_of_edge][u_of_edge].update(attr)

    def successors(self, n):
        return self._adj.get(n, {}).keys()

    def predecessors(self, n):
        return self._pred.get(n, {}).keys()


class CNITopologyGraph:
    """
    CNI Network Topology Graph.
    Uses NetworkX DiGraph if available; otherwise falls back to MockDiGraph.
    Tracks node anomaly weight, dynamic criticality, and communication edges.
    """
    def __init__(self):
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
            print("[INFO] CNITopologyGraph initialized in NetworkX mode.")
        else:
            self.graph = MockDiGraph()
            print("[INFO] CNITopologyGraph initialized in Standard Library Mock mode.")

    def add_asset(self, asset_id, anomaly_weight=0.0, dynamic_crit="low"):
        """
        Safely adds or updates a network asset node with properties.
        """
        try:
            asset_str = str(asset_id).strip()
            self.graph.add_node(
                asset_str,
                anomaly_weight=float(anomaly_weight),
                dynamic_crit=str(dynamic_crit).strip().lower(),
                last_update=time.time()
            )
        except Exception:
            # Crash-proof exception containment
            pass

    def add_communication(self, src_asset, dst_asset, protocol="tcp"):
        """
        Registers a communication edge between two nodes.
        """
        try:
            src_str = str(src_asset).strip()
            dst_str = str(dst_asset).strip()
            self.graph.add_edge(src_str, dst_str, protocol=str(protocol).strip().lower())
        except Exception:
            # Crash-proof exception containment
            pass

    def get_downstream_subgraph(self, start_node):
        """
        CNI Loop-Safe Breadth-First Search (BFS).
        Traverses downstream assets along directed communication edges.
        Safely isolates the start node from self-referencing to avoid loops.
        """
        try:
            start_str = str(start_node).strip()
            if start_str not in self.graph.nodes:
                return []

            visited = set()
            queue = [start_str]
            visited.add(start_str)

            # Safe traversal loop
            while queue:
                current_node = queue.pop(0)
                
                # Retrieve successors dynamically
                if HAS_NETWORKX:
                    successors = list(self.graph.successors(current_node))
                else:
                    successors = list(self.graph.successors(current_node))

                for neighbor in successors:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            # Remove starting node to prevent self-reference in risk scoring
            if start_str in visited:
                visited.remove(start_str)

            return sorted(list(visited))
        except Exception:
            # Catch-all container to prevent runtime failures
            return []
