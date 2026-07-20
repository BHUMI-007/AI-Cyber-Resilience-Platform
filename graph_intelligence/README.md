# Phase 3: Graph Intelligence & MITRE ATT&CK Agent Pipeline

This directory contains the source code for the **Phase 3 Graph Intelligence & MITRE ATT&CK Agent Pipeline**, designed to analyze threat propagation across CNI assets, trace downstream risk exposure dynamically, and generate MITRE-aligned tactical warning reports.

---

## 1. Directory Structure

```text
graph_intelligence/
├── graph_intelligence.py  # NetworkX DiGraph wrapper with cyclic-loop isolation & properties
├── agent_mesh.py          # LangChain tool definitions & ReAct reasoning loop
├── test_phase3.py         # Simulated cyclic lateral jump verification suite
└── README.md              # Setup and execution guide (This file)
```

---

## 2. Graph Intelligence & Cycle Isolation

The `CNITopologyGraph` wraps `networkx.DiGraph` to model assets as nodes and communications as edges. To prevent infinite loops during traversal on cyclic paths (common in CNI configurations featuring feedback and redundant segments):
- **BFS Traversal with Visited Set**: Uses a tracking set `visited` to isolate assets that have already been evaluated, terminating loops instantly.
- **Start Node Self-Referencing Filter**: Removes the starting compromised node from the output list of downstream risk assets to prevent circular threat calculations:
  \[\text{Risk Subgraph} = \text{Traversed Nodes} \setminus \{\text{Start Node}\}\]

---

## 3. LangChain Tools & String Sanitization

The `agent_mesh.py` implements tools mimicking LangChain BaseTool structures. To block whitespace anomalies or casing mismatches:
- All input parameters are cast to strings, stripped of surrounding whitespace (`.strip()`), and converted to lowercase (`.lower()`) before evaluation.
- Available tools:
  - `check_footprint_map`: Returns asset properties (criticality, anomaly weight) from the graph topology.
  - `trace_downstream_impact`: Runs the loop-safe BFS search from a starting node.
  - `map_mitre_attack`: Maps signatures to MITRE ATT&CK Enterprise/ICS tactics.

---

## 4. Execution & Validation

To execute the automated validation simulator, run:
```bash
python3 /home/venom/.gemini/antigravity/scratch/graph_intelligence/test_phase3.py
```

### Validation Flow:
1. **Node Seeding**: Adds assets (`Compromised Web Endpoint`, `Core Segment Router`, `Legacy SCADA Asset`) with anomaly weights and criticality ratings.
2. **Cycle Injection**: Sets up a cyclic communication path:
   `Web Endpoint` -> `Core Router` -> `SCADA Asset` -> `Core Router` (loop)
3. **Loop Safety Checks**: Asserts that traversing downstream from `Web Endpoint` yields the correct impacted hosts without infinite loops or self-referential listings.
4. **Agent Mesh Execution**: Executes the ReAct reasoning loop (Thought -> Action -> Observation) and prints the compiled markdown Tactical Warning Report.
