# Phase 5: Cyber Resilience Digital Twin

This directory contains the source code for the **Phase 5 Cyber Resilience Digital Twin**, designed to mirror active CNI network topologies, simulate attacker lateral movements, and quantify the operational trade-offs between different response playbooks.

---

## 1. Directory Structure

```text
resilience_twin/
├── digital_twin.py   # Isolated sandbox map cloner, attack propagator, and impact evaluator
├── test_phase5.py    # Automated multi-hop target propagation validation suite
└── README.md         # Setup and execution guide (This file)
```

---

## 2. Dynamic Threat Propagation Sim (Unsupervised Pathing)

The digital twin models attacker behavior inside the cloned `sandbox_graph` using unsupervised path iteration:
- **Descending Criticality Traversal**: Starting from a compromised host, the threat agent evaluates all adjacent unvisited nodes. The simulator prioritizes targets based on descending dynamic criticality values:
  High (3.0) > Medium (2.0) > Low (1.0).
- **Tie-breaker Rules**: If adjacent nodes share the same criticality rating, the pathing breaks the tie using descending anomaly weights.
- **Loop Prevention**: Active nodes visited during traversal are tracked in a `visited` set to ensure the simulation terminates safely on cyclic loops.

---

## 3. Playbook Operational Resilience Calculations

The orchestrator evaluates and quantifies the operational impact of isolation versus throttling:

### A. Autonomous Edge Isolation
Isolating a node completely detaches it and its downstream dependencies:
- **Downstream Loss %**: Percentage of CNI assets cut off from the network:
  \[\text{Loss \%} = \frac{N_{\text{downstream}}}{N_{\text{total}}} \cdot 100\]
- **Recovery Window (Hours)**: Time to physically re-image or reconnect interfaces:
  \[\text{Recovery Hours} = 2.0 \cdot C_{\text{target}}\]

### B. Rate-Limiting Bandwidth Throttling
Throttling maintains network access (0.0% node loss count), reducing the immediate impact:
- **Downstream Loss %**: `0.00%` (Assets remain online).
- **Recovery Window (Hours)**: Dynamic soft-configurable configuration reload time:
  \[\text{Recovery Hours} = 0.5 \cdot C_{\text{target}}\]

---

## 4. Type Compatibility & Sanitization

To prevent NameErrors and TypeErrors when reading irregular string keys or none-type fields from fallback dictionaries:
1. All node lookups are wrapped inside an explicit `.strip()` string sanitizer.
2. Element counts are cast to float values (`float(len(...))`) before executing division or multiplication operations.
3. The resulting recovery time is rounded to two decimal places using `round(..., 2)` to guarantee clean floating-point structures.

---

## 5. Execution & Validation

To run the automated digital twin validation simulation:
```bash
python3 /home/venom/.gemini/antigravity/scratch/resilience_twin/test_phase5.py
```
This script seeds a cyclic topology, mirrors it to the digital twin sandbox, traces the threat actor's steps from a compromised endpoint, and outputs the comparative playbook metrics.
