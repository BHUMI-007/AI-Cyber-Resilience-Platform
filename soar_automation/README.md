# Phase 4: Autonomous Incident Response Orchestrator (SOAR)

This directory contains the source code for the **Phase 4 Autonomous Incident Response Orchestrator (SOAR)**, designed to analyze operational risk, calculate dynamic blast radius metrics, and execute automated playbooks.

---

## 1. Directory Structure

```text
soar_automation/
├── soar_orchestrator.py   # SOAR logic matrix and bounded blast radius calculator
├── test_phase4.py         # Automated Scenario A and Scenario B validation suite
└── README.md              # Setup and execution guide (This file)
```

---

## 2. Bounded Blast Radius Normalization

To prevent blast radius calculations from expanding beyond acceptable bounds in large network topologies (which would crash alert parsing gates), the orchestrator calculates the raw score and scales it relative to the dynamic maximum possible blast radius of the graph:
- **Raw Blast Radius**:
  \[\text{Raw Blast} = C_{\text{target}} \cdot \left(1 + \sum_{n \in \text{downstream}} C_n\right)\]
  where dynamic criticalities map to Low = 1.0, Medium = 2.0, and High = 3.0.
- **Maximum Possible Blast Radius**:
  Calculated dynamically based on the total node count \(M\) of the active graph:
  \[\text{Max Possible Blast} = C_{\text{max}} \cdot \left(1 + C_{\text{max}} \cdot (M - 1)\right)\]
  where \(C_{\text{max}} = 3.0\).
- **Normalized & Bounded Score**:
  The final score is normalized and safely capped at `1.0`:
  \[\text{Bounded Blast} = \min\left(1.0, \frac{\text{Raw Blast}}{\text{Max Possible Blast} + 1e-9}\right)\]

---

## 3. Containment Decision Logic Matrix

The SOAR engine evaluates assets against the following decision matrix to determine active block rules:

| Anomaly Weight (Risk) | Blast Radius Score | Containment Action | Description | Validation Flag |
| :--- | :--- | :--- | :--- | :--- |
| **High (\(\ge 0.70\))** | **Low (\(< 0.50\))** | `autonomous_edge_isolation` | Shuts down the asset network port immediately to contain the threat. | `human_validation_required: false` |
| **High (\(\ge 0.70\))** | **High (\(\ge 0.50\))** | `rate_limiting_bandwidth_throttling` | Aborts full isolation to protect core system availability. Throttles bandwidth. | `human_validation_required: true` |
| **Low (\(< 0.70\))** | **Any** | `monitor_and_log` | Logs and profiles the asset. No active block. | `human_validation_required: false` |

---

## 4. Execution & Validation

To execute the automated validation simulator, run:
```bash
python3 /home/venom/.gemini/antigravity/scratch/soar_automation/test_phase4.py
```

### Validation Scenarios:
1. **Scenario A (Workstation A)**: A compromised low-criticality leaf node. Anomaly weight = `0.90`, Blast radius score \(\approx 0.02\). Triggers **Autonomous Edge Isolation**.
2. **Scenario B (Core Segment Router)**: A compromised high-criticality network hub node. Anomaly weight = `0.80`, Blast radius score \(\approx 0.76\). Triggers **Bandwidth Throttling** and emits the validation flag.
3. **Crash-Proof Checks**: Feeds `None` and non-existent assets to verify error isolation.
