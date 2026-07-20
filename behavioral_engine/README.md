# Phase 2: Unsupervised Behavioral Anomaly Detection Engine

This directory contains the source code for the **Phase 2 Behavioral Anomaly Detection Engine**, designed to ingest normalized OCSF events, extract dynamic statistical profiles per network asset, and flag multi-stage Advanced Persistent Threats (APTs) (such as lateral movement and exfiltration) without relying on hardcoded thresholds.

---

## 1. Directory Structure

```text
behavioral_engine/
├── sliding_window.py       # Time-series sliding window cache utilizing collections.deque (O(1))
├── feature_extractor.py    # Dynamic OCSF parsing and mathematical metrics calculator
├── adaptive_model.py       # Unsupervised PyOD wrapper with a crash-proof standard-library fallback
├── test_engine.py          # Simulated validation test runner (Baseline + APT inject)
└── README.md               # Setup and execution guide (This file)
```

---

## 2. Dynamic Metric Extraction (Mathematical Features)

The `FeatureExtractor` parses incoming logs (Class 4001, 1007, 3002) and computes the following feature vector \(X\) per asset:
1. **Mean Time-Delta (\(\mu_{td}\))**: Average time gap (in seconds) between sequential events.
2. **Std Time-Delta (\(\sigma_{td}\))**: Variance distribution of transaction timestamps (helps detect rigid periodic automated beacons vs. sporadic human commands).
3. **Rolling Data Volume**: Sum of bytes sent by the asset within the sliding window.
4. **Request Frequency**: Message rate (events per minute).
5. **Destination Port Count**: Count of unique targeted ports in the window (identifies port scans and lateral recon).

---

## 3. Algorithmic Guardrails

- **Zero-Latency Sliding Cache**: Built using `collections.deque` with automatic time-based pruning. Appends and pops are executed in \(O(1)\) time, ensuring zero performance drops even during traffic bursts.
- **Epsilon safety boundaries**: Standard deviation calculations include a small epsilon (\(\epsilon = 1e-9\)) in the denominator during Z-score standardized distance computation to avoid division-by-zero errors when analyzing highly uniform, automated industrial traffic:
  \[z_i = \frac{x_i - \mu_i}{\sigma_i + 1e-9}\]
- **Dual Mode Adaptability**: The detector dynamically checks for `pyod` and `scikit-learn` in the environment. If imports fail, it automatically switches to an optimized standard-library Z-score Mahalanobis distance calculator using Welford's algorithm to compute rolling variance in \(O(1)\) space.

---

## 4. Execution & Validation

To execute the automated validation simulator, run:
```bash
python3 /home/venom/.gemini/antigravity/scratch/behavioral_engine/test_engine.py
```

### Simulation Stages:
1. **Stage 1 (Baseline)**: Generates 500 events simulating normal workstation traffic (standard ports 80/443, small data payloads, normal frequency) and trains the running statistical mean/std profiles.
2. **Stage 2 (Normal scoring)**: Evaluates new routine events (Score should remain low, e.g., `< 0.35`).
3. **Stage 3 (Crash-proof verify)**: Injects corrupted payloads, missing keys, and incorrect types to confirm the pipeline isolates errors without crashing.
4. **Stage 4 (APT Lateral Scan)**: Injects a rapid sequence of events from a single host targeting 20 different ports. The anomaly score rises immediately (indicating port diversity and frequency outliers).
5. **Stage 5 (APT Exfiltration)**: Injects massive multi-megabyte exfiltration bursts over port 21 (FTP). The score spikes towards `1.0` (indicating rolling byte volume outliers).
