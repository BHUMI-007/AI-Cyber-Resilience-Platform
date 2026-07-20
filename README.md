# 🛡️ AI-Powered Autonomous Cyber Resilience Platform for CNI

> **An agentless, zero-hardcoding AI platform for Critical National Infrastructure (CNI) that leverages unsupervised ML baselining, dynamic topology graphs, and blast-radius-aware SOAR to compress detection & response times from weeks to seconds.**

---

## 📌 Executive Summary

Over **70% of public sector and Critical National Infrastructure (CNI) environments** operate on End-of-Life (EOL) hardware, legacy operating systems, or specialized Industrial OT (SCADA/Modbus) controllers. Installing modern Endpoint Detection and Response (EDR) agents on these legacy systems is often impossible without triggering crashes or operational disruption.

Furthermore, traditional security automation often suffers from a **self-inflicted Denial of Service (DoS) dilemma**: blindly executing automated shutdowns when an incident occurs can paralyze core services, such as hospital databases, examination portals, or power grid dispatch centers.

The **AI-Powered Autonomous Cyber Resilience Platform** solves this challenge by operating **100% agentlessly** via passive network traffic capture (SPAN/TAP). By converting raw telemetry into normalized Open Cybersecurity Schema Framework (OCSF) events, the platform uses unsupervised behavioral baselining, dynamic graph intelligence, and a blast-radius-aware response orchestrator to isolate or throttle threats **in seconds without causing operational downtime**.

---

## 🏗️ System Architecture & 5-Phase Pipeline

The platform is built on a modular, crash-proof, zero-hardcoded Python pipeline consisting of five interconnected engines:

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    PHASE 1: Agentless OCSF Ingestion Highway                    │
│        (Passive SPAN/TAP ──► Zeek/Suricata ──► Vector OCSF Normalization)       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    PHASE 2: Unsupervised ML Behavioral Engine                   │
│         (Sliding-Window Feature Extraction ──► Isolation Forest / PyOD)         │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                 PHASE 3: Graph Intelligence & MITRE Agent Mesh                  │
│       (NetworkX Topology Matrix ──► Cyclic-Safe BFS ──► Multi-Agent TTPs)       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   PHASE 4: Autonomous Response Orchestrator                     │
│      (Bounded Blast-Radius Math ──► Isolation vs. Throttling + HITL Gate)       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   PHASE 5: Cyber Resilience Digital Twin                        │
│         (Deep-Copy Virtual Sandbox ──► Red Team / Blue Team Simulation)         │
└─────────────────────────────────────────────────────────────────────────────────┘