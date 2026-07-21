#!/usr/bin/env python3
"""
orchestrator.py -- runs the full 5-phase pipeline end to end, in one process,
without requiring a live Kafka cluster.

Replays the project's own sample sensor telemetry
(agentless_pipeline/simulator/sample_inputs/*.json) through the real Phase 1
normalizer + schema validator, the real Phase 2 behavioral engine, a
persistent Phase 3 topology graph, Phase 4 SOAR decisions, and a Phase 5
digital twin comparison whenever a finding escalates -- printing a live SOC
console feed.

This is the reference implementation of "one platform" rather than five
demos. `iter_raw_events()` is the seam where a real Kafka consumer would
plug in later: swap its file read for `consumer.poll()` and everything
downstream is unchanged.

Usage:
    python orchestrator.py                 # 2 replay cycles, readable pace
    python orchestrator.py --cycles 5 --delay 0.1
"""
import argparse
import json
import os
import random
import time

from agentless_pipeline.simulator.test_normalizer import (
    normalize_zeek_conn, normalize_zeek_ot, normalize_suricata,
    normalize_sysmon, normalize_ad, validate_ocsf_record,
    GREEN, RED, YELLOW, CYAN, BOLD, RESET,
)
from behavioral_engine.sliding_window import SlidingWindowCache
from behavioral_engine.feature_extractor import FeatureExtractor
from behavioral_engine.adaptive_model import AdaptiveAnomalyDetector
from graph_intelligence.graph_intelligence import CNITopologyGraph
from graph_intelligence.agent_mesh import ReActAgentMesh
from soar_automation.soar_orchestrator import CNISoarOrchestrator
from resilience_twin.digital_twin import CyberResilienceDigitalTwin

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "agentless_pipeline", "simulator", "sample_inputs")

# Same routing table Phase 1's own test suite uses -- raw network telemetry
# that flows into Phase 2 behavioral scoring.
NETWORK_SOURCES = [
    ("zeek_conn.json", normalize_zeek_conn, "IT web traffic"),
    ("zeek_modbus.json", normalize_zeek_ot, "OT Modbus write"),
    ("zeek_dnp3.json", normalize_zeek_ot, "OT DNP3 command"),
    ("zeek_iec104.json", normalize_zeek_ot, "OT IEC 104 command"),
]
# Pre-confirmed detections -- these carry their own confidence and skip
# straight to the graph/SOAR/twin chain instead of statistical scoring.
FINDING_SOURCES = [
    ("suricata_eve.json", normalize_suricata, "Suricata IDS alert"),
]
# Endpoint telemetry -- normalized and validated to prove breadth of Phase 1,
# not wired into scoring here (see README for why).
ENDPOINT_SOURCES = [
    ("sysmon_process.json", normalize_sysmon, "Endpoint process telemetry"),
    ("active_directory_auth.json", normalize_ad, "AD authentication event"),
]

# Static asset criticality + topology -- stands in for a real CMDB/asset
# inventory, derived from the IPs actually present in the sample telemetry.
ASSET_CRITICALITY = {
    "10.0.10.25": "Low",     # IT workstation
    "10.0.10.5": "Medium",   # IT web/app server
    "10.0.20.10": "Medium",  # OT engineering workstation
    "10.0.20.50": "High",    # Modbus PLC
    "10.0.20.60": "High",    # DNP3 RTU
    "10.0.20.70": "High",    # IEC 104 substation gateway
}
TOPOLOGY_EDGES = [
    ("10.0.10.25", "10.0.10.5"),
    ("10.0.20.10", "10.0.20.50"),
    ("10.0.20.10", "10.0.20.60"),
    ("10.0.20.10", "10.0.20.70"),
]

ANOMALY_THRESHOLD = 0.75


def ts():
    return time.strftime("%H:%M:%S")


def log(line):
    print(line, flush=True)


def iter_raw_events(filename):
    """Reads one sample telemetry file (plain JSON or JSON-lines). This is
    the seam a real Kafka consumer would replace -- everything downstream
    of this function is unchanged either way."""
    filepath = os.path.join(SAMPLE_DIR, filename)
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def build_graph():
    graph = CNITopologyGraph()
    for asset, crit in ASSET_CRITICALITY.items():
        graph.add_asset(asset, anomaly_weight=0.0, dynamic_crit=crit)
    for src, dst in TOPOLOGY_EDGES:
        graph.add_communication(src, dst)
    return graph


def handle_incident(graph, src, dst, weight, title, incident_log):
    """Phase 3 -> 4 -> 5 chain, triggered by a confirmed finding or a
    behavioral score crossing the anomaly threshold."""
    graph.add_asset(src, anomaly_weight=weight, dynamic_crit=ASSET_CRITICALITY.get(src, "Medium"))
    if dst and dst not in graph.graph.nodes:
        graph.add_asset(dst, anomaly_weight=0.0, dynamic_crit=ASSET_CRITICALITY.get(dst, "Medium"))
    if dst and not graph.graph.has_edge(src, dst):
        graph.add_communication(src, dst)

    mesh = ReActAgentMesh(graph)
    mesh.run(src)  # reasoning logs available via the returned tuple if needed

    soar = CNISoarOrchestrator(graph)
    decision = soar.orchestrate_containment(src)
    action = decision["containment_action"]
    color = RED if action == "autonomous_edge_isolation" else YELLOW if "throttl" in action else GREEN
    log(f"[{ts()}]   {BOLD}\u21b3 SOAR decision for {src}:{RESET} {color}{action}{RESET} "
        f"(anomaly={decision['anomaly_weight']:.2f}, blast_radius={decision['blast_radius_score']:.2f})")

    twin = CyberResilienceDigitalTwin(graph)
    impact = None
    if action == "autonomous_edge_isolation":
        impact = twin.evaluate_playbook_impact(src, "autonomous_edge_isolation")
    elif "throttl" in action:
        impact = twin.evaluate_playbook_impact(src, "rate_limiting_bandwidth_throttling")
    if impact:
        log(f"[{ts()}]   {CYAN}\u21b3 Digital twin:{RESET} est. recovery "
            f"{impact['recovery_window_hours']:.2f}h, downstream loss {impact['downstream_loss_percentage']:.1f}%")

    incident_log.append({"time": ts(), "trigger": title, "asset": src, "action": action,
                          "anomaly": round(decision["anomaly_weight"], 2),
                          "blast_radius": round(decision["blast_radius_score"], 2)})


def replay_cycle(graph, cache, extractor, detectors, delay, incident_log, stats, sim_time):
    for filename, normalizer, label in NETWORK_SOURCES:
        for raw in iter_raw_events(filename):
            raw = dict(raw)
            raw["ts"] = sim_time
            sim_time += random.uniform(4.0, 8.0)  # realistic spacing for feature timing, independent of demo pacing
            normalized = normalizer(raw)
            errors = validate_ocsf_record(normalized)
            asset_id = FeatureExtractor.get_asset_id(normalized)

            cache.add_event(asset_id, normalized)
            window_events = cache.get_events(asset_id, normalized["time"] / 1000.0)
            feats = extractor.extract_features(window_events, normalized)
            detector = detectors.setdefault(asset_id, AdaptiveAnomalyDetector(mode="learning"))
            score = detector.score(feats)
            stats["ingested"] += 1

            valid = f"{GREEN}valid{RESET}" if not errors else f"{RED}SCHEMA-FAIL{RESET}"
            log(f"[{ts()}] INGEST  {label:<20} asset={asset_id:<12} class={normalized['class_uid']} "
                f"{valid}  anomaly={score:.2f}")
            graph.add_asset(asset_id, anomaly_weight=score, dynamic_crit=ASSET_CRITICALITY.get(asset_id, "Medium"))

            if score > ANOMALY_THRESHOLD:
                dst_ip = normalized.get("dst_endpoint", {}).get("ip")
                handle_incident(graph, asset_id, dst_ip, score, f"behavioral drift ({label})", incident_log)
                stats["decisions"] += 1
            time.sleep(delay)

    for filename, normalizer, label in FINDING_SOURCES:
        for raw in iter_raw_events(filename):
            normalized = normalizer(raw)
            errors = validate_ocsf_record(normalized)
            stats["ingested"] += 1
            if normalized.get("class_uid") != 2004:
                continue  # this file also contains plain flow records; only alerts escalate
            src = normalized["src_endpoint"]["ip"]
            dst = normalized["dst_endpoint"]["ip"]
            weight = min(0.6 + 0.1 * normalized["severity_id"], 0.97)
            valid = f"{GREEN}valid{RESET}" if not errors else f"{RED}SCHEMA-FAIL{RESET}"
            log(f"[{ts()}] {YELLOW}ALERT{RESET}   {label:<20} {src} -> {dst}  "
                f"\"{normalized['finding_info']['title']}\"  {valid}")
            handle_incident(graph, src, dst, weight, label, incident_log)
            stats["decisions"] += 1
            time.sleep(delay)

    for filename, normalizer, label in ENDPOINT_SOURCES:
        for raw in iter_raw_events(filename):
            normalized = normalizer(raw)
            errors = validate_ocsf_record(normalized)
            stats["ingested"] += 1
            valid = f"{GREEN}valid{RESET}" if not errors else f"{RED}{errors}{RESET}"
            log(f"[{ts()}] INGEST  {label:<20} class={normalized['class_uid']}  {valid}")
            time.sleep(delay)

    return sim_time


def warmup_baseline(cache, extractor, detectors, cycles=12):
    """Feeds jittered replays of the routine network telemetry before the
    live loop starts, so each asset has a learned baseline instead of
    scoring off a single cold-start sample (which reads as noisy variance,
    not real anomaly). Uses the same spacing distribution as the live
    replay so the baseline and live traffic aren't drawn from different
    patterns."""
    log(f"{CYAN}[SYSTEM] Establishing behavioral baseline...{RESET}")
    sim_time = time.time() - cycles * 6.0
    for _ in range(cycles):
        for filename, normalizer, _label in NETWORK_SOURCES:
            for raw in iter_raw_events(filename):
                raw = dict(raw)
                raw["ts"] = sim_time
                sim_time += random.uniform(4.0, 8.0)
                normalized = normalizer(raw)
                asset_id = FeatureExtractor.get_asset_id(normalized)
                cache.add_event(asset_id, normalized)
                window_events = cache.get_events(asset_id, normalized["time"] / 1000.0)
                feats = extractor.extract_features(window_events, normalized)
                detector = detectors.setdefault(asset_id, AdaptiveAnomalyDetector(mode="learning"))
                detector.score(feats)
    log(f"{CYAN}[SYSTEM] Baseline established for {len(detectors)} assets.{RESET}\n")
    return sim_time


def print_summary(incident_log, stats):
    log(f"\n{BOLD}{CYAN}{'=' * 72}{RESET}")
    log(f"{BOLD}Run summary{RESET}")
    log(f"  Telemetry events ingested : {stats['ingested']}")
    log(f"  SOAR decisions triggered  : {stats['decisions']}")
    if incident_log:
        log(f"\n  {'Time':<10}{'Trigger':<26}{'Asset':<14}{'Action':<32}{'Anomaly':<9}Blast")
        for row in incident_log:
            log(f"  {row['time']:<10}{row['trigger']:<26}{row['asset']:<14}{row['action']:<32}"
                f"{row['anomaly']:<9}{row['blast_radius']}")
    log(f"{BOLD}{CYAN}{'=' * 72}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cycles", type=int, default=2, help="number of replay cycles (default: 2)")
    parser.add_argument("--delay", type=float, default=0.3, help="seconds between events, for readability (default: 0.3)")
    args = parser.parse_args()

    graph = build_graph()
    cache = SlidingWindowCache()
    extractor = FeatureExtractor()
    detectors = {}
    incident_log = []
    stats = {"ingested": 0, "decisions": 0}

    log(f"{BOLD}{CYAN}{'=' * 72}{RESET}")
    log(f"{BOLD}{CYAN}  CNI CYBER RESILIENCE PLATFORM -- single-process orchestrator{RESET}")
    log(f"{BOLD}{CYAN}{'=' * 72}{RESET}\n")

    sim_time = warmup_baseline(cache, extractor, detectors)

    for cycle in range(1, args.cycles + 1):
        log(f"\n{BOLD}--- Cycle {cycle}/{args.cycles} ---{RESET}")
        sim_time = replay_cycle(graph, cache, extractor, detectors, args.delay, incident_log, stats, sim_time)

    print_summary(incident_log, stats)


if __name__ == "__main__":
    main()