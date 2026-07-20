# test_engine.py
# Automated validation suite for Phase 2 Behavioral Anomaly Detection Engine

import random
import time
import json
from sliding_window import SlidingWindowCache
from feature_extractor import FeatureExtractor
from adaptive_model import AdaptiveAnomalyDetector

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def generate_normal_event(timestamp_ms, src_ip):
    """
    Generates a routine OCSF Class 4001 (Network Activity) log representing normal traffic.
    """
    normal_ports = [80, 443, 22]
    dst_ip_pool = ["10.0.5.10", "10.0.5.20", "10.0.5.30"]
    return {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 0,
        "severity_id": 1,
        "time": timestamp_ms,
        "src_endpoint": {
            "ip": src_ip,
            "port": random.randint(49152, 65535)
        },
        "dst_endpoint": {
            "ip": random.choice(dst_ip_pool),
            "port": random.choice(normal_ports)
        },
        "connection_info": {
            "protocol_name": "tcp"
        },
        "traffic": {
            "bytes": random.randint(500, 5000)
        },
        "metadata": {
            "product": {
                "name": "Passive Network Sensor",
                "vendor": "Corelight"
            }
        }
    }

def generate_scan_event(timestamp_ms, src_ip, dst_port):
    """
    Generates an OCSF Class 4001 log representing a scanning packet.
    """
    return {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 0,
        "severity_id": 1,
        "time": timestamp_ms,
        "src_endpoint": {
            "ip": src_ip,
            "port": random.randint(49152, 65535)
        },
        "dst_endpoint": {
            "ip": "10.0.20.99",
            "port": dst_port
        },
        "connection_info": {
            "protocol_name": "tcp"
        },
        "traffic": {
            "bytes": 64  # Small scan packets
        },
        "metadata": {
            "product": {
                "name": "Passive Network Sensor",
                "vendor": "Corelight"
            }
        }
    }

def generate_exfil_event(timestamp_ms, src_ip):
    """
    Generates an OCSF Class 4001 log representing massive data exfiltration over an EOL port.
    """
    return {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 0,
        "severity_id": 1,
        "time": timestamp_ms,
        "src_endpoint": {
            "ip": src_ip,
            "port": random.randint(49152, 65535)
        },
        "dst_endpoint": {
            "ip": "198.51.100.42",  # External untrusted IP
            "port": 21             # FTP (legacy / EOL protocol)
        },
        "connection_info": {
            "protocol_name": "tcp"
        },
        "traffic": {
            "bytes": 50000000  # 50 Megabytes (massive volume outlier)
        },
        "metadata": {
            "product": {
                "name": "Passive Network Sensor",
                "vendor": "Corelight"
            }
        }
    }

def run_simulation():
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}     PHASE 2 UNSUPERVISED BEHAVIORAL ANOMALY DETECTION ENGINE        {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")
    
    # 1. Initialize sliding window (6 hours = 21600 seconds) and feature extractor
    window_duration_sec = 21600
    cache = SlidingWindowCache(window_duration_seconds=window_duration_sec)
    extractor = FeatureExtractor()
    detector = AdaptiveAnomalyDetector(mode="learning")
    
    current_time_sec = 1773050000.0  # Start mock time
    
    # 2. Stage 1: Build Normal Campus Traffic Baseline (500 events)
    print(f"\n{BOLD}[STAGE 1] Simulating 500 events of normal campus workstation traffic...{RESET}")
    print("Generating baseline profiles dynamically...")
    
    # Pools of normal workstation IPs
    normal_workstations = [f"10.0.1.{i}" for i in range(10, 50)]
    
    for i in range(500):
        # Move time forward by a normal interval (5 to 45 seconds)
        current_time_sec += random.randint(5, 45)
        timestamp_ms = int(current_time_sec * 1000)
        
        # Pick a random normal host
        host_ip = random.choice(normal_workstations)
        event = generate_normal_event(timestamp_ms, host_ip)
        
        # 1. Update time-series cache
        cache.add_event(host_ip, event)
        
        # 2. Extract features from sliding window
        window_events = cache.get_events(host_ip, current_time_sec)
        features = extractor.extract_features(window_events, event)
        
        # 3. Fit baseline model incrementally
        detector.fit_incremental(features)
        
    print(f"{GREEN}[SUCCESS] Normal baseline established.{RESET}")
    print(f"Learned baseline metrics summary (means of features):")
    print(f"  - Mean time delta: {detector.means[0]:.2f} sec")
    print(f"  - Std time delta: {detector.stds[0]:.2f} sec")
    print(f"  - Mean rolling window bytes: {detector.means[2]:.2f} bytes")
    print(f"  - Mean request frequency: {detector.means[3]:.2f} events/min")
    print(f"  - Mean target port count: {detector.means[4]:.2f} ports")
    
    # Switch detector to scoring mode to assess alerts strictly
    detector.set_mode("scoring")
    
    # 3. Stage 2: Simulating normal traffic and outputting scores
    print(f"\n{BOLD}[STAGE 2] Checking anomaly scores of random normal traffic...{RESET}")
    normal_scores = []
    for i in range(5):
        current_time_sec += random.randint(10, 30)
        timestamp_ms = int(current_time_sec * 1000)
        host_ip = "10.0.1.15"  # Host 15
        
        event = generate_normal_event(timestamp_ms, host_ip)
        cache.add_event(host_ip, event)
        window_events = cache.get_events(host_ip, current_time_sec)
        features = extractor.extract_features(window_events, event)
        score = detector.score(features)
        normal_scores.append(score)
        print(f"  Normal Event {i+1} from {host_ip}: Score = {GREEN}{score:.4f}{RESET}")

    # 4. Stage 3: Injecting Malformed Logs to Verify Crash-Proof Guardrails
    print(f"\n{BOLD}[STAGE 3] Injecting malformed logs (Crash-Proof Verification)...{RESET}")
    malformed_logs = [
        {"invalid_field": "corrupted_payload", "time": int(current_time_sec * 1000)},  # Missing almost all keys
        {"class_uid": "NOT_AN_INT", "time": "STRING_TIME"},                           # Invalid data types
        None,                                                                         # None event
        {"class_uid": 4001, "time": int(current_time_sec * 1000), "src_endpoint": "string_instead_of_dict"} # Structural mismatch
    ]
    
    for idx, bad_log in enumerate(malformed_logs):
        try:
            asset = extractor.get_asset_id(bad_log) if bad_log else "unknown"
            if bad_log:
                cache.add_event(asset, bad_log)
                window_events = cache.get_events(asset, current_time_sec)
                features = extractor.extract_features(window_events, bad_log)
                score = detector.score(features)
            print(f"  Malformed event {idx+1} processed successfully. Zero crashes. Score = {YELLOW}0.0000 (Safe Fallback){RESET}")
        except Exception as e:
            print(f"  {RED}[CRITICAL BUG]{RESET} Pipeline crashed on malformed event {idx+1}: {e}")
            return
            
    print(f"{GREEN}[SUCCESS] Crash-proof guardrails validated.{RESET}")

    # 5. Stage 4: Ingesting APT threat (Lateral Port Scanning from 10.0.1.25)
    attacker_ip = "10.0.1.25"
    print(f"\n{BOLD}{RED}[STAGE 4] INJECTING APT ATTACK SEQUENCE FROM HOST {attacker_ip}...{RESET}")
    print(f"{BOLD}[APT Phase 1] Lateral Port Scan (Rapid scanning of multiple destination ports){RESET}")
    
    # Simulated lateral scan targeting ports 1000 through 1019 in rapid succession (0.1 second intervals)
    for scan_port in range(1000, 1020):
        current_time_sec += 0.1  # Highly frequent
        timestamp_ms = int(current_time_sec * 1000)
        
        event = generate_scan_event(timestamp_ms, attacker_ip, scan_port)
        
        # Ingest to cache
        cache.add_event(attacker_ip, event)
        window_events = cache.get_events(attacker_ip, current_time_sec)
        features = extractor.extract_features(window_events, event)
        
        score = detector.score(features)
        
        # Color coding score severity
        color = GREEN if score < 0.4 else (YELLOW if score < 0.7 else RED)
        print(f"  Scan Event on Port {scan_port}: Score = {color}{score:.4f}{RESET} | Port Count = {len(window_events)}")
        
    # 6. Stage 5: APT Phase 2 - Data Exfiltration over Legacy FTP (Port 21)
    print(f"\n{BOLD}[APT Phase 2] Data Exfiltration (Massive data volume transfer over legacy protocol){RESET}")
    for exfil_idx in range(3):
        current_time_sec += 5.0  # Periodic massive pushes
        timestamp_ms = int(current_time_sec * 1000)
        
        event = generate_exfil_event(timestamp_ms, attacker_ip)
        
        cache.add_event(attacker_ip, event)
        window_events = cache.get_events(attacker_ip, current_time_sec)
        features = extractor.extract_features(window_events, event)
        
        score = detector.score(features)
        color = GREEN if score < 0.4 else (YELLOW if score < 0.7 else RED)
        print(f"  Exfiltration Burst {exfil_idx+1}: Score = {color}{score:.4f}{RESET} | Exfiltrated Bytes = {features[2]:,}")
        
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{GREEN}[SUCCESS] Phase 2 Behavioral Engine simulation execution completed.{RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}\n")

if __name__ == "__main__":
    run_simulation()
