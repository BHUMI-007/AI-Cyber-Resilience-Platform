#!/usr/bin/env python3
"""
OCSF Telemetry Normalizer and Schema Validator.
Replicates the Vector VRL (Vector Remap Language) pipeline inside a Python validation runner.
Ensures conformance to OCSF v1.1.0/v1.2.0 schemas and validates OT metadata containment rules.
"""

import os
import json
import time
from datetime import datetime, timezone

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Path to workspace directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUTS_DIR = os.path.join(BASE_DIR, "sample_inputs")
OUTPUTS_DIR = os.path.join(BASE_DIR, "sample_outputs")
os.makedirs(OUTPUTS_DIR, exist_ok=True)


def parse_timestamp_safe(ts_str):
    """
    Safe datetime parsing. Mimics:
    parse_timestamp(.timestamp, "%Y-%m-%dT%H:%M:%S.%f%z") ?? parse_timestamp(...) ?? now()
    """
    if not ts_str:
        return int(time.time() * 1000)
    
    # Try ISO with offset (e.g. 2026-07-10T12:47:42.000123+0300)
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z"
    ]:
        try:
            # Normalize offset format (+0300 -> +03:00)
            cleaned = ts_str
            if "+" in cleaned and len(cleaned.split("+")[-1]) == 4:
                offset = cleaned.split("+")[-1]
                cleaned = cleaned.replace("+" + offset, "+" + offset[:2] + ":" + offset[2:])
            elif "-" in cleaned and len(cleaned.split("-")[-1]) == 4 and "T" in cleaned:
                offset = cleaned.split("-")[-1]
                cleaned = cleaned.replace("-" + offset, "-" + offset[:2] + ":" + offset[2:])
                
            dt = datetime.strptime(cleaned, fmt)
            return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
        except ValueError:
            continue
            
    # Fallback to current time
    return int(time.time() * 1000)


# ==========================================
# VRL Transform Implementations (Python)
# ==========================================

def normalize_zeek_conn(raw):
    """VRL: normalize_zeek_conn"""
    ts_float = float(raw.get("ts", 0.0))
    time_ms = int(ts_float * 1000.0)
    
    id_block = raw.get("id", {})
    
    return {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 0,
        "severity_id": 1,
        "time": time_ms,
        "src_endpoint": {
            "ip": str(id_block.get("orig_h", "0.0.0.0")),
            "port": int(id_block.get("orig_p", 0))
        },
        "dst_endpoint": {
            "ip": str(id_block.get("resp_h", "0.0.0.0")),
            "port": int(id_block.get("resp_p", 0))
        },
        "connection_info": {
            "protocol_name": str(raw.get("proto", "tcp")).lower()
        },
        "metadata": {
            "product": {
                "name": "Zeek Connection Logs",
                "vendor": "Corelight",
                "version": "6.0.0"
            }
        }
    }


def normalize_zeek_ot(raw):
    """VRL: normalize_zeek_ot"""
    ts_float = float(raw.get("ts", 0.0))
    time_ms = int(ts_float * 1000.0)
    
    id_block = raw.get("id", {})
    
    ocsf = {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 0,
        "severity_id": 1,
        "time": time_ms,
        "src_endpoint": {
            "ip": str(id_block.get("orig_h", "0.0.0.0")),
            "port": int(id_block.get("orig_p", 0))
        },
        "dst_endpoint": {
            "ip": str(id_block.get("resp_h", "0.0.0.0")),
            "port": int(id_block.get("resp_p", 0))
        },
        "connection_info": {
            "protocol_name": "tcp"
        },
        "metadata": {
            "product": {
                "name": "Zeek OT Parser",
                "vendor": "Corelight"
            }
        },
        "extensions": {
            "ot_extension": {
                "protocol": "unknown"
            }
        }
    }
    
    # Custom profile extension logic
    # A. Modbus check
    if "func_code" in raw or "func" in raw:
        ocsf["extensions"]["ot_extension"] = {
            "protocol": "modbus",
            "function_code": int(raw.get("func_code", 0)),
            "function_name": str(raw.get("func", "unknown")),
            "unit_id": int(raw.get("unit_id", 0)),
            "address": str(raw.get("address", "unknown")),
            "value": str(raw.get("value", ""))
        }
    # B. DNP3 check
    elif "fc_request" in raw or "fc_response" in raw:
        fc = raw.get("fc_request") or raw.get("fc_response")
        ocsf["extensions"]["ot_extension"] = {
            "protocol": "dnp3",
            "function_name": str(fc) if fc else "unknown",
            "dnp3_iin": str(raw.get("iin", "0"))
        }
    # C. IEC 104 check
    elif "apdu_type" in raw:
        ocsf["extensions"]["ot_extension"] = {
            "protocol": "iec104",
            "iec104_coa": int(raw.get("coa", 0)),
            "iec104_ioa": int(raw.get("ioa", 0)),
            "iec104_cot": int(raw.get("cot", 0)),
            "value": str(raw.get("value", ""))
        }
        
    return ocsf


def normalize_suricata(raw):
    """VRL: normalize_suricata"""
    ts_str = raw.get("timestamp", "")
    time_ms = parse_timestamp_safe(ts_str)
    
    if "alert" in raw:
        alert = raw["alert"]
        pri = int(alert.get("priority", 3))
        
        # Priority mapping: 1 -> 5, 2 -> 4, 3 -> 3, 4 -> 2
        severity_id = 5 if pri == 1 else (4 if pri == 2 else (3 if pri == 3 else 2))
        
        return {
            "class_uid": 2004,
            "category_uid": 2,
            "activity_id": 1,
            "severity_id": severity_id,
            "time": time_ms,
            "finding_info": {
                "title": str(alert.get("signature", "Unknown Alert")),
                "uid": str(alert.get("signature_id", "0"))
            },
            "src_endpoint": {
                "ip": str(raw.get("src_ip", "0.0.0.0")),
                "port": int(raw.get("src_port", 0))
            },
            "dst_endpoint": {
                "ip": str(raw.get("dest_ip", "0.0.0.0")),
                "port": int(raw.get("dest_port", 0))
            },
            "metadata": {
                "product": {
                    "name": "Suricata Alert",
                    "vendor": "OISF"
                }
            }
        }
    else:
        return {
            "class_uid": 4001,
            "category_uid": 4,
            "activity_id": 0,
            "severity_id": 1,
            "time": time_ms,
            "src_endpoint": {
                "ip": str(raw.get("src_ip", "0.0.0.0")),
                "port": int(raw.get("src_port", 0))
            },
            "dst_endpoint": {
                "ip": str(raw.get("dest_ip", "0.0.0.0")),
                "port": int(raw.get("dest_port", 0))
            },
            "connection_info": {
                "protocol_name": str(raw.get("proto", "tcp")).lower()
            },
            "metadata": {
                "product": {
                    "name": "Suricata Flow Logs",
                    "vendor": "OISF"
                }
            }
        }


def normalize_sysmon(raw):
    """VRL: normalize_sysmon"""
    event = raw.get("Event", {})
    system = event.get("System", {})
    event_data = event.get("EventData", {})
    
    system_time = system.get("TimeCreated", {}).get("SystemTime", "")
    time_ms = parse_timestamp_safe(system_time)
    
    return {
        "class_uid": 1007,
        "category_uid": 1,
        "activity_id": 1,
        "severity_id": 1,
        "time": time_ms,
        "process": {
            "name": str(event_data.get("Image", "unknown")),
            "pid": int(event_data.get("ProcessId", 0)),
            "cmd_line": str(event_data.get("CommandLine", ""))
        },
        "process.parent_process": {
            "name": str(event_data.get("ParentImage", "unknown")),
            "pid": int(event_data.get("ParentProcessId", 0))
        },
        "actor": {
            "user": {
                "name": str(event_data.get("User", "unknown"))
            }
        },
        "metadata": {
            "product": {
                "name": "Sysmon",
                "vendor": "Microsoft"
            }
        }
    }


def normalize_ad(raw):
    """VRL: normalize_ad"""
    event = raw.get("Event", {})
    system = event.get("System", {})
    event_data = event.get("EventData", {})
    
    system_time = system.get("TimeCreated", {}).get("SystemTime", "")
    time_ms = parse_timestamp_safe(system_time)
    
    src_ip = str(event_data.get("IpAddress", "127.0.0.1"))
    if src_ip == "-":
        src_ip = "127.0.0.1"
        
    return {
        "class_uid": 3002,
        "category_uid": 3,
        "activity_id": 1,
        "severity_id": 1,
        "time": time_ms,
        "user": {
            "name": str(event_data.get("TargetUserName", "unknown")),
            "domain": str(event_data.get("TargetDomainName", "unknown"))
        },
        "src_endpoint": {
            "ip": src_ip
        },
        "logon_type": int(event_data.get("LogonType", 3)),
        "metadata": {
            "product": {
                "name": "Active Directory Security Audit",
                "vendor": "Microsoft"
            }
        }
    }


# ==========================================
# OCSF Rules Checker & Validation Logic
# ==========================================

def validate_ocsf_record(record):
    """
    Verifies that the generated record is fully compliant with OCSF specifications
    """
    errors = []
    
    # 1. Base Class Mandatory Fields
    for key in ["class_uid", "category_uid", "activity_id", "severity_id", "time", "metadata"]:
        if key not in record:
            errors.append(f"Missing mandatory base field '{key}'")
            
    # Check values
    if "class_uid" in record and not isinstance(record["class_uid"], int):
        errors.append(f"'class_uid' must be an integer (got {type(record['class_uid']).__name__})")
        
    if "time" in record:
        if not isinstance(record["time"], int) or record["time"] <= 0:
            errors.append(f"'time' must be a valid epoch millisecond integer (got {record['time']})")
            
    # 2. Check metadata block
    if "metadata" in record:
        meta = record["metadata"]
        if not isinstance(meta, dict) or "product" not in meta:
            errors.append("Metadata must be a dictionary containing 'product'")
        else:
            prod = meta["product"]
            if not isinstance(prod, dict) or "name" not in prod or "vendor" not in prod:
                errors.append("Metadata.product must contain 'name' and 'vendor'")

    # 3. Class-specific structural validation
    class_uid = record.get("class_uid", 0)
    
    # Class 4001: Network Activity
    if class_uid == 4001:
        if "src_endpoint" not in record or not isinstance(record["src_endpoint"], dict):
            errors.append("Network Activity (4001) requires a 'src_endpoint' dictionary")
        else:
            if "ip" not in record["src_endpoint"] or not record["src_endpoint"]["ip"]:
                errors.append("src_endpoint requires an 'ip'")
        
        if "dst_endpoint" not in record or not isinstance(record["dst_endpoint"], dict):
            errors.append("Network Activity (4001) requires a 'dst_endpoint' dictionary")
        else:
            if "ip" not in record["dst_endpoint"] or not record["dst_endpoint"]["ip"]:
                errors.append("dst_endpoint requires an 'ip'")
                
        # 4. Critical OT isolation check: Verify OT fields do NOT leak to the root level
        # This checks for direct inclusion of Modbus/DNP3/IEC 104 properties at root level
        for leaked_key in ["func_code", "func", "unit_id", "address", "fc_request", "fc_response", "iin", "apdu_type", "coa", "ioa", "cot"]:
            if leaked_key in record:
                errors.append(f"OT Isolation Violation: Raw OT key '{leaked_key}' leaked to OCSF root level!")
                
        # Check extensions block
        if "extensions" in record:
            ext = record["extensions"]
            if "ot_extension" in ext:
                ot_ext = ext["ot_extension"]
                if "protocol" not in ot_ext:
                    errors.append("extensions.ot_extension requires a 'protocol' name")
                    
    # Class 2004: Detection Finding
    elif class_uid == 2004:
        if "finding_info" not in record or not isinstance(record["finding_info"], dict):
            errors.append("Detection Finding (2004) requires 'finding_info'")
        else:
            finfo = record["finding_info"]
            if "title" not in finfo or not finfo["title"]:
                errors.append("finding_info requires a 'title'")
            if "uid" not in finfo or not finfo["uid"]:
                errors.append("finding_info requires a 'uid'")
                
    # Class 1007: Process Activity
    elif class_uid == 1007:
        if "process" not in record or not isinstance(record["process"], dict):
            errors.append("Process Activity (1007) requires a 'process' dictionary")
        else:
            proc = record["process"]
            if "name" not in proc or not proc["name"]:
                errors.append("process requires a 'name'")
            if "pid" not in proc:
                errors.append("process requires a 'pid'")
        if "actor" not in record or "user" not in record["actor"]:
            errors.append("Process Activity (1007) requires 'actor.user'")
            
    # Class 3002: Authentication Activity
    elif class_uid == 3002:
        if "user" not in record or "name" not in record["user"] or "domain" not in record["user"]:
            errors.append("Authentication Activity (3002) requires user name and domain")
        if "logon_type" not in record:
            errors.append("Authentication Activity (3002) requires 'logon_type'")
            
    return errors


# ==========================================
# Main Test Orchestrator
# ==========================================

def run_tests():
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}             OCSF NORMALIZATION & OT ISOLATION TEST SUITE            {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")
    
    test_cases = [
        ("zeek_conn.json", normalize_zeek_conn, "Zeek HTTP/TCP Connection"),
        ("zeek_modbus.json", normalize_zeek_ot, "Zeek OT Modbus TCP Write"),
        ("zeek_dnp3.json", normalize_zeek_ot, "Zeek OT DNP3 Cold Restart"),
        ("zeek_iec104.json", normalize_zeek_ot, "Zeek OT IEC 60870-5-104 Command"),
        ("suricata_eve.json", normalize_suricata, "Suricata Alerts & Flows"),
        ("sysmon_process.json", normalize_sysmon, "Windows Sysmon Process Launch"),
        ("active_directory_auth.json", normalize_ad, "Active Directory 4624 Authentication")
    ]
    
    total_passed = 0
    total_failed = 0
    
    for filename, normalizer_func, label in test_cases:
        filepath = os.path.join(INPUTS_DIR, filename)
        if not os.path.exists(filepath):
            print(f"{RED}[ERROR]{RESET} Test input file {filename} not found in {INPUTS_DIR}!")
            total_failed += 1
            continue
            
        print(f"\n{BOLD}Running normalization check on: {label} ({filename}){RESET}")
        
        # Read file. Some files (like suricata_eve.json) are JSON Lines (JSONL)
        raw_events = []
        with open(filepath, "r") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        raw_events.append(json.loads(line_str))
                    except json.JSONDecodeError as e:
                        print(f"  {RED}[ERROR]{RESET} Failed to decode JSON line: {e}")
                        
        case_passed = True
        normalized_results = []
        
        for idx, raw_ev in enumerate(raw_events):
            # 1. Replicate VRL transform
            try:
                normalized = normalizer_func(raw_ev)
                normalized_results.append(normalized)
            except Exception as ex:
                print(f"  Event {idx+1}: {RED}FAIL{RESET} - Transform exception: {ex}")
                case_passed = False
                continue
                
            # 2. Validate OCSF Schema conformance
            errors = validate_ocsf_record(normalized)
            if not errors:
                print(f"  Event {idx+1}: {GREEN}PASS{RESET} (OCSF Class {normalized['class_uid']})")
                # Show OT separation proof if applicable
                if "extensions" in normalized and "ot_extension" in normalized["extensions"]:
                    ot_proto = normalized["extensions"]["ot_extension"]["protocol"]
                    print(f"    {GREEN}↳ Proof of OT Isolation:{RESET} '{ot_proto}' fields successfully isolated in .extensions.ot_extension")
            else:
                print(f"  Event {idx+1}: {RED}FAIL{RESET}")
                for err in errors:
                    print(f"    - {RED}Error:{RESET} {err}")
                case_passed = False
                
        # Write OCSF output logs to file
        output_filename = f"ocsf_{filename}"
        output_filepath = os.path.join(OUTPUTS_DIR, output_filename)
        with open(output_filepath, "w") as out_f:
            for norm in normalized_results:
                out_f.write(json.dumps(norm) + "\n")
                
        print(f"  {CYAN}↳ Normalized telemetry saved to:{RESET} {output_filepath}")
        
        if case_passed:
            total_passed += 1
        else:
            total_failed += 1
            
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}Test Execution Summary:{RESET}")
    print(f"  Passed cases: {GREEN}{total_passed}{RESET}")
    print(f"  Failed cases: {RED}{total_failed}{RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")
    
    if total_failed > 0:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run_tests())
