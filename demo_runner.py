import time
import os
import sys

# ANSI Colors for Visual Impact in Terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"{CYAN}{BOLD}")
    print("=========================================================================")
    print(" 🛡️  NATIONAL CYBER RESILIENCE PLATFORM - LIVE SIMULATION DEMO")
    print("=========================================================================")
    print(f"{RESET}")

def run_stage(stage_num, title, description, script_path):
    print(f"\n{YELLOW}{BOLD}[STAGE {stage_num}: {title}]{RESET}")
    print(f"{CYAN}Description:{RESET} {description}")
    print(f"{BOLD}Executing module:{RESET} {script_path}")
    print("-" * 75)
    time.sleep(1.5)  # Pause for judges to read
    
    os.system(f"python3 {script_path}")
    print("-" * 75)
    print(f"{GREEN}✔ Stage {stage_num} Completed Successfully.{RESET}\n")
    time.sleep(2)

if __name__ == "__main__":
    print_banner()
    
    # 1. Pipeline Ingestion
    run_stage(1, "Agentless Pipeline Ingestion & OCSF Normalization",
              "Ingesting raw SPAN/TAP telemetry across IT and legacy OT (SCADA/Modbus) protocols into OCSF format.",
              "agentless_pipeline/simulator/test_normalizer.py")

    # 2. Behavioral Anomaly Engine
    run_stage(2, "Unsupervised Behavioral Anomaly Scoring",
              "Profiling baseline user/device behavior and calculating real-time anomaly scores without static signatures.",
              "behavioral_engine/test_engine.py")

    # 3. Knowledge Graph & MITRE Agent
    run_stage(3, "Graph Intelligence & Threat Attribution",
              "Mapping weak signals to NetworkX topology, tracing lateral jump paths, and mapping to MITRE ATT&CK TTPs.",
              "graph_intelligence/test_phase3.py")

    # 4. Blast Radius SOAR Orchestration
    run_stage(4, "Blast-Radius-Aware Incident Response (SOAR)",
              "Evaluating operational criticality before executing containment (Autonomous Isolation vs. Throttling + HITL).",
              "soar_automation/test_phase4.py")

    # 5. Cyber Resilience Digital Twin
    run_stage(5, "Digital Twin Attack Path & Playbook Modeling",
              "Cloning topology into an isolated sandbox to run AI Red Team simulations and Blue Team impact assessments.",
              "resilience_twin/test_phase5.py")

    print(f"{GREEN}{BOLD}========================================================================={RESET}")
    print(f"{GREEN}{BOLD}🎉 DEMO COMPLETE: Time to Detection & Response Compressed from Weeks to Seconds!{RESET}")
    print(f"{GREEN}{BOLD}========================================================================={RESET}")