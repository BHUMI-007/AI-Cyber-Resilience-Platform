# Passive Agentless IT/OT Security Telemetry Pipeline

This repository contains configurations and validation tests for an agentless, passive network-monitoring and telemetry-normalization pipeline. The pipeline captures low-level IT and OT signals without loading agents onto endpoints, normalizes them to the **Open Cybersecurity Schema Framework (OCSF)**, and streams them through **Vector** to **Apache Kafka**.

---

## 1. Passive Capture & Sensor Deployment Architecture

To achieve absolute agentless visibility, sensors are deployed at core network boundaries. Legacy systems (PLCs, RTUs, old servers) are not touched; network traffic is mirrored at the switch level.

```
       +---------------------------------------------+
       |             IT & OT Core Switch             |
       +---------------------------------------------+
              |                               |
        [SPAN Port 1]                   [SPAN Port 2]
         (IT VLANs)                      (OT VLANs)
              |                               |
              +---------------+---------------+
                              |
                     Passive Network TAP
                              |
                    +---------+---------+
                    |                   |
               [eth1: SPAN]        [eth1: SPAN]
            +---------------+   +-----------------+
            |  Zeek Sensor  |   | Suricata Sensor |
            +---------------+   +-----------------+
                    |                    |
                conn.log              eve.json
               modbus.log             (Alerts)
                dnp3.log                 |
                    |                    |
                    +---------+----------+
                              |
                         (TCP Push)
                              v
                  +-----------------------+
                  |    Vector Pipeline    | (Disk-Buffered)
                  +-----------------------+
                              |
                        (OCSF Normal)
                              v
                  +-----------------------+
                  |  Apache Kafka Broker  | (Unified Event Bus)
                  +-----------------------+
```

### A. Switch Mirroring (SPAN Port Configuration)
For core network switches, configure Switch Port Analyzer (SPAN) or port mirroring to mirror aggregate uplink/downlink traffic to the network monitoring ports.

*Example Cisco Catalyst IOS configuration:*
```ios
! Define the session number and source VLANs to monitor
monitor session 1 source vlan 10 , 20 , 30 both

! Define the destination port connected to the Zeek/Suricata sensor
monitor session 1 destination interface GigabitEthernet0/24 encapsulation replicate
```

### B. Configuring Promiscuous Mode on Sensors
To process raw traffic without IP bindings (minimizing sensor attack surface), configure the monitoring interface in promiscuous mode without an IP address.

*Linux systemd-networkd / NetworkManager configuration on the sensor:*
```bash
# Enable promiscuous mode and bring interface up without IPv4/v6 addresses
sudo ip link set dev eth1 promisc on
sudo ip link set dev eth1 up
```

---

## 2. Sensor Configurations & Industrial Parsers

### Zeek NSM
Zeek is configured in `/zeek/local.zeek` to:
1. Output all logs as structured JSON (`@load policy/tuning/json-logs`).
2. Load native OT protocol analyzers for **Modbus** and **DNP3**.
3. Register TCP port 2404 for **IEC 60870-5-104 (IEC 104)** connection tracking.
4. Disable network packet checksum validation (`ignore_checksums = T`) to handle mirroring errors safely.

> [!TIP]
> To enable deep ASDU payload extraction for IEC 104, install the external parser using Zeek Package Manager:
> `zkg install zeek/amazon-science/iec104`

### Suricata IDS
Suricata is configured in `/suricata/suricata.yaml` to read from the raw capture interface `eth1` using high-performance AF_PACKET ring buffers and load threat signatures from `/suricata/rules/ot.rules`.

We use Native Suricata application-layer keywords to detect commands:
- **Modbus Writes / Setpoint adjustments**: Detects writes to coils or registers (Functions 5, 6, 15, 16).
- **DNP3 Reboots**: Detects outstation Cold/Warm Restart commands (Functions 13, 14) and Stop Application requests.
- **IEC 104 Connection Tracking**: Audits APCI start sequence headers (0x68) on TCP port 2404.

---

## 3. High-Throughput Event Bus & Buffering Policies

**Vector** acts as the high-throughput aggregator. Vector receives raw logs over TCP sockets, normalizes them via **Vector Remap Language (VRL)**, and streams them to Apache Kafka.

### Zero-Loss Disk Buffering
To ensure zero data loss during high-stress scenarios (e.g. broadcast storms, DDoS events, or downstream Kafka maintenance), Vector is configured with **disk-backed buffers** at the sink layer:
- **Type**: `disk`
- **Max Size**: `10 GiB` (Configured via `max_size`)
- **Full Policy**: `block` (Backpressures the TCP input socket instead of dropping records)

```yaml
    buffer:
      type: "disk"
      max_size: 10737418240
      when_full: "block"
```

---

## 4. OCSF Normalization & Isolation Scheme

Telemetry is normalized to standard OCSF classes to enforce a unified language across IT and OT:

| Source Log | OCSF Category | OCSF Class UID | OCSF Class Name | Mapping Details |
| :--- | :--- | :--- | :--- | :--- |
| **Zeek connection logs** | Network Activity (4) | `4001` | **Network Activity** | Maps IP addresses, ports, protocols, and connection states. |
| **Zeek Modbus/DNP3/IEC104 logs** | Network Activity (4) | `4001` | **Network Activity** | Maps network metadata, isolating OT-specific attributes into the `.extensions.ot_extension` block. |
| **Suricata Alerts** | Findings (2) | `2004` | **Detection Finding** | Maps alert signatures, IDs, priorities, and matching indicators. |
| **Suricata Flows** | Network Activity (4) | `4001` | **Network Activity** | Maps netflow statistics, bytes, packets, and duration. |
| **Windows Sysmon Event 1** | System Activity (1) | `1007` | **Process Activity** | Maps process names, PIDs, CLI arguments, parent context, and actor user. |
| **Active Directory Event 4624** | Identity & Access (3) | `3002` | **Authentication Activity** | Maps target domain, logon types (e.g., interactive, network), and usernames. |

### OT Isolation Rule
To prevent dilution of IT log search indices, industrial-specific payload metadata must **never** be injected at the schema root. The normalization engine enforces isolation within:
`.extensions.ot_extension.<attribute>`

---

## 5. Enterprise Scaling & Kafka Partitioning

To scale the pipeline to millions of events per second:
1. **CPU Pinning**: Configure Vector to utilize multiple CPU threads by scaling the `Vector` process vertically, and set `multithreaded = true` if running on multi-core sensors.
2. **Kafka Partition Key**: Partition Kafka logs by `src_endpoint.ip` or `dst_endpoint.ip` instead of using round-robin. This ensures that sequence order is strictly maintained for events originating from the same system, allowing SIEM correlators to track progressive attack states (e.g. reconnaissance -> write commands -> process execution).
3. **Log Sharding**: Dedicate different topics for high-volume logs:
   - `ot-network-activity` (Modbus, DNP3, IEC 104)
   - `it-network-activity` (Zeek http, dns, conn logs)
   - `endpoint-findings` (Suricata alerts, Sysmon, AD audits)
