# local.zeek
# Passive Network Tap configuration for core switches / SPAN ports
# Focuses on passive analysis of industrial (OT) protocols and IT traffic

# 1. Enable structured JSON output for all Zeek log streams
# This makes it easy for Vector to ingest and parse logs at high performance
@load policy/tuning/json-logs

# 2. Load standard IT protocol analyzers
@load protocols/conn/main
@load protocols/dns/main
@load protocols/http/main
@load protocols/ssl/main
@load protocols/ssh/main

# 3. Load OT protocol analyzers (Modbus & DNP3 are built-in)
@load protocols/modbus/main
@load protocols/dnp3/main

# 4. Configure IEC 60870-5-104 (IEC 104) protocol registration
# IEC 104 runs on TCP port 2404 by default.
# Note: For full payload analysis, the zeek-plugin-iec104 must be installed.
# We register port 2404 to ensure connection state tracking is optimized.
const iec104_port = 2404/tcp;
redef LikelyAnalyzer::ports += { ["iec104"] = iec104_port };

# Add custom logging for IEC 104 events if the plugin is present
module IEC104;

export {
    # Define the log stream ID
    redef enum Log::ID += { LOG };

    # Record structure matching the IEC 104 schema
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        apdu_type: string &log &optional;
        type_id: count &log &optional;     # ASDU Type ID (e.g. single command, telemetry)
        cot: count &log &optional;         # Cause of Transmission
        coa: count &log &optional;         # Common Address of ASDU (ASDU Address)
        ioa: count &log &optional;         # Information Object Address
        value: string &log &optional;       # Telemetry value read/written
    };
}

# 5. Tune Connection Tracking for SPAN ports
# On SPAN/mirror ports, packet loss can occur during bursts. 
# We disable checksum validation to prevent dropping valid connections due to mirror card artifacts.
redef ignore_checksums = T;

# Tune flow timeouts for high-throughput networks
redef tcp_inactivity_timeout = 15 mins;
redef udp_inactivity_timeout = 1 min;
