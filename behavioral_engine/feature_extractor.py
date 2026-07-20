# feature_extractor.py
# Dynamic, index-free OCSF feature extraction for unsupervised anomaly detection

import math

class FeatureExtractor:
    """
    Extracts numerical feature vectors from historical OCSF events in the sliding window.
    Provides crash-proof, schema-agnostic extraction.
    """
    @staticmethod
    def get_asset_id(event):
        """
        Dynamically extracts a unique identifier for the source asset from OCSF payload.
        Order of priority: src_endpoint.ip -> Computer/Host Name -> Actor Username.
        """
        try:
            if not isinstance(event, dict):
                return "unknown_asset"

            # 1. Network Activity (Class 4001) / Suricata Alerts (Class 2004)
            src_ep = event.get("src_endpoint")
            if isinstance(src_ep, dict):
                ip = src_ep.get("ip")
                if ip and ip not in ("-", "127.0.0.1", ""):
                    return ip

            # 2. Windows Event Logs (AD / Sysmon)
            system = event.get("Event", {}).get("System")
            if isinstance(system, dict):
                comp = system.get("Computer")
                if comp:
                    return comp

            # 3. Identity Logs (Active Directory Class 3002)
            user = event.get("user")
            if isinstance(user, dict):
                username = user.get("name")
                if username and username != "unknown":
                    return username
                    
            # 4. Fallback actor user
            actor_user = event.get("actor", {}).get("user", {}).get("name")
            if actor_user:
                return actor_user
        except Exception:
            pass
        return "unknown_asset"

    @staticmethod
    def get_event_bytes(event):
        """
        Safely extracts traffic byte size from OCSF payload.
        """
        try:
            if not isinstance(event, dict):
                return 0
            # Check traffic block
            traffic = event.get("traffic")
            if isinstance(traffic, dict):
                b = traffic.get("bytes")
                if b is not None:
                    return int(b)
            # Check root-level bytes
            b_root = event.get("bytes")
            if b_root is not None:
                return int(b_root)
        except Exception:
            pass
        return 0

    @staticmethod
    def get_dst_port(event):
        """
        Safely extracts destination port from OCSF payload.
        """
        try:
            if not isinstance(event, dict):
                return 0
            dst_ep = event.get("dst_endpoint")
            if isinstance(dst_ep, dict):
                p = dst_ep.get("port")
                if p is not None:
                    return int(p)
        except Exception:
            pass
        return 0

    def extract_features(self, events, current_event):
        """
        Processes a list of events in the window for an asset and returns a normalized
        feature vector: [mean_time_delta, std_time_delta, rolling_bytes, frequency, port_diversity]
        
        All math metrics are computed relative to the current sliding window.
        """
        if not events:
            return [0.0, 0.0, 0.0, 0.0, 0.0]

        try:
            # 1. Sort timestamps in chronological order (in seconds)
            timestamps = []
            for ev in events:
                try:
                    if not isinstance(ev, dict):
                        continue
                    t_ms = ev.get("time")
                    if t_ms is not None:
                        timestamps.append(float(t_ms) / 1000.0)
                except (ValueError, TypeError):
                    continue
            
            timestamps.sort()

            # Calculate time deltas
            time_deltas = []
            for i in range(1, len(timestamps)):
                delta = timestamps[i] - timestamps[i - 1]
                time_deltas.append(delta)

            # Compute statistics for time deltas
            if time_deltas:
                n_deltas = len(time_deltas)
                mean_td = sum(time_deltas) / n_deltas
                
                # Standard deviation
                variance_td = sum((x - mean_td) ** 2 for x in time_deltas) / n_deltas
                std_td = math.sqrt(variance_td)
            else:
                mean_td = 0.0
                std_td = 0.0

            # 2. Compute rolling data volume (bytes)
            total_bytes = sum(self.get_event_bytes(ev) for ev in events)

            # 3. Compute request frequency (events per minute)
            # Find time range of current window
            if len(timestamps) > 1:
                window_span_sec = timestamps[-1] - timestamps[0]
                window_span_min = max(window_span_sec, 1.0) / 60.0
                frequency = len(events) / window_span_min
            else:
                frequency = 1.0  # Default frequency if only 1 event exists

            # 4. Destination port diversity
            unique_ports = set()
            for ev in events:
                port = self.get_dst_port(ev)
                if port > 0:
                    unique_ports.add(port)
            
            port_diversity = float(len(unique_ports))

            # Return feature vector
            return [
                float(mean_td),
                float(std_td),
                float(total_bytes),
                float(frequency),
                float(port_diversity)
            ]

        except Exception:
            # Crash-proof isolation: return default zero-vector if calculation errors
            return [0.0, 0.0, 0.0, 0.0, 0.0]
