# sliding_window.py
# Memory-efficient and high-performance sliding window cache for behavioral analytics

import collections

class SlidingWindowCache:
    """
    Maintains a rolling time-series cache of OCSF events grouped by source asset.
    Uses collections.deque to achieve O(1) appends and prunes, preventing memory leaks
    and latency bottlenecks.
    """
    def __init__(self, window_duration_seconds=21600):
        # 6 hours = 21600 seconds
        self.window_duration = window_duration_seconds
        # Maps asset_id -> deque of events
        self.cache = collections.defaultdict(collections.deque)

    def add_event(self, asset_id, event):
        """
        Adds a new event to the asset's sliding window cache and prunes expired logs.
        Strictly crash-proof against invalid structures.
        """
        try:
            if not isinstance(event, dict):
                return
                
            event_time_ms = event.get("time")
            if event_time_ms is None:
                return
                
            current_time_sec = float(event_time_ms) / 1000.0
            deque_ref = self.cache[asset_id]
            
            # Append the new event to the right
            deque_ref.append((current_time_sec, event))
            
            # Prune expired events from the left (oldest first)
            cutoff_time = current_time_sec - self.window_duration
            self._prune_old_events(deque_ref, cutoff_time)
        except (ValueError, TypeError, AttributeError):
            # Crash-proof isolation: discard malformed event silently
            pass

    def get_events(self, asset_id, current_time_sec):
        """
        Prunes and returns all active events in the window for the specified asset.
        """
        try:
            deque_ref = self.cache[asset_id]
            cutoff_time = current_time_sec - self.window_duration
            self._prune_old_events(deque_ref, cutoff_time)
            return [item[1] for item in deque_ref]
        except Exception:
            return []

    def _prune_old_events(self, deque_ref, cutoff_time):
        """
        Helper method to pop expired items from the left of the deque in O(1) time.
        """
        try:
            # While the oldest event in the deque is older than the cutoff, pop it
            while deque_ref and deque_ref[0][0] < cutoff_time:
                deque_ref.popleft()
        except Exception:
            # Crash-proof isolation
            pass

    def clear(self):
        """
        Clears the cache.
        """
        self.cache.clear()
