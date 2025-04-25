# detectors/brute_force_detector.py

import time
from detectors.base_detector import BaseDetector

class BruteForceDetector(BaseDetector):
    """
    Detects user credential brute-force attempts by counting repeated 4625 failures
    and ending on lockout (4740) or success (4624).
    """

    def __init__(self, config, alert_callback):
        # Pass both config and callback up to BaseDetector
        super().__init__(config, alert_callback)

        self.start_events = set(config.get("start_events", []))
        self.end_events   = set(config.get("end_events",   []))
        self.threshold    = config.get("threshold", 5)
        self.window       = config.get("window_minutes", 5) * 60
        self.state        = {}  # key=(username,ip) → {"count":…, "start":…}

    def on_event(self, event: dict):
        ev_id    = int(event["Event"]["System"]["EventID"])
        data     = event["Event"]["EventData"]
        username = data.get("SubjectUserName")
        ip       = data.get("IpAddress")

        if not username or username == "-" or not ip or ip == "-":
            return

        key    = (username, ip)
        now    = time.time()
        record = self.state.get(key)

        # failure events
        if ev_id in self.start_events:
            if record is None or (now - record["start"]) > self.window:
                record = {"count": 0, "start": now}
            record["count"] += 1
            self.state[key] = record

            if record["count"] >= self.threshold:
                self.alert_callback({
                    "attack":   "User Credential Brute Forcing",
                    "username": username,
                    "ip":       ip,
                    "attempts": record["count"],
                    "window_start": record["start"],
                    "window_end":   now
                })

        # end events
        elif ev_id in self.end_events and record:
            self.alert_callback({
                "attack":   "User Credential Brute Forcing",
                "username": username,
                "ip":       ip,
                "attempts": record["count"],
                "window_start": record["start"],
                "window_end":   now,
                "end_event":   ev_id
            })
            del self.state[key]

        # expire old
        for k,v in list(self.state.items()):
            if now - v["start"] > self.window:
                del self.state[k]
