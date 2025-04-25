# detectors/log_clearing_detector.py

import time
from detectors.base_detector import BaseDetector

class LogClearingDetector(BaseDetector):
    """
    Detects Security-log clearing events (1102/1100).
    """

    def __init__(self, config, alert_callback):
        super().__init__(config, alert_callback)
        self.trigger = set(config.get("start_events", []))
        self.key_field = config.get("key_fields", ["Computer"])[0]

    def on_event(self, event: dict):
        ev_id = int(event["Event"]["System"]["EventID"])
        if ev_id not in self.trigger:
            return

        computer = event["Event"]["System"].get(self.key_field)
        now      = time.time()

        self.alert_callback({
            "attack":  "Clearing Security Logs",
            "computer": computer,
            "event_id": ev_id,
            "timestamp": now
        })
