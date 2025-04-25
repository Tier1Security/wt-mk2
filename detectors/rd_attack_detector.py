# detectors/rd_attack_detector.py

import time
from datetime import datetime
from detectors.base_detector import BaseDetector
from reporters.rd_attack_reporter import generate_rd_attack_report

class RDAttackDetector(BaseDetector):
    """
    Detects Remote Desktop brute-force attempts by collecting EventID 4625 failures per IP.
    When the configured threshold is reached within the rolling window, it generates a PDF report.
    """

    FAILURE_CODE = 4625

    def __init__(self, config, alert_callback):
        """
        Args:
            config (dict): YAML- loaded configuration containing:
                - threshold (int): number of failures before reporting
                - window_minutes (int): time window in minutes
            alert_callback (callable): called with an alert dict after PDF creation
        """
        super().__init__(config, alert_callback)
        self.threshold = int(config.get("threshold", 5))
        # convert minutes to seconds
        self.window    = int(config.get("window_minutes", 5)) * 60
        # state[ip] = {"events": [event_dicts], "start": timestamp}
        self.state     = {}

    def on_event(self, event: dict):
        # Only consider 4625 failed logon events
        ev_id = int(event["Event"]["System"]["EventID"])
        if ev_id != self.FAILURE_CODE:
            return

        ip = event["Event"]["EventData"].get("IpAddress")
        if not ip or ip == "-":
            return

        now = time.time()
        record = self.state.get(ip)

        # Initialize or reset the window
        if record is None or (now - record["start"] > self.window):
            record = {"events": [], "start": now}

        record["events"].append(event)
        self.state[ip] = record

        # If threshold reached, generate report and clear state
        if len(record["events"]) >= self.threshold:
            self._generate_report(ip, record["events"])
            del self.state[ip]

        # Expire any stale windows
        self._expire_windows(now)

    def _expire_windows(self, current_time: float):
        """Remove any IP records older than the rolling window."""
        for ip, rec in list(self.state.items()):
            if (current_time - rec["start"]) > self.window:
                del self.state[ip]

    def _generate_report(self, ip: str, events: list) -> str:
        """
        Build summary, timeline, and raw events, then call the PDF generator.

        Returns:
            The filename of the generated PDF.
        """
        # 1) Summary
        summary = {
            "Attack": "Remote Desktop Brute-Force",
            "Time":    datetime.utcnow().isoformat(),
            "System":  events[0]["Event"]["System"].get("Computer"),
            "IP":      ip
        }

        # 2) Timeline
        timeline = [
            {
                "Sequence": idx,
                "EventID":  ev["Event"]["System"].get("EventID"),
                "Timestamp": ev["Event"]["System"].get("TimeCreated")
            }
            for idx, ev in enumerate(events, start=1)
        ]

        # 3) Raw events
        raw_events = events

        # 4) Create PDF
        filename = generate_rd_attack_report(
            title="Remote Desktop Brute-Force Detected",
            summary=summary,
            timeline=timeline,
            raw_events=raw_events
        )

        # 5) Emit alert
        alert = {
            "attack": "Remote Desktop Brute-Force",
            "ip":      ip,
            "count":   len(events),
            "report":  filename
        }
        self.alert_callback(alert)

        return filename
