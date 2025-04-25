# orchestrator.py

import glob
import yaml
import time
from threading import Thread
from winevt_ng import EventLog

from subscribers import handle_event, event_queue
from utils.xml_parser import parse_event_xml
from detectors.brute_force_detector import BruteForceDetector
from detectors.log_clearing_detector import LogClearingDetector
from detectors.rd_attack_detector import RDAttackDetector

# 1) Load & validate YAML configs
configs = []
for path in glob.glob("config/*.yaml"):
    with open(path, 'r', encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict) or 'name' not in cfg:
        print(f"⚠️  Skipping invalid config: {path}")
        continue
    configs.append(cfg)

# 2) Map config names → detector classes
DETECTOR_MAP = {
    "User Credential Brute Forcing": BruteForceDetector,
    "Clearing Security Logs":        LogClearingDetector,
    "Remote Desktop Attacks":        RDAttackDetector,
}

# 3) Instantiate detectors
detectors = []
def alert_callback(alert: dict):
    print("🚨 ALERT:", alert)

for cfg in configs:
    cls = DETECTOR_MAP.get(cfg['name'])
    if cls:
        detectors.append(cls(cfg, alert_callback))
    else:
        print(f"⚠️  No detector found for '{cfg['name']}'")

# 4) Build your XPath filter expression
all_eids = set()
for cfg in configs:
    for key in ('start_events','step_events','end_events'):
        all_eids.update(cfg.get(key, []))
filter_expr = " or ".join(f"EventID={eid}" for eid in sorted(all_eids))
xpath = f"Event[System[{filter_expr}]]"

# 5) Start worker threads to consume parsed XML
def worker():
    while True:
        xml_str = event_queue.get()
        try:
            evt_dict = parse_event_xml(xml_str)
            for det in detectors:
                det.on_event(evt_dict)
        except Exception as e:
            print("❌ Worker error:", e)
        finally:
            event_queue.task_done()

for _ in range(4):
    t = Thread(target=worker, daemon=True)
    t.start()

# 6) Subscribe to the Security log
print(f"🚀 Orchestrator listening with filter: {xpath}")
cb = EventLog.Subscribe("Security", xpath, handle_event)

# 7) Keep the main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("🛑 Shutting down orchestrator…")
