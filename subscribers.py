# subscribers.py

from queue import Queue
from utils.xml_parser import parse_event_xml
from utils.json_utils import to_pretty_json

# Thread-safe queue used by orchestrator worker threads
event_queue = Queue()

def handle_event(action, pContext, event):
    """
    Callback from winevt_ng on every new event.
    Parses the raw XML into a dict, pretty-prints it as JSON, prints LogonType,
    and enqueues the XML for downstream detectors.
    """
    eid = getattr(event, "EventID", None)
    print(f"\n🔔 Event callback: EventID={eid}")

    raw_xml = getattr(event, "xml", None)
    if raw_xml is None:
        print("⚠️  No raw XML available on this event")
        return

    # 1) Parse XML → dict
    try:
        evt_dict = parse_event_xml(raw_xml)
    except Exception as e:
        print("❌ Error parsing XML:", e)
        return

    # 2) Pretty-print JSON
    print("----- Parsed Event JSON -----")
    print(to_pretty_json(evt_dict))

    # 3) Print LogonType if present
    lt = evt_dict["Event"]["EventData"].get("LogonType")
    if lt is not None:
        print(f"LogonType: {lt}")

    # 4) Enqueue raw XML for worker threads
    event_queue.put(raw_xml)
