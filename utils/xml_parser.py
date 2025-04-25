import xml.etree.ElementTree as ET

# ── Define which fields to pull from the XML
SYSTEM_FIELDS = ["EventID", "EventRecordID", "Channel", "Computer"]
EXECUTION_FIELDS = ["ProcessID", "ThreadID"]
EVENTDATA_FIELDS = [
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
    "TargetUserName", "TargetDomainName", "WorkstationName",
    "ProcessName", "IpAddress",
    "LogonType"           # ← add this line
]

def extract_system(root: ET.Element, ns: dict) -> dict:
    """
    Extracts relevant fields from the <System> section of the event XML.
    """
    system = {}
    for field in SYSTEM_FIELDS:
        el = root.find(f".//e:System/e:{field}", ns)
        if el is not None and el.text:
            system[field] = el.text

    time_created = root.find(".//e:System/e:TimeCreated", ns)
    if time_created is not None:
        system["TimeCreated"] = time_created.attrib.get("SystemTime")

    correlation = root.find(".//e:System/e:Correlation", ns)
    if correlation is not None:
        system["ActivityID"] = correlation.attrib.get("ActivityID")

    execution = root.find(".//e:System/e:Execution", ns)
    if execution is not None:
        for field in EXECUTION_FIELDS:
            val = execution.attrib.get(field)
            if val:
                system[field] = val

    return system

def extract_eventdata(root: ET.Element, ns: dict) -> dict:
    """
    Extracts relevant fields from the <EventData> section of the event XML.
    """
    eventdata = {}
    for data_el in root.findall(".//e:EventData/e:Data", ns):
        name = data_el.attrib.get("Name")
        if name in EVENTDATA_FIELDS:
            eventdata[name] = (data_el.text or "").strip()
    return eventdata

def parse_event_xml(xml_str: str) -> dict:
    """
    Parses the full event XML string and extracts structured event data.
    """
    root = ET.fromstring(xml_str)
    ns_uri = root.tag.split("}")[0].strip("{")
    ns = {"e": ns_uri}
    return {
        "Event": {
            "System":    extract_system(root, ns),
            "EventData": extract_eventdata(root, ns)
        }
    }
