# parsers/xml/parser_4825.py
import xml.etree.ElementTree as ET
from utils.xml_parser import extract_system, extract_eventdata

def parse_4825(xml_str):
    """Parse a 4825 (RDP blocked by policy) event into a dict."""
    root = ET.fromstring(xml_str)
    ns = {'e': root.tag.split('}')[0].strip('{')}
    return {
        'System': extract_system(root, ns),
        'EventData': extract_eventdata(root, ns)
    }