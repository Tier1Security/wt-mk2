# parsers/xml/parser_4625.py
import xml.etree.ElementTree as ET
from utils.xml_parser import extract_system, extract_eventdata

def parse_4625(xml_str):
    """Parse a 4625 (failed logon) event into a dict."""
    root = ET.fromstring(xml_str)
    ns = {'e': root.tag.split('}')[0].strip('{')}
    return {
        'System': extract_system(root, ns),
        'EventData': extract_eventdata(root, ns)
    }