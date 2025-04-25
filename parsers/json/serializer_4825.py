# parsers/json/serializer_4825.py
import json
from parsers.xml.parser_4825 import parse_4825

def serialize_4825(xml_str):
    """Convert a 4825 event XML to pretty JSON."""
    data = parse_4825(xml_str)
    return json.dumps(data, indent=2)