# parsers/json/serializer_4624.py
import json
from parsers.xml.parser_4624 import parse_4624

def serialize_4624(xml_str):
    """Convert a 4624 event XML to pretty JSON."""
    data = parse_4624(xml_str)
    return json.dumps(data, indent=2)