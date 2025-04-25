# parsers/json/serializer_4625.py
import json
from parsers.xml.parser_4625 import parse_4625

def serialize_4625(xml_str):
    """Convert a 4625 event XML to pretty JSON."""
    data = parse_4625(xml_str)
    return json.dumps(data, indent=2)