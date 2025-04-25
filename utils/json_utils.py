# utils/json_utils.py

import json

def to_pretty_json(data: dict, indent: int = 2) -> str:
    """
    Convert a Python dict (or list) into a pretty-printed JSON string.
    
    Args:
        data: The Python object to serialize.
        indent: Number of spaces to use for indentation.
        
    Returns:
        A formatted JSON string.
    """
    return json.dumps(data, indent=indent, ensure_ascii=False, default=str)

def dump_json(data: dict, file_path: str, indent: int = 2) -> None:
    """
    Serialize a Python object to a JSON file.
    
    Args:
        data: The Python object to serialize.
        file_path: Destination path for the JSON output.
        indent: Number of spaces for indentation.
    """
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False, default=str)

def load_json(file_path: str):
    """
    Load a JSON file into a Python object.
    
    Args:
        file_path: Path to the input JSON file.
        
    Returns:
        The deserialized Python object (dict or list).
    """
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)
