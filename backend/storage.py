import json
import os
import uuid
from typing import Dict, Any, Optional

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

# Ensure the reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)

def save_report(report_data: Dict[str, Any]) -> str:
    """
    Saves the JSON report to disk using a unique UUID to make it private.
    Returns the UUID string.
    """
    report_id = str(uuid.uuid4())
    filepath = os.path.join(REPORTS_DIR, f"{report_id}.json")
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    return report_id

def load_report(report_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a report by its UUID from the disk.
    Returns None if not found.
    """
    # Quick safety check to prevent traversal
    if ".." in report_id or "/" in report_id or "\\" in report_id:
        return None
        
    filepath = os.path.join(REPORTS_DIR, f"{report_id}.json")
    
    if not os.path.exists(filepath):
        return None
        
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)
