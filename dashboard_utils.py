import json
from pathlib import Path

AUDIT_FILE = Path(__file__).resolve().parent / "audit.jsonl"


def load_events():
    if not AUDIT_FILE.exists():
        return []

    events = []

    with AUDIT_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except json.JSONDecodeError:
                continue

    return events


def normalize_event(event):
    if "allowed" in event:
        if event["allowed"] is True:
            status = "Allowed"
        elif event["allowed"] is False:
            status = "Denied"
        else:
            status = "Unknown"

    elif "event_type" in event:
        status = str(event.get("outcome", "Unknown")).title()

    else:
        status = "Unknown"

    return {
        "timestamp": event.get("timestamp", ""),
        "agent_id": event.get("agent_id", "Unknown"),
        "tool_name": event.get("tool_name", "Unknown"),
        "event_type": event.get("event_type", "authorization"),
        "status": status,
        "reason": event.get("reason", ""),
    }
