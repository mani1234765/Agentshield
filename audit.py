import json
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("audit.jsonl")

def log_decision(user_id, agent_id,tool_name, allowed, reason):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "allowed": allowed,
        "reason": reason
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def log_security_event(
    agent_id: str,
    event_type: str,
    tool_name: str,
    outcome: str,
    details: dict | None = None,
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "event_type": event_type,
        "tool_name": tool_name,
        "outcome": outcome,
        "details": details or {},
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
