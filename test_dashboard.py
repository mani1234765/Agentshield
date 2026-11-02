import json

import dashboard_utils as dashboard


def test_missing_audit_file(tmp_path, monkeypatch):
    missing_file = tmp_path / "missing.jsonl"

    monkeypatch.setattr(
        dashboard,
        "AUDIT_FILE",
        missing_file,
    )

    assert dashboard.load_events() == []


def test_invalid_json_is_skipped(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.jsonl"

    audit_file.write_text(
        json.dumps({
            "agent_id": "test_agent",
            "allowed": False,
        }) + "\n"
        + "{invalid json}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        dashboard,
        "AUDIT_FILE",
        audit_file,
    )

    events = dashboard.load_events()

    assert len(events) == 1
    assert events[0]["agent_id"] == "test_agent"
    assert events[0]["allowed"] is False


def test_normalize_denied_event():
    event = {
        "agent_id": "test_agent",
        "tool_name": "delete_document",
        "allowed": False,
    }

    normalized = dashboard.normalize_event(event)

    assert normalized["status"] == "Denied"
    assert normalized["event_type"] == "authorization"
