import json

from audit import log_decision

def test_audit_log_created(tmp_path, monkeypatch):
    log_file = tmp_path / "audit.jsonl"

    monkeypatch.setattr("audit.LOG_FILE", log_file)

    log_decision(
        user_id="user_101",
        agent_id="claude_agent_01",
        tool_name="delete_document",
        allowed=False,
        reason="Permission denied",
    )

    assert log_file.exists()

    records = log_file.read_text().splitlines()
    assert len(records) == 1

    event = json.loads(records[0])

    assert event["user_id"] == "user_101"
    assert event["agent_id"] == "claude_agent_01"
    assert event["tool_name"] == "delete_document"
    assert event["allowed"] is False
    assert event["reason"] == "Permission denied"
    assert "timestamp" in event
