
import json
from unittest.mock import patch

import audit


def test_security_event_is_logged(tmp_path):
    test_log = tmp_path / "security_audit.jsonl"

    with patch.object(audit, "LOG_FILE", test_log):
        audit.log_security_event(
            agent_id="finance_agent_02",
            event_type="prompt_injection",
            tool_name="read_document",
            outcome="blocked",
            details={
                "categories": ["instruction_override"],
                "risk_score": 35,
            },
        )

    records = [
        json.loads(line)
        for line in test_log.read_text().splitlines()
    ]

    assert len(records) == 1
    assert records[0]["event_type"] == "prompt_injection"
    assert records[0]["outcome"] == "blocked"
    assert records[0]["agent_id"] == "finance_agent_02"
