from identity import create_security_context
import pytest


def test_known_user():
    context = create_security_context(
        "user_101",
        "claude_agent_01"
    )

    assert context.role == "intern"
    assert context.user_id == "user_101"


def test_unknown_user():
    with pytest.raises(ValueError):
        create_security_context(
            "unknown_user",
            "claude_agent_01"
        )
