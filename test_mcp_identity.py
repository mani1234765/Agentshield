import pytest
import asyncio
from unittest.mock import patch
from mcp_server import get_security_context, check_policy

def test_known_user_context():
    context = get_security_context()

    assert context.user_id == "user_101"
    assert context.role == "intern"
    assert context.agent_id == "claude_agent_01"

def test_unknown_user_rejected():
    with patch("mcp_server.CURRENT_USER_ID", "unknown_user"):
        with pytest.raises(ValueError):
            get_security_context()

@pytest.mark.asyncio
async def test_unknown_user_blocked_by_gateway():
    with patch("mcp_server.CURRENT_USER_ID", "unknown_user"):
        allowed = await check_policy("read_document")

    assert allowed is False
