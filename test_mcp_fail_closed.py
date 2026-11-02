import pytest
import httpx
from unittest.mock import patch, MagicMock
from mcp_server import check_policy
import asyncio

@pytest.mark.asyncio
async def test_policy_service_unavailable():
    fake_token = MagicMock()
    fake_token.client_id = "claude_agent_02"

    with(
        patch("mcp_server.get_access_token", return_value=fake_token),
        patch.dict(
            "mcp_server.CLIENT_POLICY_TOKENS",
            {"claude_agent_02": "test_policy_token",}
        ),
    ):
        allowed = await check_policy("update_document")

    assert allowed is False


@pytest.mark.asyncio
async def test_policy_response_cannot_fake_boolean():
    fake_token = MagicMock()
    fake_token.client_id = "claude_agent_02"

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = '{"allowed": "true"}'
    fake_response.json.return_value = {"allowed": "true"}
    fake_response.raise_for_status.return_value = None

    with (
        patch("mcp_server.get_access_token", return_value=fake_token),
        patch.dict(
            "mcp_server.CLIENT_POLICY_TOKENS",
            {"claude_agent_02": "test_policy_token"},
        ),
        patch(
            "mcp_server.httpx.AsyncClient.post",
            return_value=fake_response,
        ),
    ):
        allowed = await check_policy("update_document")

    assert allowed is False


@pytest.mark.asyncio
async def test_invalid_policy_json_is_denied():
    fake_token = MagicMock()
    fake_token.client_id = "claude_agent_02"

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = "THIS IS NOT JSON"
    fake_response.raise_for_status.return_value = None
    fake_response.json.side_effect = ValueError("Invalid JSON")

    with (
        patch("mcp_server.get_access_token", return_value=fake_token),
        patch.dict(
            "mcp_server.CLIENT_POLICY_TOKENS",
            {"claude_agent_02": "test_policy_token"},
        ),
        patch(
            "mcp_server.httpx.AsyncClient.post",
            return_value=fake_response,
        ),
    ):
        allowed = await check_policy("update_document")

    assert allowed is False
