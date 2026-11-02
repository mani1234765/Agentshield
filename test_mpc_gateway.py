from unittest.mock import patch
import httpx
import pytest
import asyncio

from mcp_server import check_policy, read_document

@pytest.mark.asyncio
async def test_policy_server_offline():

    with patch("mcp_server.httpx.AsyncClient.post") as mock_post:
        mock_post.side_effect = httpx.ConnectError(
            "Policy server is offline"
        )

        allowed = await check_policy("read_document")

        assert allowed is False
