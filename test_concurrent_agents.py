
import asyncio
import os
from pathlib import Path
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
import pytest

MCP_URL = "http://127.0.0.1:8002/mcp"


async def run_agent(name, token, new_content):
    transport = StreamableHttpTransport(
        url=MCP_URL,
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    async with Client(transport) as client:
        identity = await client.call_tool("who_am_i", {})
        update = await client.call_tool(
            "update_document",
            {"new_content": new_content},
            )

        assert not identity.is_error
        assert not update.is_error

        return (
            name,
            identity.content[0].text,
            update.content[0].text,
        )



async def main():
    intern_token = os.environ["AGENTSHIELD_MCP_CLIENT_TOKEN"]
    finance_token = os.environ["AGENTSHIELD_FINANCE_CLIENT_TOKEN"]

    test_file = (
        Path(__file__).resolve().parent
        / "protected_documents"
        / "update_test.txt"
    )

    test_file.write_text(
        "Original test document",
        encoding="utf-8",
    )


    results = await asyncio.gather(
        run_agent("Intern", intern_token, "UNAUTHORIZED INTERN UPDATE",),
        run_agent("Finance", finance_token, "AUTHORIZED FINANCE UPDATE",),
    )

    expected = {
        "Intern": {
            "identity": "claude_agent_01",
            "response": "BLOCKED: AgentShield denied document update",
        },
        "Finance": {
            "identity": "finance_agent_02",
            "response": "Document updated successfully (simulation)",
        },
    }

    for name, identity, response in results:
        assert expected[name]["identity"] in identity
        assert response == expected[name]["response"]

        print(f"PASS: {name} authentication and authorization")

    # Verify actual file content after both requests.
    final_content = test_file.read_text(encoding="utf-8")

    assert final_content == "AUTHORIZED FINANCE UPDATE"

    print("PASS: Protected file contains only the finance update")
    print("All concurrent real-file checks passed!")

@pytest.mark.asyncio
async def test_concurrent_mcp_agents():
    await main()

if __name__ == "__main__":
    asyncio.run(main())
