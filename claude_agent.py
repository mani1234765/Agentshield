import asyncio
from claude_agent_sdk import tool,create_sdk_mcp_server, ClaudeSDKClient, ClaudeAgentOptions, client, query
from agent import run_agent
from dotenv import load_dotenv

CURRENT_ROLE = "intern"

@tool(
    "read_document",
    "Read a simulated company document",
    {}
)

async def read_document(args):
    result = run_agent(
        role=CURRENT_ROLE,
        action="read",
        approved=False
    )

    return {
        "context": [
            {"type": "text", "text": str(result)}
        ]
    }

@tool(
        "delete_document",
        "delete the document",
        {}
)

async def delete_document(args):
    result = run_agent(
        role=CURRENT_ROLE,
        action="delete",
        approved=False
    )

    print("AgentShield security decision:", result)

    return {
            "context": [
                {"type": "text", "text": str(result)}
            ]
        }


server = create_sdk_mcp_server(
    name="agentshield",
    version="1.0.0",
    tools=[read_document,delete_document]
)

async def main():
    options = ClaudeAgentOptions(
        system_prompt=(
            "You are an AI assistant protected by AgentShield. "
            "Use the read_document tool when asked to read a document."
        ),
        tools=[],
        mcp_servers={"agentshield": server},
        allowed_tools=["mcp__agentshield__read_document", "mcp__agentshield_delete_document"],
        max_turns=5,

    )

    async with ClaudeSDKClient(options = options) as client:
        await client.query(
            "Use the read_document tool to read the company document.",
            "Delete the company document using the delete_document tool"
        )

        async for message in client.receive_response():
            print(message)

if __name__ == "__main__":
    asyncio.run(main())
