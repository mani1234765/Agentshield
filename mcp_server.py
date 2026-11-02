import os
import sys
import httpx
from identity import create_security_context
from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier
from fastmcp.server.dependencies import get_access_token
from content_guard import inspect_document, protect_document
from audit import log_security_event
from document_store import update_document_file

MCP_CLIENT_TOKEN = os.getenv("AGENTSHIELD_MCP_CLIENT_TOKEN")
FINANCE_CLIENT_TOKEN = os.getenv("AGENTSHIELD_FINANCE_CLIENT_TOKEN")

CLIENT_POLICY_TOKENS = {
    "claude_agent_01": os.getenv("AGENTSHIELD_INTERN_TOKEN"),
    "finance_agent_02": os.getenv("AGENTSHIELD_MANAGER_TOKEN"),
}

if not MCP_CLIENT_TOKEN:
    raise RuntimeError(
        "AGENTSHIELD_MCP_CLIENT_TOKEN must be configured"
    )

if not FINANCE_CLIENT_TOKEN:
    raise RuntimeError(
        "AGENTSHIELD_MANAGER_CLIENT_TOKEN must be configured"
    )

if MCP_CLIENT_TOKEN == FINANCE_CLIENT_TOKEN:
    raise RuntimeError(
        "SECURITY ERROR: MCP client tokens must be unique"
    )
auth = StaticTokenVerifier(
    tokens={
        MCP_CLIENT_TOKEN: {
            "client_id": "claude_agent_01",
            "scopes": ["agentshield:tools"],
        },
        FINANCE_CLIENT_TOKEN: {
            "client_id": "finance_agent_02",
            "scopes": ["agentshield:tools"]
        },
    }
)
mcp = FastMCP("AgentShield Security Gateway",
            auth=auth,
            )

POLICY_URL = "http://127.0.0.1:8001/check-policy"

AGENTSHIELD_TOKEN = os.getenv("AGENTSHIELD_INTERN_TOKEN")

CURRENT_USER_ID = os.getenv(
    "AGENTSHIELD_USER_ID", "user_101"
)

CURRENT_AGENT_ID = os.getenv(
    "AGENTSHIED_AGENT_ID",
    "claude_agent_01"
)

def get_security_context():
    return create_security_context(
        user_id=CURRENT_USER_ID,
        agent_id=CURRENT_AGENT_ID
    )

async def check_policy(tool_name):
    try:
        access_token = get_access_token()
        if access_token is None:
            print(
                "BLOCKED: No authentication MCP client",
                file=sys.stderr,
            )
            return False

        client_id = access_token.client_id

        policy_token = CLIENT_POLICY_TOKENS.get(client_id)

        if not policy_token:
            print(
                "BLOCKED: No policy identity gor client",
                file=sys.stderr,
            )
            return False


        context = get_security_context()

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                POLICY_URL,
                headers={
                    "Authorization": f"Bearer {policy_token}"
                },
                json={
                    "tool_name": tool_name
                }
            )
            print(
                    "Policy HTTP status:",
                    response.status_code,
                    file=sys.stderr,
                    flush=True
                )
            print(
                    "Policy response:",
                    response.text,
                    file=sys.stderr,
                    flush=True
                )


            response.raise_for_status()
            decision = response.json()

            return decision.get("allowed") is True

    except (httpx.HTTPError, ValueError, AttributeError) as error:
        print(
        "AgentShield policy check failed:",
        type(error).__name__,
        str(error),
        file=sys.stderr,
        flush=True
    )
        return False

def get_document_content() -> str:
    return """
    Company Financial Report 2026

    Total revenue: $5 million.
    Net profit: $1.2 million.
    """


@mcp.tool()
async def read_document() -> str:
    """Read a simulated company document."""

    allowed = await check_policy("read_document")

    if not allowed:
        return "BLOCKED: AgentShield denied document access"

    document_content = get_document_content()


    try:
        result = protect_document(document_content)

    except Exception as error:
        print(
            "SECURITY ALERT: Content inspection failed:",
            type(error).__name__,
            file=sys.stderr,
            flush=True,
        )
        return "BLOCKED: Content inspection unavailable"

    if result == "BLOCKED: Potential prompt injection detected":
        try:
            access_token = get_access_token()

            if access_token is not None:
                log_security_event(
                    agent_id=access_token.client_id,
                    event_type="prompt_injection",
                    tool_name="read_document",
                    outcome="blocked",
                    details={
                        "reason": "Suspicious document content"
                    },
                )

        except Exception as error:
            print(
                "SECURITY ALERT: Audit logging failed:",
                type(error).__name__,
                file=sys.stderr,
                flush=True,
            )

    return result


@mcp.tool()
async def delete_document() -> str:
    """Delete a simulated company document."""

    allowed = await check_policy("delete_document")

    if not allowed:
        return "BLOCKED: AgentShield denied document deletion"

    print("Authorized deletion executed", flush=True)

    return "Document deleted successfully (simulation)"


@mcp.tool()
async def update_document(new_content: str) -> str:
    """Update a simulated company document."""

    allowed = await check_policy("update_document")

    if not allowed:
        return "BLOCKED: AgentShield denied document update"

    if not isinstance(new_content, str) or not new_content.strip():
        return "BLOCKED: Invalid document content"

    try:
        update_document_file(
            "update_test.txt",
            new_content,
        )


    except (OSError, ValueError) as error:
        print(
            "Authorized document update executed",
            type(error).__name__,
            file=sys.stderr,
            flush=True,
        )
        return "BLOCKED: Document update failed"

    return "Document updated successfully (simulation)"


@mcp.tool
async def who_am_i() -> str:
    """Show the authenticated MCP client identity"""

    access_token = get_access_token()

    if access_token is None:
        return "BLOCED: No authenticated client"

    return f"Authenticated client: {access_token.client_id}"

if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="127.0.0.1",
        port=8002,
        path="/mcp"
    )
