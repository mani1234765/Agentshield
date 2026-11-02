import os
import pytest
from fastapi.testclient import TestClient
from policy_service import app

client = TestClient(app)

@pytest.mark.parametrize(
    "token_env,tool_name,expected",

    [
         ("AGENTSHIELD_INTERN_TOKEN", "read_document", True),
        ("AGENTSHIELD_INTERN_TOKEN", "update_document", False),
        ("AGENTSHIELD_INTERN_TOKEN", "delete_document", False),

        ("AGENTSHIELD_MANAGER_TOKEN", "read_document", True),
        ("AGENTSHIELD_MANAGER_TOKEN", "update_document", True),
        ("AGENTSHIELD_MANAGER_TOKEN", "delete_document", False),
    ],
)

def test_agent_permisiion(token_env,tool_name,expected):
    token = os.environ[token_env]

    response = client.post(
        "/check-policy",
        headers={"Authorization": f"Bearer {token}"},
        json={"tool_name": tool_name},
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is expected

def test_invalid_token_is_rejected():
    response = client.post(
        "/check-policy",
        headers={
        "Authorization": "Bearer invalid_test_token"
        },
        json={
            "tool_name": "read_document"
        },
    )

    assert response.status_code == 401


def test_intern_cannot_impersonate_manager():
    token = os.environ["AGENTSHIELD_INTERN_TOKEN"]

    response = client.post(
        "/check-policy",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "tool_name": "update_document",
            "role": "manager",
            "user_id": "user_102",
            "agent_id": "claude_agent_02"
        },
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_unknown_tool_is_denied():
    token = os.environ["AGENTSHIELD_MANAGER_TOKEN"]

    response = client.post(
        "/check-policy",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "tool_name": "transfer_money"
        },
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
