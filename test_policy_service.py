import os
from fastapi.testclient import TestClient
from policy_service import app

client = TestClient(app)

def auth_headers(token_name):
    token = os.environ.get(token_name)
    return {"Authorization": f"Bearer {token}"}

def test_intern_can_read():
    response = client.post(
        "/check-policy",
        headers=auth_headers("AGENTSHIELD_INTERN_TOKEN"),
        json={
            "user_id": "user_101",
            "tool_name": "read_document",
            "approved": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True

def test_intern_cannot_delete():
    response = client.post(
        "/check-policy",
        headers=auth_headers("AGENTSHIELD_INTERN_TOKEN"),
        json={
            "user_id": "user_101",
            "tool_name": "delete_document",
            "approved": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False

def test_admin_cannot_delete_without_approval():
    response = client.post(
        "/check-policy",
        headers=auth_headers("AGENTSHIELD_ADMIN_TOKEN"),
        json={
            "user_id": "user_103",
            "tool_name": "delete_document",
            "approved": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
