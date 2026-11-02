from fastapi.testclient import TestClient
from main import app
import pytest

client = TestClient(app)

def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_manager_cannot_delete():
    response = client.post("/authorize",

        json={
            "role": "manager",
            "action": "delete",
            "approved": True
        }
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False

@pytest.mark.parametrize(
    "role,action,approved,expected",
    [
            ("intern", "read", False, True),
            ("intern", "delete", True, False),
            ("manager", "delete", True, False),
            ("manager", "update", False, True),
            ("manager", "read", False, True),
            ("admin", "delete", True, True),
            ("admin", "delete", False, False)
    ]
)

def test_authorization_roles(role, action, approved, expected):
    response = client.post("/authorize",
                           json={
                               "role":role,
                               "action":action,
                               "approved":approved
                           }
                        )
    assert response.status_code == 200
    assert response.json()["allowed"] is expected
