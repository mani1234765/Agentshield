from fastapi.security import HTTPAuthorizationCredentials
from authentication import authenticate
import os

def test_intern_token_cannot_become_admin():
    token = os.getenv("AGENTSHIELD_INTERN_TOKEN")
    assert token, "Intern token must be configured"

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )

    identity = authenticate(credentials)

    assert identity.user_id == "user_101"
    assert identity.role == "intern"
    assert identity.agent_id == "claude_agent_01"
