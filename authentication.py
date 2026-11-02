import os
import secrets
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from authorization import TrustedIdentity

INTERN_TOKEN = os.getenv("AGENTSHIELD_INTERN_TOKEN", "")
ADMIN_TOKEN = os.getenv("AGENTSHIELD_ADMIN_TOKEN", "")

if INTERN_TOKEN and ADMIN_TOKEN:
    if secrets.compare_digest(INTERN_TOKEN, ADMIN_TOKEN):
        raise RuntimeError(
            "SECURITY ERROR: Intern and admin tokens must be different"
        )

TOKEN_IDENTITIES ={
    token: TrustedIdentity(
        user_id=user_id,
        agent_id=agent_id,
        role=role,
    )

    for token, user_id, agent_id, role in [
        (
            os.getenv("AGENTSHIELD_INTERN_TOKEN", ""),
            "user_101",
            "claude_agent_01",
            "intern",
        ),
        (
            os.getenv("AGENTSHIELD_MANAGER_TOKEN", ""),
            "user_102",
            "claude_agent_02",
            "manager",
        ),
        (
            os.getenv("AGENTSHIELD_ADMIN_TOKEN", ""),
            "user_103",
            "claude_agent_01",
            "admin",
        ),

    ]
    if token
}

tokens = [
    os.getenv("AGENTSHIELD_INTERN_TOKEN", ""),
    os.getenv("AGENTSHIELD_MANAGER_TOKEN", ""),
    os.getenv("AGENTSHIELD_ADMIN_TOKEN", ""),
]

configured_tokens = [token for token in tokens if token]

if len(configured_tokens) != len(set(configured_tokens)):
    raise RuntimeError(
        "SECURITY ERROR: Policy identity tokens must be unique"
    )

def authenticate(
        credentials:HTTPAuthorizationCredentials | None,
) -> TrustedIdentity:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid credentials",
        )

    for token, identity in TOKEN_IDENTITIES.items():
        if secrets.compare_digest(credentials.credentials, token):
            return identity

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
    )
