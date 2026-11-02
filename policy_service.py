from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from audit import log_decision
from permission import check_permission
from authentication import authenticate
from authorization import TrustedIdentity

app = FastAPI(title="AgentShield Central Policy Service")

security = HTTPBearer(auto_error=False)

TOOL_POLICIES = {
    "read_document": "read",
    "update_document": "update",
    "delete_document": "delete"
}


class PolicyRequest(BaseModel):
    tool_name: str

def get_current_identity(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> TrustedIdentity:
    return authenticate(credentials)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/check-policy")
def check_policy(
    request: PolicyRequest,
    identity: TrustedIdentity = Depends(get_current_identity),
):
    action = TOOL_POLICIES.get(request.tool_name)

    if action is None:

        allowed = False
        reason = "Unknown user or tool"


    else:

        allowed = check_permission(
            role=identity.role,
            action=action,
            approved=False,
        )

        reason = "Permission Granted" if allowed else "permission denided"

    log_decision(
        user_id=identity.user_id,
        agent_id=identity.agent_id,
        tool_name=request.tool_name,
        allowed=allowed,
        reason=reason,
    )
    return {
        "allowed": allowed,
        "reason": reason,
    }
