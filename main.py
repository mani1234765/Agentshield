from fastapi import FastAPI
from permission import check_permission
from pydantic import BaseModel

app = FastAPI(title="AgentShield Security API")

class AuthorizationRequest(BaseModel):
    role: str
    action: str
    approved: bool

@app.get("/health")
def health_check():
    return {"status": "healthy", "message": "AgentShield Security API is running.","service":"AgentShield Security API"}

@app.post("/authorize")
def authorize(request: AuthorizationRequest):
    allowed = check_permission(request.role, request.action, request.approved)
    return {"allowed": allowed,
            "reason": "Permission granted" if allowed else "Permission denied"}
