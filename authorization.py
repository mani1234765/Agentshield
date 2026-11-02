from dataclasses import dataclass
from permission import check_permission

@dataclass(frozen=True)
class TrustedIdentity:
    user_id: str
    agent_id: str
    role: str

@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    approved_by: str | None = None

def authorize_action(
        identity: TrustedIdentity,
        action: str,
        approval: ApprovalDecision,
) -> bool:
    return check_permission(
        role=identity.role,
        action=action,
        approved=approval.approved,
    )
