from dataclasses import dataclass

@dataclass(frozen=True)
class SecurityContext:
    user_id: str
    role: str
    agent_id: str
