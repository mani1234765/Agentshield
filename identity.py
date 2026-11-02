from security_context import SecurityContext

USERS = {
    "user_101": "intern",
    "user_102": "manager",
    "user_103": "admin"
}

def create_security_context(user_id, agent_id):
    role = USERS.get(user_id)

    if role is None:
        raise ValueError("Unknown user")

    return SecurityContext(
        user_id=user_id,
        role=role,
        agent_id=agent_id
        )
