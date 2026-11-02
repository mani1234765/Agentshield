from permission import check_permission

def execute_tool(role,action,approved,tool_function):
    allowed = check_permission(role, action, approved)

    if not allowed:
        return {
            "executed": False,
            "reason": "Blocked By AgentShield"
        }

    result = tool_function()

    return {
        "executed": True,
        "result": result
    }
