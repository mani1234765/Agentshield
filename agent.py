from guard import execute_tool

def read_file():
    return "Successfully read the file"

def update_file():
    return "Successfully updated the file"

def delete_file():
    return "Successfully deleted the file"

TOOLS = {
    "read":read_file,
    "update":update_file,
    "delete":delete_file
}

def run_agent(role, action, approved=False):
    tool_function = TOOLS.get(action)

    if tool_function is None:
        return {
            "executed" : False,
            "reason" : "Unknown Tool"
        }

    return execute_tool(
        role=role,
        action=action,
        approved=approved,
        tool_function=tool_function
    )
