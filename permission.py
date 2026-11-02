def check_permission(role,action,approved):
    if role == "intern" and action == "read":
        return True
    elif role == "manager" and action in ("read","update"):
        return True
    elif role == "admin" and action in ("read","update"):
        return True
    elif role == "admin" and action == "delete" and approved is True:
        return True
    else:
        return False
