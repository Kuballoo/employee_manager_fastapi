from .models import Users
from .models import Users
def has_permission(user_uuid: str, perm_list: list[str], db, all_roles_required: bool = False) -> bool:
    """
    Check if a user has the specified permissions.
    
    Args:
        user_uuid (str): UUID of the user.
        perm_list (list[str]): List of permission names to check.
        db: Database session.
        all_roles_required (bool): 
            - True → user must have all listed permissions
            - False → user having any permission is enough

    Returns:
        bool: True if the condition is satisfied, False otherwise.
    """
    user = db.query(Users).filter(Users.uuid == user_uuid).first()
    if not user:
        return False

    # !DELETE AFTER DB IS FILLED
    # if user.login == "admin":
    #    return True

    # initialize flags
    perms_flags = {perm_name: False for perm_name in perm_list}

    for role in user.roles:
        for perm in role.permissions:
            if perm.name in perms_flags:
                perms_flags[perm.name] = True

    if all_roles_required:
        return all(perms_flags.values())
    else:
        return any(perms_flags.values())


    #return any(perm_name == perm.name for role in user.roles for perm in role.permissions)
    # for role in user.roles:
    #     for perm in role.permissions:
    #         if perm.name == perm_name:
    #             return True
    
    # return False