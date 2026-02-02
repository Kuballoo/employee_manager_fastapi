from .models import Users
from .models import Users
def has_permission(user_uuid: str, perm_name: str, db) -> bool:
    """
    Check if a user has a specific permission.
    Args:
        user (Users): The user object to check permissions for.
        perm_name (str): The name of the permission to verify.
    Returns:
        bool: True if the user has the specified permission through any of their roles,
              False otherwise.
    """
    user = db.query(Users).filter(Users.uuid == user_uuid).first()
    if not user:
        return False
    # !DELETE THIS SHIT AFTER FILLING DB
    if user.login == "admin":
        return True
    return any(perm_name == perm.name for role in user.roles for perm in role.permissions)
    # for role in user.roles:
    #     for perm in role.permissions:
    #         if perm.name == perm_name:
    #             return True
    
    # return False