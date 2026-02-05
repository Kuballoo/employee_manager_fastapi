from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated
from uuid import UUID

from ..dependecies import db_dependency, user_dependency
from ..models import Users, Employees, Roles, Permissions, RolesPermissions, UsersRoles
from ..schemas import CreateUserRequest, CreateRoleRequest, AddPermissionsRolesRequest, AddRolesUserRequest
from ..security import bcrypt_context
from ..rbac_logic import has_permission

router = APIRouter(
    prefix="/rbac",
    tags=["rbac"]
)



@router.get("/users/{user_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def get_user_data(user_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Retrieve the roles associated with a specific user.
    Args:
        user_uuid (UUID): The UUID of the user whose roles are to be retrieved.
        db (db_dependency): Database session dependency for querying user data.
        user (user_dependency): The current authenticated user making the request.
    Returns:
        dict: A dictionary containing:
            - login (str): The user's login name.
            - uuid (UUID): The user's unique identifier.
            - roles (list[str]): A list of role names assigned to the user.
    Raises:
        HTTPException: 
            - status_code 403 (Forbidden): If the current user lacks "user:read" permission.
            - status_code 404 (Not Found): If the specified user does not exist in the database.
    """

    if not has_permission(user.get("user_uuid"), ["user:read"], db, True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    
    user_query = db.query(Users).filter(Users.uuid == user_uuid).first()
    if not user_query:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user_roles = [role.name for role in user_query.roles]
    user_data = {
        "uuid": user_query.uuid,
        "login": user_query.login,
        "roles": user_roles
    }
    return user_data

@router.get("/roles", status_code=status.HTTP_200_OK)
async def get_roles(db: db_dependency, user: user_dependency):
    """
    Retrieve all roles from the database.
    This endpoint fetches all available roles with permission verification.
    Only users with 'role:read' permission are allowed to access this endpoint.
    Args:
        db (db_dependency): Database session dependency for querying the database.
        user (user_dependency): Current user dependency containing user information including user_uuid.
    Returns:
        list[Roles]: A list of all Role objects from the database.
    Raises:
        HTTPException: With status code 403 (Forbidden) if the user lacks 'role:read' permission.
    """

    if not has_permission(user.get("user_uuid"), ["role:read"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    roles = db.query(Roles).all()
    return roles

@router.get("/roles/{role_uuid}", status_code=status.HTTP_200_OK)
async def get_role_data(role_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Retrieve detailed information about a specific role including its permissions.
    Args:
        role_uuid (UUID): The unique identifier of the role to retrieve.
        db (db_dependency): Database session dependency for querying role data.
        user (user_dependency): Current authenticated user information.
    Returns:
        dict: A dictionary containing:
            - uuid (UUID): The role's unique identifier.
            - description (str): The role's description.
            - permissions (list): A sorted list of permission names assigned to the role.
    Raises:
        HTTPException: 403 Forbidden if the user lacks "role:read" or "permission:read" permissions.
        HTTPException: 404 Not Found if the role does not exist.
    """
    if not has_permission(user.get("user_uuid"), ["role:read", "permission:read"], db, True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    role = db.query(Roles).filter(Roles.uuid == role_uuid).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    permissions = [permission.name for permission in role.permissions]
    permissions.sort()
    return {
        "uuid": role.uuid,
        "description": role.description,
        "permissions": permissions
    }

@router.delete("/permissions/{permission_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(permission_name: str, db: db_dependency, user: user_dependency):
    """
    Delete a permission from the system.
    This function removes a permission record from the database after validating
    that the user has the required 'permission:delete' permission. All associations
    between the permission and roles are cleared before deletion.
    Args:
        permission_name (str): The name of the permission to delete.
        db (db_dependency): Database session dependency for querying and performing operations.
        user (user_dependency): The current user's information containing user_uuid and permissions.
    Raises:
        HTTPException: With status 403 FORBIDDEN if the user lacks 'permission:delete' permission.
        HTTPException: With status 404 NOT_FOUND if the permission does not exist in the database.
    Returns:
        None
    """

    if not has_permission(user.get("user_uuid"), ["permission:delete"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    permission = db.query(Permissions).filter(Permissions.name == permission_name).first()
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    permission.roles.clear()
    db.delete(permission)
    db.commit()

@router.delete("/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_name: str, db: db_dependency, user: user_dependency):
    """
    Delete a role from the database.
    This function removes a role and all its associated permissions and user assignments.
    Only users with the 'role:delete' permission can perform this operation.
    Args:
        role_name (str): The name of the role to delete.
        db (db_dependency): Database session dependency for executing queries.
        user (user_dependency): Current user dependency containing user information and UUID.
    Raises:
        HTTPException: If the user lacks 'role:delete' permission (status 403).
        HTTPException: If the role does not exist (status 404).
    Returns:
        None
    """
    
    if not has_permission(user.get("user_uuid"), ["role:delete"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    role = db.query(Roles).filter(Roles.name == role_name).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    role.permissions.clear()
    role.users.clear()
    db.delete(role)
    db.commit()

@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest, db: db_dependency, user: user_dependency):
    """
    Create a new user with validation.
    This function creates a new user in the database after performing several validation checks:
    - Ensures the login is unique (not already in use)
    - Verifies that the password and password confirmation match
    - Hashes the password using bcrypt before storing
    Args:
        create_user_request (CreateUserRequest): Request object containing:
            - login (str): The unique username for the new user
            - password (str): The user's password
            - password_confirm (str): Password confirmation for validation
            - role (str): The role to assign to the new user
        db (db_dependency): Database session dependency for performing queries and commits
        user (user_dependency): User dependency for authentication
    Raises:
        HTTPException: Raised with status code 400 if:
            - A user with the provided login already exists
            - The password and password_confirm fields do not match
    Returns:
        None (implicitly returns the committed database transaction)
    
    """
    if not has_permission(user.get("user_uuid"), ["user:create"], db):
        raise HTTPException(status_code=403, detail="Forbidden")
    existing_user = db.query(Users).filter(Users.login == create_user_request.login).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User with this login already exists")
    
    if create_user_request.password != create_user_request.password_confirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    new_user = Users(login=create_user_request.login, hashed_password=bcrypt_context.hash(create_user_request.password))
    db.add(new_user)
    db.commit()

@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(create_role_request: CreateRoleRequest, db: db_dependency, user: user_dependency):
    """
    Create a new role in the system.
    This endpoint creates a new role with the provided details. The user must have
    the 'role:create' permission to perform this operation.
    Args:
        create_role_request (CreateRoleRequest): The request object containing role details.
        db (db_dependency): Database session dependency for querying and persisting data.
        user (user_dependency): Current authenticated user dependency containing user information.
    Raises:
        HTTPException: If the user lacks 'role:create' permission (status_code=403).
        HTTPException: If a role with the same name already exists (status_code=400).
    Returns:
        Roles: The newly created role object.
    """
    if not has_permission(user.get("user_uuid"), ["role:create"], db):
        raise HTTPException(status_code=403, detail="Forbidden")
    existing_role = db.query(Roles).filter(Roles.name == create_role_request.name).first()
    if existing_role:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role with this name already exists")

    new_role = Roles(**create_role_request.model_dump())
    db.add(new_role)
    db.commit()

@router.post("/permissions", status_code=status.HTTP_201_CREATED)
async def create_permission(permission_name: str, db: db_dependency, user: user_dependency):
    """
    Create a new permission in the system.
    Args:
        permission_name (str): The name of the permission to be created.
        db (db_dependency): Database session dependency for performing database operations.
        user (user_dependency): Current user dependency containing user information and authentication details.
    Raises:
        HTTPException: Raised with status code 403 if the user does not have "permission:create" permission.
    Returns:
        The newly created permission object.
    """
    if not has_permission(user.get("user_uuid"), ["permission:create"], db):
        raise HTTPException(status_code=403, detail="Forbidden")
    existing_permission = db.query(Permissions).filter(Permissions.name == permission_name).first()
    if existing_permission:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Permission with this name already exists")

    new_permission = Permissions(name=permission_name)
    db.add(new_permission)
    db.commit()

@router.post("/user-roles", status_code=status.HTTP_201_CREATED)
async def add_roles_to_users(add_roles_user: AddRolesUserRequest, db: db_dependency, user: user_dependency):
    """
    Adds one or more roles to a user.
    This function assigns the specified roles to a user, after validating that:
    1. The requesting user has permission to manage users and/or roles
    2. The user does not already have any of the roles being assigned
    Args:
        add_roles_user (AddRolesUserRequest): Request object containing:
            - user_uuid (str): The UUID of the user to assign roles to
            - roles_uuids (List[str]): List of role UUIDs to assign to the user
        db (db_dependency): Database session dependency for query execution
        user (user_dependency): Current authenticated user dependency
    Raises:
        HTTPException: 403 Forbidden if the current user lacks "user:manage" or "role:manage" permissions
        HTTPException: 400 Bad Request if the user already has any of the roles being assigned
    Returns:
        None
    """
    
    if not has_permission(user.get("user_uuid"), ["user:manage", "role:manage"], db, True):
        raise HTTPException(status_code=403, detail="Forbidden")
    user_uuid = add_roles_user.user_uuid
    roles_uuids = add_roles_user.roles_uuids

    for role_uuid in roles_uuids:
        exists = db.query(UsersRoles).filter(
            UsersRoles.uuid_role == role_uuid,
            UsersRoles.uuid_user == user_uuid
        ).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                                detail=f"This user have this role uuid -> {role_uuid}")
    
    for role_uuid in roles_uuids:
        db.add(UsersRoles(uuid_user=user_uuid, uuid_role=role_uuid))
    db.commit()

@router.post("/roles-permissions", status_code=status.HTTP_201_CREATED)
async def add_permissions_to_roles(add_permissions_roles_request: AddPermissionsRolesRequest, db: db_dependency, user: user_dependency):
    """
    Connect multiple permissions to multiple roles.
    This function establishes associations between roles and permissions in the database.
    It performs permission validation, checks for existing connections, and creates new
    role-permission relationships for all specified combinations.
    Args:
        add_permissions_roles_request (AddPermissionsRolesRequest): Request object containing
            lists of role UUIDs and permission UUIDs to be connected.
        db (db_dependency): Database session dependency for performing queries and commits.
        user (user_dependency): Current user dependency containing user information and UUID.
    Raises:
        HTTPException: 403 Forbidden if the user lacks required permissions (role:manage or permission:manage).
        HTTPException: 400 Bad Request if a connection already exists between any specified role-permission pair.
    Returns:
        None: Commits the changes to the database on successful execution.
    """
    
    if not has_permission(user.get("user_uuid"), ["role:manage", "permission:manage"], db, True):
        raise HTTPException(status_code=403, detail="Forbidden")
    roles_uuids = add_permissions_roles_request.roles_uuids
    permissions_uuids = add_permissions_roles_request.permissions_uuids
    for role_uuid in roles_uuids:
        for permission_uuid in permissions_uuids:
            exists = db.query(RolesPermissions).filter(
                RolesPermissions.uuid_permission == permission_uuid,
                RolesPermissions.uuid_role == role_uuid
            ).first()
            if exists:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Connection already exists: role {role_uuid} - permission {permission_uuid}"
                )
            
    for role_uuid in roles_uuids:
        for permission_uuid in permissions_uuids:
            db.add(RolesPermissions(uuid_role=role_uuid, uuid_permission=permission_uuid))

    db.commit()
        


"""
@router.post("/give_access")
async def give_access(give_access_request: GiveAccessRequest, db: db_dependency, user: user_dependency):
    
    Grant database access to a user for specified employees.
    This endpoint allows an admin user to grant access to one or more employees
    for another user. It validates that the requester is an admin, checks if access
    already exists, verifies employee existence, and creates new access entries.
    Args:
        give_access_request (GiveAccessRequest): Request object containing:
            - user_id: UUID of the user to grant access to
            - employees_ids: List of employee UUIDs to grant access for
            - access_level: The level of access to grant
        db (db_dependency): Database session dependency
        user (user_dependency): Current authenticated user dependency
    Returns:
        dict: A dictionary mapping employee IDs (as strings) to status messages:
            - "Access granted": Access was successfully created
            - "Access already exists": User already has access to this employee
            - "Employee not found": The specified employee does not exist
    Raises:
        HTTPException: 
            - 401 status: If user is None or does not have admin role
            - 500 status: If database commit fails during access creation
    Note:
        All access entries are committed in a single transaction. If any error
        occurs during commit, the entire transaction is rolled back.

    if user is None or user.get("user_role") != "admin":
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    give_access_successful = dict()
    for employee_id in give_access_request.employees_ids:
        existing = db.query(UsersEmployeeAccess).filter_by(
            uuid_user=give_access_request.user_id,
            uuid_employee=employee_id
        ).first()

        if existing:
            give_access_successful[str(employee_id)] = "Access already exists"
            continue

        employee_entry = db.query(Employees).filter(Employees.uuid == employee_id).first()
        if not employee_entry:
            give_access_successful[str(employee_id)] = "Employee not found"
            continue
        new_access_entry = UsersEmployeeAccess(
            uuid_user=give_access_request.user_id,
            uuid_employee=employee_id,
            access_level=give_access_request.access_level
        )

        db.add(new_access_entry)
        give_access_successful[str(employee_id)] = "Access granted"
    
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to grant access")
    
    return give_access_successful
"""
