from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated
from uuid import UUID

from ..dependecies import db_dependency, user_dependency
from ..models import Users, Employees, Roles, Permissions, RolesPermissions
from ..schemas import CreateRoleRequest, AddDeletePerrmisionsRequest
from ..security import bcrypt_context
from ..rbac_logic import has_permission

router = APIRouter(
    prefix="/roles",
    tags=["roles"]
)


@router.get("/", status_code=status.HTTP_200_OK)
async def get_data(db: db_dependency, user: user_dependency):
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

@router.get("/{role_uuid}", status_code=status.HTTP_200_OK)
async def get_detailed_data(role_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Retrieve detailed information about a specific role.
    This endpoint fetches comprehensive data for a role including its UUID, description,
    associated permissions, and assigned users. Access is restricted to users with 
    'role:read' and 'permission:read' permissions.
    Args:
        role_uuid (UUID): The unique identifier of the role to retrieve.
        db (db_dependency): Database session dependency for querying role data.
        user (user_dependency): Current authenticated user dependency for permission validation.
    Returns:
        dict: A dictionary containing:
            - uuid (UUID): The role's unique identifier.
            - description (str): The role's description.
            - permissions (list[str]): Sorted list of permission names assigned to the role.
            - users (list[str]): List of user logins assigned to the role.
    Raises:
        HTTPException: 
            - 403 Forbidden: If the user lacks required 'role:read' and 'permission:read' permissions.
            - 404 Not Found: If the role with the specified UUID does not exist.
    """

    if not has_permission(user.get("user_uuid"), ["role:read", "permission:read"], db, True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    role = db.query(Roles).filter(Roles.uuid == role_uuid).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    permissions = [permission.name for permission in role.permissions]
    users = [user.login for user in role.users]
    permissions.sort()
    return {
        "uuid": role.uuid,
        "name": role.name,
        "description": role.description,
        "permissions": permissions,
        "users": users
    }

@router.post("/", status_code=status.HTTP_201_CREATED)
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

@router.delete("/{role_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Delete a role from the database.
    This function removes a role and all its associated permissions and user assignments.
    Only users with the 'role:delete' permission can perform this operation.
    Args:
        role_name (UUID): The uuid of the role to delete.
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
    role = db.query(Roles).filter(Roles.uuid == role_uuid).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    role.permissions.clear()
    role.users.clear()
    db.delete(role)
    db.commit()

@router.post("/{role_uuid}/permissions", status_code=status.HTTP_201_CREATED)
async def add_permissions(role_uuid: UUID, request: AddDeletePerrmisionsRequest, db: db_dependency, user: user_dependency):
    """
    Add permissions to a role.
    Args:
        role_uuid (UUID): The UUID of the role to which permissions will be added.
        request (AddDeletePerrmisionsRequest): Request object containing a list of permission UUIDs to add.
        db (db_dependency): Database session dependency.
        user (user_dependency): Current user dependency containing user information.
    Raises:
        HTTPException: 403 Forbidden if the user lacks 'role:manage' or 'permission:manage' permissions.
        HTTPException: 400 Bad Request if a connection between the role and any permission already exists.
    Returns:
        None
    Description:
        This endpoint verifies that the current user has the necessary permissions to manage roles and permissions.
        It checks if any of the requested role-permission connections already exist in the database.
        If all validations pass, it adds all permissions to the role and commits the changes to the database.
    """
    
    if not has_permission(user.get("user_uuid"), ["role:manage", "permission:manage"], db, True):
        raise HTTPException(status_code=403, detail="Forbidden")
    role = db.query(Roles).filter(Roles.uuid == role_uuid).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    permissions_uuids = request.permissions_uuids
    for permission_uuid in permissions_uuids:
        exists = db.query(RolesPermissions).filter(
            RolesPermissions.uuid_permission == permission_uuid,
            RolesPermissions.uuid_role == role_uuid
        ).first()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Connection already exists with permission {permission_uuid}"
            )
            
    for permission_uuid in permissions_uuids:
        db.add(RolesPermissions(uuid_role=role_uuid, uuid_permission=permission_uuid))

    db.commit()

@router.delete("/{role_uuid}/permissions", status_code=status.HTTP_204_NO_CONTENT)
async def remove_permissions(role_uuid: UUID, request: AddDeletePerrmisionsRequest, db: db_dependency, user: user_dependency):
    """
    Delete multiple permissions from a role.
    This endpoint removes the specified permissions from a given role. The user must have
    either 'role:manage' or 'permission:manage' permissions to perform this action.
    Args:
        role_uuid (UUID): The unique identifier of the role from which permissions will be deleted.
        request (AddDeletePerrmisionsRequest): Request object containing the list of permission UUIDs to delete.
        db (db_dependency): Database session dependency for executing queries.
        user (user_dependency): Current user dependency containing user information and permissions.
    Raises:
        HTTPException: 403 Forbidden if the user lacks required permissions ('role:manage' or 'permission:manage').
        HTTPException: 404 Not Found if the specified role does not exist.
        HTTPException: 400 Bad Request if any of the specified permissions are not connected to the role.
    Returns:
        None: Commits the deletion to the database on successful completion.
    """
    
    if not has_permission(user.get("user_uuid"), ["role:manage", "permission:manage"], db, True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    role = db.query(Roles).filter(Roles.uuid == role_uuid).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    permissions_uuids = request.permissions_uuids
    for permission_uuid in permissions_uuids:
        exists = db.query(RolesPermissions).filter(
            RolesPermissions.uuid_permission == permission_uuid,
            RolesPermissions.uuid_role == role_uuid
        ).first()
        if not exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Connection not exists with permission {permission_uuid}"
            )
        db.delete(exists)
    
    db.commit()
    