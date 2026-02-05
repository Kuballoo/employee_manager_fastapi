from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated
from uuid import UUID

from ..dependecies import db_dependency, user_dependency
from ..models import Permissions
from ..schemas import CreateUserRequest, CreateRoleRequest
from ..security import bcrypt_context
from ..rbac_logic import has_permission

router = APIRouter(
    prefix="/permissions",
    tags=["permissions"]
)

@router.get("/", status_code=status.HTTP_200_OK)
async def get_permissions(db: db_dependency, user: user_dependency):
    """
    Retrieve all permissions from the database.
    This endpoint fetches a list of all available permissions. Access is restricted
    to users who have the 'permission:read' permission.
    Args:
        db (db_dependency): Database session dependency for executing queries.
        user (user_dependency): Current authenticated user dependency containing user information.
    Returns:
        list[Permissions]: A list of all permission objects from the database.
    Raises:
        HTTPException: 403 Forbidden if the user does not have 'permission:read' permission.
    """
    
    if not has_permission(user.get("user_uuid"), ["permission:read"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    permissions = db.query(Permissions).order_by(Permissions.name).all()
    return permissions

@router.post("/", status_code=status.HTTP_201_CREATED)
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

@router.delete("/{permission_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(permission_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Delete a permission from the system.
    This function removes a permission record from the database after validating
    that the user has the required 'permission:delete' permission. All associations
    between the permission and roles are cleared before deletion.
    Args:
        permission_uuid (UUID): The name of the permission to delete.
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
    permission = db.query(Permissions).filter(Permissions.uuid == permission_uuid).first()
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    permission.roles.clear()
    db.delete(permission)
    db.commit()
