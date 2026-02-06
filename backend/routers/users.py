from fastapi import APIRouter, HTTPException, Depends, status
from typing import Optional, Annotated
from uuid import UUID

from ..dependecies import db_dependency, user_dependency
from ..models import Users, UsersRoles
from ..schemas import CreateUserRequest, AddDeleteRolesRequest
from ..security import bcrypt_context
from ..rbac_logic import has_permission

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.get("/me", status_code=status.HTTP_200_OK)
async def get_my_data(db: db_dependency, user: user_dependency):
    """
    Retrieve the authenticated user's data.
    This endpoint returns the current user's profile information including their UUID,
    login, and assigned roles.
    Args:
        db (db_dependency): Database session dependency for querying user records.
        user (user_dependency): Authenticated user dependency containing user_uuid.
    Returns:
        dict: A dictionary containing:
            - uuid (str): The unique identifier of the user.
            - login (str): The login username of the user.
            - roles (list): A list of role names assigned to the user.
    Raises:
        HTTPException: 401 Unauthorized if user is not authenticated.
        HTTPException: 404 Not Found if the user does not exist in the database.
    """
    
    if user is None:
       raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user_data = db.query(Users).filter(Users.uuid == user.get("user_uuid")).first()
    if not user_data:
       raise HTTPException(status_code=404, detail="User not found")
    return {
        "uuid": user_data.uuid,
        "login": user_data.login,
        "roles": [role.name for role in user_data.roles]
    }

@router.get("/", status_code=status.HTTP_200_OK)
async def get_users(db: db_dependency, user: user_dependency,user_uuid: Optional[UUID] = None):
    """
    Retrieve user information from the database.
    Fetches either a single user by UUID or all users, depending on whether
    user_uuid parameter is provided. Requires 'user:read' permission.
    Args:
        db (db_dependency): Database session dependency for querying user data.
        user (user_dependency): Current authenticated user dependency containing user_uuid.
        user_uuid (Optional[UUID]): UUID of a specific user to retrieve. If not provided,
            all users are returned. Defaults to None.
    Returns:
        List[Dict[str, Any]]: List of dictionaries containing user information with keys:
            - uuid (UUID): Unique identifier of the user.
            - login (str): Login name of the user.
            - roles (List[str]): List of role names assigned to the user.
    Raises:
        HTTPException: Status code 403 if the current user lacks 'user:read' permission.
        HTTPException: Status code 404 if the specified user_uuid is not found in the database.
    """

    if not has_permission(user.get("user_uuid"), ["user:read"], db, True):
        raise HTTPException(status_code=403, detail="Forbidden")

    if user_uuid:
        single_user = db.query(Users).filter(Users.uuid == user_uuid).first()
        if not single_user:
            raise HTTPException(status_code=404, detail="User not found")
        users = [single_user]
    else:
        users = db.query(Users).all()

    return [
        {
            "uuid": u.uuid,
            "login": u.login,
            "roles": [role.name for role in u.roles]
        }
        for u in users
    ]

@router.post("/", status_code=status.HTTP_201_CREATED)
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

@router.post("/{user_uuid}/roles", status_code=status.HTTP_201_CREATED)
async def add_roles(user_uuid: UUID, request: AddDeleteRolesRequest, db: db_dependency, user: user_dependency):
    """
    Add one or more roles to a user.
    This endpoint allows authorized users to assign roles to a specific user.
    The requesting user must have either 'user:manage' or 'role:manage' permissions.
    Args:
        user_uuid (UUID): The UUID of the user to whom roles will be added.
        request (AddDeleteRolesRequest): Request object containing a list of role UUIDs to be added.
        db (db_dependency): Database session dependency for querying and committing changes.
        user (user_dependency): Current authenticated user dependency containing user information.
    Raises:
        HTTPException: 403 Forbidden if the requesting user lacks 'user:manage' or 'role:manage' permissions.
        HTTPException: 400 Bad Request if the user already has any of the roles being added.
    Returns:
        None: Commits the changes to the database if all validations pass.
    """

    if not has_permission(user.get("user_uuid"), ["user:manage"], db):
        raise HTTPException(status_code=403, detail="Forbidden")
    roles_uuids = request.roles_uuids

    for role_uuid in roles_uuids:
        exists = db.query(UsersRoles).filter(
            UsersRoles.uuid_role == role_uuid,
            UsersRoles.uuid_user == user_uuid
        ).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"This user already has role {role_uuid}")
    
    for role_uuid in roles_uuids:
        db.add(UsersRoles(uuid_user=user_uuid, uuid_role=role_uuid))
    db.commit()

@router.delete("/{user_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Delete a user from the database.
    Args:
        user_uuid (UUID): The UUID of the user to be deleted.
        db (db_dependency): Database session dependency for querying and modifying data.
        user (user_dependency): The current authenticated user making the deletion request.
    Raises:
        HTTPException: 
            - status_code 403 (Forbidden) if the current user lacks the 'user:delete' permission.
            - status_code 404 (Not Found) if no user with the specified UUID exists in the database.
    Returns:
        None
    Side Effects:
        - Clears all roles associated with the user before deletion.
        - Commits the deletion to the database.
    """

    if not has_permission(user.get("user_uuid"), ["user:delete"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    user_to_delete = db.query(Users).filter(Users.uuid == user_uuid).first()
    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with {user_uuid} not found")
    user_to_delete.roles.clear()
    db.delete(user_to_delete)
    db.commit()
