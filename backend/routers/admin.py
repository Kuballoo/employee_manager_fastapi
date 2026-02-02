from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated

from ..dependecies import db_dependency, user_dependency
from ..models import Users, Employees, Roles
from ..schemas import CreateUserRequest, CreateRoleRequest
from ..security import bcrypt_context
from .. rbac import has_permission

router = APIRouter(
    prefix="/admin",
    tags=["admin"]
)

@router.post("/create_user", status_code=status.HTTP_201_CREATED)
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
    if not has_permission(user.get("user_uuid"), "users:create", db):
        raise HTTPException(status_code=403, detail="Forbidden")
    existing_user = db.query(Users).filter(Users.login == create_user_request.login).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User with this login already exists")
    
    if create_user_request.password != create_user_request.password_confirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    new_user = Users(login=create_user_request.login, hashed_password=bcrypt_context.hash(create_user_request.password))
    db.add(new_user)
    db.commit()


@router.post("/create_role", status_code=status.HTTP_201_CREATED)
async def create_role(create_role_request: CreateRoleRequest, db: db_dependency, user: user_dependency):
    if not has_permission(user.get("user_uuid"), "role:create", db):
        raise HTTPException(status_code=403, detail="Forbidden")
    existing_role = db.query(Roles).filter(Roles.name == create_role_request.name).first()
    if existing_role:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role with this name already exists")

    new_role = Roles(**create_role_request.model_dump())
    db.add(new_role)
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
