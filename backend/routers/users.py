from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated

from dependecies import db_dependency, user_dependency
from models import Users
from schemas import CreateUserRequest
from security import bcrypt_context

router = APIRouter(
    prefix="/users",
    tags=["users"]
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
    if user is None or user.get("user_role") != "admin":
        raise HTTPException(status_code=401, detail="Authentication Failed")
    existing_user = db.query(Users).filter(Users.login == create_user_request.login).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User with this login already exists")
    
    if create_user_request.password != create_user_request.password_confirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    new_user = Users(login=create_user_request.login, hashed_password=bcrypt_context.hash(create_user_request.password), role=create_user_request.role)
    db.add(new_user)
    db.commit()
