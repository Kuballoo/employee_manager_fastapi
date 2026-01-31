from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated

from ..dependecies import db_dependency
from ..security import authenticate_user, create_access_token

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.post("/token")
async def login_for_access_token(login_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    """
    Handle user login and generate access token.
    Authenticates a user based on their username and password credentials,
    and returns a JWT access token for subsequent authenticated requests.
    Args:
        login_data (OAuth2PasswordRequestForm): The login credentials containing
            username and password.
        db (db_dependency): Database session dependency for user lookup.
    Returns:
        dict: A dictionary containing:
            - access_token (str): JWT token for authentication
            - token_type (str): Token type, always "bearer"
    Raises:
        HTTPException: 400 status code if authentication fails (invalid
            username or password).
    """

    user = authenticate_user(login_data.username, login_data.password, db)
    if not user:
        raise HTTPException(status_code=400, detail="Authentication failed")

    token = create_access_token(user.uuid, user.role)

    return {"access_token": token, "token_type": "bearer"}
