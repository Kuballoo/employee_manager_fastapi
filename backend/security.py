from fastapi import Depends, HTTPException, status, Cookie, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import timedelta, datetime, timezone
from jose import jwt, JWTError
from typing import Annotated
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

from .models import Users


bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"

def create_access_token(uuid: str, expires_delta: timedelta = timedelta(minutes=15)):
    """
    Create a JWT access token with user credentials and expiration time.
    
    Args:
        uuid (str): The user's unique identifier to encode in the token.
        role (str): The user's role for authorization purposes.
        expires_delta (timedelta, optional): Token's validity period (default 15 minutes).
    
    Returns:
        str: Encoded JWT token containing the user's UUID, role, and expiration time.
    """

    expire_date = datetime.now() + expires_delta
    payload = {
        "sub": str(uuid),
        "exp": expire_date
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
def authenticate_user(login: str, password: str, db):
    """
    Authenticate a user by verifying their login credentials.

    Args:
        login (str): The user's login username.
        password (str): The user's plain text password.
        db: Database session object for querying user records.

    Returns:
        Users | bool: The user object if authentication is successful, False otherwise.

    Raises:
        None
    """
    user = db.query(Users).filter(Users.login == login).first()
    if not user: 
        return False

    return user if bcrypt_context.verify(password, user.hashed_password) else False

def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    """
    Validate and extract user information from a JWT token.
    This function decodes a JWT token and extracts the user UUID and role claims.
    It verifies that both required claims are present in the token payload.
    Args:
        token (Annotated[str, Depends(oauth2_bearer)]): The JWT token obtained from the OAuth2 bearer scheme.
    Returns:
        dict: A dictionary containing:
            - user_uuid (str): The unique identifier of the authenticated user.
            - user_role (str): The role assigned to the authenticated user.
    Raises:
        HTTPException: With status code 401 (HTTP_401_UNAUTHORIZED) if:
            - The token is invalid or cannot be decoded (JWTError).
            - The required claims ('sub' for user_uuid or 'role') are missing from the token payload.
    """
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_uuid: str = payload.get("sub")

        if user_uuid is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")
        return {"user_uuid": user_uuid}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")

def get_current_user_or_redirect(request: Request):
    """
    Dependency function to extract current user from JWT token or redirect to login.

    This utility function checks for a valid JWT access token in cookies and
    extracts the user_uuid from the payload. Returns user data on success or
    redirects to login page on authentication failure/missing token.

    Args:
        request (Request): The incoming HTTP request containing cookies.

    Returns:
        dict or RedirectResponse:
            - dict: On success, returns {"user_uuid": str} extracted from JWT payload.
            - RedirectResponse: On failure (no token or invalid/expired token),
                redirects to "/auth/login" (302) and deletes invalid cookie.

    Raises:
        JWTError: If token decoding fails (invalid signature, expired, etc.).
    """
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/login", status_code=302)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"user_uuid": payload["sub"]}
    except JWTError:
        response = RedirectResponse("/auth/login", status_code=302)
        response.delete_cookie("access_token")
        return response

#token_test = create_access_token("7f760de9-9a9d-402e-8cb9-1b7e1c7516a8", "admin")
#print(token_test)
#get_current_user(token_test)
