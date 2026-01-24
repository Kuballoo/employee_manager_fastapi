from datetime import timedelta, datetime
from jose import jwt
from passlib.context import CryptContext
import os

from dotenv import load_dotenv
from models import Users


bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"

def create_access_token(login: str, expires_delta: timedelta = timedelta(minutes=15)):
    """
    Create a JWT access token with user credentials and expiration time.
    
    Args:
        login (str): The user's login/username to encode in the token.
        role (str): The user's role to encode in the token for authorization purposes.
        expires_delta (timedelta, optional): The token's validity period. 
            Defaults to 15 minutes if not specified.
    
    Returns:
        str: An encoded JWT token containing the user's login, role, and expiration time.
    
    Raises:
        Exception: May raise JWT encoding errors if SECRET_KEY or ALGORITHM are invalid.
    """
    expire_date = datetime.now() + expires_delta
    payload = {
        "sub": login,
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
