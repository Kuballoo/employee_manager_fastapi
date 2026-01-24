from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated

from dependecies import db_dependency
from models import Users
from security import authenticate_user, create_access_token

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.post("/token")
async def login_for_access_token(login_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(login_data.username, login_data.password, db)
    if not user:
        raise HTTPException(status_code=400, detail="Authentication failed")
    
    token = create_access_token(user.login)

    return token
