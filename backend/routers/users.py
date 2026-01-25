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


@router.get("/")
async def read_employees(db: db_dependency, user: user_dependency):
    pass