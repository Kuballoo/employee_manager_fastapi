from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated

from dependecies import db_dependency, user_dependency
from models import Users

router = APIRouter(
    prefix="/users",
    tags=["users"]
)


@router.get("/")
async def read_employees(db: db_dependency, user: user_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    user_entry = db.query(Users).filter(Users.uuid == user.get("user_uuid")).first()
    employees = user_entry.access_employees
    return employees
