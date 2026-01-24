from fastapi import APIRouter, HTTPException, status

from models import Users
from dependecies import db_dependency
from schemas import CreateUserRequest

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(user_data: CreateUserRequest, db: db_dependency):
    new_user = Users(**user_data.model_dump())
    db.add(new_user)
    db.commit()