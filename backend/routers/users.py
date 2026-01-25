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
    """
    Retrieve all employees accessible to the authenticated user.
    Args:
        db (db_dependency): Database session dependency for querying the database.
        user (user_dependency): Current authenticated user dependency containing user information.
    Returns:
        dict: A dictionary containing a "data" key with a list of employees accessible to the user.
    Raises:
        HTTPException: 401 Unauthorized if the user is not authenticated (user is None).
    """

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    user_entry = db.query(Users).filter(Users.uuid == user.get("user_uuid")).first()
    employees = user_entry.access_employees
    return {"data": employees}
