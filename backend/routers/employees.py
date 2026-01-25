from fastapi import APIRouter, HTTPException, status

from models import Employees
from dependecies import db_dependency
from schemas import CreateEmployeeRequest

router = APIRouter(
    prefix="/Employees",
    tags=["employees"]
)

@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(employee_data: CreateEmployeeRequest, db: db_dependency):
    """
    Creates a new user in the database using the provided employee data.
    Args:
        employee_data (CreateEmployeeRequest): The data required to create a new employee.
        db (Session): The database session dependency.
    Returns:
        None
    """
    
    new_user = Employees(**employee_data.model_dump())
    db.add(new_user)
    db.commit()