from fastapi import APIRouter, HTTPException, status, UploadFile, File
from typing import Annotated
from pandas import read_csv, read_excel

from models import Employees
from dependecies import db_dependency
from schemas import CreateEmployeeRequest
from dependecies import user_dependency

router = APIRouter(
    prefix="/employees",
    tags=["employees"]
)

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(employee_data: CreateEmployeeRequest, db: db_dependency, user: user_dependency):
    """
    Creates a new user in the database using the provided employee data.
    Args:
        employee_data (CreateEmployeeRequest): The data required to create a new employee.
        db (Session): The database session dependency.
    Returns:
        None
    """
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    new_user = Employees(**employee_data.model_dump())
    db.add(new_user)
    db.commit()

@router.post("/add_employees")
async def upload_employees_file(file: Annotated[UploadFile, File()], db: db_dependency, user: user_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    if file.filename.endswith(".csv"):
        df = read_csv(file.file)
    elif file.filename.endswith((".xlsx", ".xls")):
        df = read_excel(file.file)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported file type")
    
    try:
        for row in df.itertuples(index=False):
            employee_data = CreateEmployeeRequest(**row._asdict())
            db.add(Employees(**employee_data.model_dump()))
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(400, "Failed to insert employees")
        
    db.commit()