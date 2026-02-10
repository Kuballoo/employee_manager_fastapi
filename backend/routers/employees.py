from fastapi import APIRouter, HTTPException, status, UploadFile, File
from fastapi.requests import Request
from typing import Annotated
from pandas import read_csv, read_excel
from uuid import UUID

from ..models import Employees
from ..dependecies import db_dependency, user_dependency
from ..schemas import CreateEmployeeRequest
from ..rbac_logic import has_permission
from ..templates import templates

router = APIRouter(
    prefix="/employees",
    tags=["employees"]
)


### API ENDPOINTS ###
@router.get("/", status_code=status.HTTP_200_OK)
async def read_employees(request: Request, db: db_dependency, user: user_dependency):
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
    if not has_permission(user.get("user_uuid"), ["employee:read"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication Failed")
    
    employees = db.query(Employees).all()
    return templates.TemplateResponse(
        "employees-panel.html",
        {"request": request, "employees": employees}
    )

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_employee(employee_data: CreateEmployeeRequest, db: db_dependency, user: user_dependency):
    """
    Create a new employee record in the database.
    Args:
        employee_data (CreateEmployeeRequest): The employee data to be created, validated through the request model.
        db (db_dependency): Database session dependency for executing database operations.
        user (user_dependency): Current authenticated user dependency containing user information and permissions.
    Returns:
        The newly created employee object.
    Raises:
        HTTPException: If the user lacks 'employee:create' permission (status 403).
        HTTPException: If user authentication fails or user is None (status 401).
    """
    
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    if not has_permission(user.get("user_uuid"), ["employee:create"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    
    new_employee = Employees(**employee_data.model_dump())
    db.add(new_employee)
    db.commit()

@router.post("/import", status_code=status.HTTP_201_CREATED)
async def upload_employees_file(file: Annotated[UploadFile, File()], db: db_dependency, user: user_dependency):
    """
    Upload and process employees from a CSV or Excel file.
    This async endpoint handles file uploads containing employee data and stores them in the database.
    Only authenticated users can access this endpoint.
    Args:
        file (UploadFile): The uploaded file in CSV (.csv) or Excel (.xlsx, .xls) format containing employee data.
        db (db_dependency): Database session dependency for performing CRUD operations.
        user (user_dependency): Current authenticated user dependency.
    Raises:
        HTTPException: 
            - Status 401 if user is not authenticated.
            - Status 400 if the file format is not supported (not CSV or Excel) or if employee data insertion fails.
    Returns:
        None (implicit success response on completion)
    Notes:
        - Supports .csv, .xlsx, and .xls file formats.
        - Data is validated against the CreateEmployeeRequest model before insertion.
        - On any insertion error, the transaction is rolled back to maintain data integrity.
        - A final commit is executed after successful processing.
    """
    if not has_permission(user.get("user_uuid"), ["employee:create"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
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
        
@router.delete("/{employee_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_employee(employee_uuid: UUID, db: db_dependency, user: user_dependency):
    """
    Delete an employee from the database.
    This endpoint removes an employee record identified by their UUID. It first verifies
    that the requesting user has the necessary 'employee:delete' permission. If the user
    lacks permission, a 403 Forbidden error is raised. If the employee does not exist,
    a 404 Not Found error is raised.
    Args:
        employee_uuid (UUID): The unique identifier of the employee to delete.
        db (db_dependency): Database session dependency for querying and modifying data.
        user (user_dependency): The current authenticated user with their permissions.
    Raises:
        HTTPException: 403 Forbidden if the user lacks 'employee:delete' permission.
        HTTPException: 404 Not Found if the employee with the given UUID does not exist.
    Returns:
        None
    """
    
    if not has_permission(user.get("user_uuid"), ["employee:delete"], db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    employee = db.query(Employees).filter(Employees.uuid == employee_uuid).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")
    db.delete(employee)
    db.commit()