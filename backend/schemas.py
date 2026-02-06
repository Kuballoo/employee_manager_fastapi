from typing import Annotated
from datetime import date
from uuid import UUID
from pydantic import BaseModel, Field

class CreateEmployeeRequest(BaseModel):
    first_name: Annotated[str, Field(max_length=50)]
    last_name: Annotated[str, Field(max_length=50)]
    email: Annotated[str, Field(max_length=100)]
    phone: Annotated[str, Field(max_length=50)]
    country: Annotated[str, Field(max_length=25)]
    salary: Annotated[float, Field(gt=0)]
    employment_date: Annotated[date, Field()]

class CreateUserRequest(BaseModel):
    login: Annotated[str, Field(max_length=50)]
    password: Annotated[str, Field(min_length=8)]
    password_confirm: Annotated[str, Field(min_length=8)]

class CreateRoleRequest(BaseModel):
    name: Annotated[str, Field(max_length=50)]
    description: Annotated[str, Field(max_length=500)]

class AddDeleteRolesRequest(BaseModel):
    roles_uuids: Annotated[list[UUID], Field()]

class AddDeletePerrmisionsRequest(BaseModel):
    permissions_uuids: Annotated[list[UUID], Field()]