from typing import Annotated
from datetime import date

from pydantic import BaseModel, Field

class CreateEmployeeRequest(BaseModel):
    first_name: Annotated[str, Field(max_length=50)]
    last_name: Annotated[str, Field(max_length=50)]
    email: Annotated[str, Field(max_length=100)]
    phone: Annotated[str, Field(max_length=50)]
    country: Annotated[str, Field(max_length=25)]
    salary: Annotated[float, Field(gt=0)]
    employment_date: Annotated[date, Field()]
