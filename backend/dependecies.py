from fastapi import Depends
from sqlalchemy.orm import Session
from typing import Annotated

from .security import get_current_user_or_redirect
from .db import get_db

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user_or_redirect)]