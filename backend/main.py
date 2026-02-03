from contextlib import asynccontextmanager
from fastapi import FastAPI

from .models import create_db_and_tables
from .routers import employees, auth, users, rbac


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(employees.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(rbac.router)

@app.get("/")
async def root():
    return {"message": "Hello World!"}