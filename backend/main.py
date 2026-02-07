from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from .templates import templates
from .models import create_db_and_tables
from .routers import employees, auth, users, roles, permissions

BASE_DIR = Path(__file__).resolve().parents[1]
print(BASE_DIR)
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "frontend" / "static"),
    name="static"
)

app.include_router(employees.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(permissions.router)

@app.get("/")
async def root():
    return {"message": "Hello World!"}