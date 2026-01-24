from contextlib import asynccontextmanager
from fastapi import FastAPI

from models import create_db_and_tables
from routers import employees



@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(employees.router)

@app.get("/")
async def root():
    return {"message": "Hello World!"}