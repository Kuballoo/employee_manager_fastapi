from sqlalchemy import Column, String, Uuid, Float, Date, create_engine
from sqlalchemy.orm import DeclarativeBase
from uuid import uuid4
from datetime import date

from dotenv import load_dotenv
from os import getenv

# Load environment variables from .env file
load_dotenv()

# Create SQLAlchemy engine for PostgreSQL database
engine = create_engine(f"postgresql://{getenv('DB_USER')}:{getenv('DB_PASSWORD')}@127.0.0.1:5432/{getenv('DB_NAME')}")


class Base(DeclarativeBase):
    pass

class Users(Base):
    """
        Model for Users table in database.
        
        Stores personal, contact, and employment-related information.
    """
    __tablename__ = "users"

    uuid = Column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    phone = Column(String(50), nullable=False, unique=True)
    country = Column(String(25))
    salary = Column(Float, nullable=False)
    employment_date = Column(Date, nullable=False, default=date.today)


def create_db_and_tables():
    Base.metadata.create_all(engine)