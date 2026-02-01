from sqlalchemy import Column, String, Uuid, Float, Date, create_engine, ForeignKey
from sqlalchemy.orm import DeclarativeBase, relationship
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

class Employees(Base):
    """
    Model for Employees table in database.
    
    Stores personal, contact, and employment-related information.
    """
    __tablename__ = "employees"

    uuid = Column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    phone = Column(String(50), nullable=False, unique=True)
    country = Column(String(25))
    salary = Column(Float, nullable=False)
    employment_date = Column(Date, nullable=False, default=date.today)
    access_users = relationship(
        "Users",
        secondary="user_employee_access",
        back_populates="access_employees"
    )


class Users(Base):
    """
    Model for the Employees table in the database.

    Stores personal, contact, and employment-related information.
    """
    __tablename__ = "users"

    uuid = Column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    login = Column(String(50), nullable=False, unique=True)
    role = Column(String(50), nullable=False)
    hashed_password = Column(String(), nullable=False)
    access_employees = relationship(
        "Employees",
        secondary="user_employee_access",
        back_populates="access_users"
    )


class UsersEmployeeAccess(Base):
    __tablename__ = "user_employee_access"
    """
    Model for the UserEmployeeAccess table in the database.

    Tracks which users have access to which employees
    and the level of access (e.g., read, write, admin).
    """
    uuid_user = Column(Uuid(as_uuid=True), ForeignKey("users.uuid"), primary_key=True)
    uuid_employee = Column(Uuid(as_uuid=True), ForeignKey("employees.uuid"), primary_key=True)
    access_level = Column(String(50))
    

# TODO
class Roles():
    __tablename__ = "roles"

class Permissions():
    __tablename__ = "permissions"

# END TODO

def create_db_and_tables():
    Base.metadata.create_all(engine)