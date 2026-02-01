from sqlalchemy import Column, String, Uuid, Float, Date, create_engine, ForeignKey, Text
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
    Employees model representing employee records in the database.
    Attributes:
        uuid (UUID): Unique identifier for the employee, automatically generated.
        first_name (str): Employee's first name, max 50 characters.
        last_name (str): Employee's last name, max 50 characters.
        email (str): Employee's email address, max 100 characters, must be unique.
        phone (str): Employee's phone number, max 50 characters, must be unique.
        country (str): Employee's country of residence, max 25 characters.
        salary (float): Employee's salary amount, required field.
        employment_date (date): Employee's employment start date, defaults to today's date.
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


class Users(Base):
    """
    Users table model for storing user account information.
    Attributes:
        uuid (UUID): Unique identifier for each user, auto-generated using uuid4.
        login (str): User's login/username, must be unique and non-nullable, max 50 characters.
        hashed_password (str): Encrypted password string, non-nullable.
        roles (relationship): Many-to-many relationship with Roles
            through the users_roles association table.
    """

    __tablename__ = "users"

    uuid = Column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    login = Column(String(50), nullable=False, unique=True)
    hashed_password = Column(String(), nullable=False)
    roles = relationship(
        "Roles",
        secondary="users_roles",
        back_populates="users"
    )

class Roles(Base):
    """
    Roles model representing user roles in the system.
    This model defines roles that can be assigned to users and associated with
    specific permissions through a many-to-many relationship.
    Attributes:
        uuid (UUID): Unique identifier for the role, automatically generated.
        name (str): The name of the role (max 50 characters), must be unique.
        description (str): Optional text description of the role's purpose.
        permissions (relationship): Many-to-many relationship to Permissions
            through the roles_permissions association table.
        users (relationship): Many-to-many relationship to Users
            through the users_roles association table.
    """

    __tablename__ = "roles"

    uuid = Column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(50), nullable=False, unique=True)
    description = Column(Text)

    permissions = relationship(
        "Permissions",
        secondary="roles_permissions",
        back_populates="roles"
    )

    users = relationship(
        "Users",
        secondary="users_roles",
        back_populates="roles"
    )

class Permissions(Base):
    """
    Permissions model for managing application permissions.
    This model represents a permission entity that can be assigned to roles.
    Permissions are stored in the 'permissions' table and can be associated
    with multiple roles through a many-to-many relationship via the
    'roles_permissions' junction table.
    Attributes:
        uuid (UUID): Unique identifier for the permission (primary key).
        name (str): The name of the permission (max 50 characters).
        roles (relationship): Many-to-many relationship with Roles model,
            allowing a permission to be assigned to multiple roles.
    """

    __tablename__ = "permissions"
    
    uuid = Column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(50), unique=True, nullable=False)
    
    roles = relationship(
        "Roles",
        secondary="roles_permissions",
        back_populates="permissions"
    )

class UsersRoles(Base):
    """
    Association table for the many-to-many relationship between users and roles.
    This model represents the junction table that links users to their assigned roles.
    Each record in this table indicates that a specific user has a specific role.
    Attributes:
        uuid_user (UUID): Foreign key referencing the uuid of a user in the users table.
                          Part of the composite primary key.
        uuid_role (UUID): Foreign key referencing the uuid of a role in the roles table.
                          Part of the composite primary key.
    """

    __tablename__ = "users_roles"

    uuid_user = Column(Uuid(as_uuid=True), ForeignKey("users.uuid"), primary_key=True)
    uuid_role = Column(Uuid(as_uuid=True), ForeignKey("roles.uuid"), primary_key=True)

class RolesPermissions(Base):
    """
    Association table for mapping roles to permissions.

    This is a many-to-many join table that establishes the relationship between
    roles and permissions. Each row represents a permission granted to a specific role.

    Attributes:
        uuid_role (UUID): Foreign key referencing the roles table. Part of the composite primary key.
        uuid_permission (UUID): Foreign key referencing the permissions table. Part of the composite primary key.
    """

    __tablename__ = "roles_permissions"

    uuid_role = Column(Uuid(as_uuid=True), ForeignKey("roles.uuid"), primary_key=True)
    uuid_permission = Column(Uuid(as_uuid=True), ForeignKey("permissions.uuid"), primary_key=True)


def create_db_and_tables():
    Base.metadata.create_all(engine)