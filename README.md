# users_manager_fastapi

A simple API for managing employees through functional (service) accounts, built with **FastAPI**.  
Designed with clarity and explicit access in mind, utilizing a database that is easy to understand.

---

## 🎯 Project Goal

Provide a central API for:

- Managing employees and users (including service accounts)  
- Controlled access to employee data  
- Role-based authorization (**RBAC** – planned)  

> No magic. No overengineering. Easy to extend and audit.

---

## 🧱 Tech Stack

- **Python** 3.10+  
- **FastAPI**  
- **SQLAlchemy** (ORM)  
- **PostgreSQL** (primary)  
- **SQLite** (dev/testing)  
- **JWT / OAuth2**  
- **Alembic** *(planned)*  

---

## 🗄 Database Model (Current State)

### Employees
Stores personal and employment-related data.  

**Key fields:**
- `uuid` *(PK)*
- `first_name`, `last_name`
- `email`, `phone` *(unique)*
- `salary`
- `employment_date`

Employees can be accessed by multiple users via an access table.

### Users
Represents human users and service accounts.  

**Key fields:**
- `uuid` *(PK)*
- `login` *(unique)*
- `role` *(string-based for now)*
- `hashed_password`

Users can have access to multiple employees.

### User–Employee Access
Defines many-to-many relationships with access levels.

**Table:** `user_employee_access`  
**Fields:**
- `uuid_user` *(FK → users)*  
- `uuid_employee` *(FK → employees)*  
- `access_level` *(e.g. read, write, admin)*  

This is the core authorization mechanism at the moment.

---

## 🚀 Running the Project

### 1. Create virtual environment
```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the server
```bash
uvicorn backend.main:app --reload
```

### 4. Open in browser
- API root: [http://127.0.0.1:8000](http://127.0.0.1:8000)  
- API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🔐 Security (Current)

- Passwords hashed (**bcrypt**)  
- JWT-based authentication  
- Explicit access mapping via DB (no implicit permissions)  
- No logging of secrets *(as it should be)*  

---

## 🛠 Roadmap / TODO

1. **RBAC (Role-Based Access Control)**
    - Separate `roles` and `permissions` tables  
    - Assign roles to users  
    - Enforce permissions via FastAPI dependencies  
    - Replace plain `role` string in `users`  

2. **Departments**
    - `departments` table  
    - `department_id` column in `employees`  
    - Proper relations and indexing  

3. **Department-Based Access**
    - User → department scope  
    - Manager → own + subordinate departments  
    - Admin → full access  

4. **Admin Panel**
    - Access control  
    - User & service account management  
    - Password / token reset  

5. **Frontend**
    - Optional  
    - React / Vue / Svelte — or  
      classic HTML admin panel *(boring, reliable, effective)*  

---

## 📌 Project Status

Early stage — focusing on foundational elements:  
**Schema → access rules → API logic.**  
> UI comes last — as it should.

