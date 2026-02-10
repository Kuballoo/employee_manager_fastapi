from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from jose import jwt, JWTError

from .security import SECRET_KEY, ALGORITHM
from .templates import templates
from .models import create_db_and_tables
from .routers import employees, auth, users, roles, permissions

BASE_DIR = Path(__file__).resolve().parents[1]

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


@app.middleware("http")
async def auth_redirect_middleware(request: Request, call_next):
    """
    Middleware for handling authentication and redirection.

    This middleware intercepts incoming HTTP requests and checks if the
    requested path requires authentication. If the user tries to access
    a protected endpoint without a valid JWT token, they are redirected
    to the login page. Invalid or expired tokens are also removed from cookies.

    Args:
        request (Request): The incoming HTTP request object.
        call_next (Callable): The next request handler in the middleware chain,
            used to continue request processing if authentication passes.

    Returns:
        Response: 
            - RedirectResponse to '/auth/login' if the user is not authenticated or token is invalid.
            - The original route handler response if authentication succeeds.

    Behavior:
        - Checks if the request path starts with any of the protected paths (e.g. "/users").
        - If the path is protected, retrieves the JWT access token from cookies.
        - If no token is found, redirects to the login page.
        - If a token is present, verifies its validity using the configured SECRET_KEY and ALGORITHM.
        - On JWT verification failure, redirects to the login page and removes the invalid cookie.

    Raises:
        JWTError: If token decoding fails during verification.
    """

    if request.url.path.startswith("/users"):
        token = request.cookies.get("access_token")

        if not token:
            return RedirectResponse("/auth/login", status_code=302)

        try:
            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            response = RedirectResponse("/auth/login", status_code=302)
            response.delete_cookie("access_token")
            return response

    return await call_next(request)

app.include_router(employees.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(permissions.router)

