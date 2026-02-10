from fastapi import APIRouter, HTTPException, Depends, status, Form, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from typing import Annotated, Optional
from urllib.parse import quote

from ..dependecies import db_dependency
from ..security import authenticate_user, create_access_token
from ..templates import templates

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

### FRONTEND ENDPOINTS ###
@router.get("/logout")
async def logout():
    """
    Logout endpoint that clears the authentication session.

    This endpoint invalidates the user's session by removing the JWT access token
    from the browser cookies and redirects the user back to the login page.
    After calling this endpoint, the user must re-authenticate to access protected routes.

    Args:
        None

    Returns:
        RedirectResponse: Redirects to '/auth/login' (302 status code) with
            the 'access_token' cookie deleted, effectively logging out the user.

    Raises:
        None
    """
    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie("access_token")
    return response

@router.get("/login")
async def login_page(request: Request, error: Optional[str] = None):
    """
    Login page endpoint that renders the authentication form.

    This endpoint serves the HTML login template, optionally displaying error
    messages passed as query parameters (e.g., after failed authentication attempts).
    It does not perform actual authentication — handles only the login form rendering.

    Args:
        request (Request): The incoming HTTP request object.
        error (Optional[str], optional): Error message to display on the login form.
            Defaults to None. Passed via query parameter `?error=message`.

    Returns:
        TemplateResponse: Renders 'login.html' template with:
            - request: The FastAPI Request object for template context.
            - error: Optional error message for form validation/display.

    Raises:
        None
    """
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error
        }
    )

@router.post("/login/submit", include_in_schema=False)
def login_submit(request: Request, db: db_dependency, username: str | None = Form(None), password: str | None = Form(None)):
    """
    Handle user login submission and authentication.
    Authenticates the user with the provided username and password credentials.
    If authentication succeeds, creates an access token and returns a redirect response
    with the token stored in an HTTP-only cookie. If authentication fails, returns
    the login template with an error message.
    Args:
        request (Request): The incoming HTTP request object.
        db (db_dependency): Database session dependency for querying user credentials.
        username (str): The username provided in the form submission.
        password (str): The password provided in the form submission.
    Returns:
        TemplateResponse: Login template with error message if authentication fails (401 status).
        RedirectResponse: Redirect to home page with access token cookie if authentication succeeds (302 status).
    """
    if not username or not password:
        return RedirectResponse(
            url=f"/auth/login?error={quote('Fill all fields')}",
            status_code=302
        )
    
    user_auth = authenticate_user(username, password, db)

    if not user_auth:
        return RedirectResponse(
            url=f"/auth/login?error={quote('Wrong login or password')}",
            status_code=302
        )

    token = create_access_token(user_auth.uuid)
    
    response = RedirectResponse(url="/users/home-page", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True
    )
    return response


### O2AUTH API ENDPOINT ###
@router.post("/token")
async def login_for_access_token(login_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    """
    Handle user login and generate access token.
    Authenticates a user based on their username and password credentials,
    and returns a JWT access token for subsequent authenticated requests.
    Args:
        login_data (OAuth2PasswordRequestForm): The login credentials containing
            username and password.
        db (db_dependency): Database session dependency for user lookup.
    Returns:
        dict: A dictionary containing:
            - access_token (str): JWT token for authentication
            - token_type (str): Token type, always "bearer"
    Raises:
        HTTPException: 401 status code if authentication fails (invalid
            username or password).
    """

    user = authenticate_user(login_data.username, login_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = create_access_token(user.uuid)

    return {"access_token": token, "token_type": "bearer"}
