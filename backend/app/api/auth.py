from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.security import create_session_token, verify_password, verify_session_token
from app.models.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])

SESSION_COOKIE = "osp_session"


class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str


def current_user(
    session: Session = Depends(get_session),
    osp_session: str | None = Cookie(default=None),
) -> User:
    if not osp_session:
        raise HTTPException(status_code=401, detail="not authenticated")
    user_id = verify_session_token(osp_session)
    if not user_id:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    return user


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, response: Response, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == payload.email)).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid email or password")

    token = create_session_token(user.id)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user
