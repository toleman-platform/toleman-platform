from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.core.auth_audit import log_auth_event
from app.core.security import hash_password
from app.models.models import AuthEventType, User, UserRole

router = APIRouter(prefix="/api/admin/users", tags=["admin"])


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str


class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    role: UserRole = UserRole.USER


class UpdateRoleRequest(BaseModel):
    role: UserRole


@router.get("", response_model=list[UserOut])
def list_users(session: Session = Depends(get_session)):
    return session.exec(select(User)).all()


@router.post("", response_model=UserOut)
def create_user(payload: CreateUserRequest, session: Session = Depends(get_session)):
    existing = session.exec(select(User).where(User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=409, detail="email already registered")
    user = User(
        email=payload.email,
        name=payload.name,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.patch("/{user_id}/role", response_model=UserOut)
def update_role(
    user_id: int,
    payload: UpdateRoleRequest,
    session: Session = Depends(get_session),
    admin_user: User = Depends(current_user),
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    old_role = user.role
    user.role = payload.role
    session.add(user)
    session.commit()
    session.refresh(user)
    if old_role != user.role:
        log_auth_event(
            session,
            AuthEventType.ROLE_CHANGED,
            actor=admin_user.email,
            target_email=user.email,
            detail=f"{old_role.value} -> {user.role.value}",
        )
    return user


@router.delete("/{user_id}")
def delete_user(user_id: int, session: Session = Depends(get_session)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    session.delete(user)
    session.commit()
    return {"ok": True}
