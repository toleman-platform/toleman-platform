from datetime import datetime

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.core.security import create_session_token, decode_session_token, hash_api_token, hash_password, verify_password
from app.models.models import (
    WORKSPACE_ROLE_RANK,
    ApiToken,
    ApiTokenScope,
    Finding,
    Target,
    User,
    WorkspaceMembership,
    WorkspaceRole,
)

LOGIN_RATE_LIMIT = 5
LOGIN_RATE_WINDOW_SECONDS = 60

router = APIRouter(prefix="/api/auth", tags=["auth"])

SESSION_COOKIE = "toleman_session"


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
    toleman_session: str | None = Cookie(default=None),
) -> User:
    if not toleman_session:
        raise HTTPException(status_code=401, detail="not authenticated")
    payload = decode_session_token(toleman_session)
    if not payload:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    user = session.get(User, payload["uid"])
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    if payload.get("tv") != user.token_version:
        raise HTTPException(status_code=401, detail="session revoked")
    return user


def _resolve_api_token(session: Session, authorization: str | None) -> ApiToken:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed Authorization header")
    plaintext = authorization.removeprefix("Bearer ").strip()
    token_hash = hash_api_token(plaintext)
    token = session.exec(select(ApiToken).where(ApiToken.token_hash == token_hash)).first()
    if not token or token.revoked_at is not None:
        raise HTTPException(status_code=401, detail="invalid or revoked API token")
    return token


# Declared so the generated OpenAPI document actually describes how to
# authenticate against /api/public/v1 (#109). Reading the header manually
# works at runtime but is invisible to the schema, so Swagger UI, Postman
# imports and generated clients all showed the endpoints as unauthenticated
# and had no way to send a token. auto_error=False keeps the existing 401
# bodies from _resolve_api_token rather than letting FastAPI substitute its
# own, so behaviour is unchanged for existing callers.
api_token_scheme = HTTPBearer(
    scheme_name="ApiToken",
    description=(
        "Personal access token from Settings -> Workspace. Send as "
        "`Authorization: Bearer toleman_pat_...`."
    ),
    auto_error=False,
)


def current_api_token_user(
    session: Session = Depends(get_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(api_token_scheme),
) -> User:
    """Issue #109: resolves the caller of `/api/public/v1/*` from an
    `Authorization: Bearer <token>` header instead of the session cookie
    `current_user` uses; the public API is meant for scripts/CI/third-
    party integrations, not browser sessions.

    Returns the token's owning `User` (so downstream handlers can reuse
    `accessible_workspace_ids(session, user)` unchanged) and bumps
    `last_used_at` so a token's dashboard entry shows real recency instead
    of only creation time. Write-scope checking lives in the separate
    `require_api_token_write_scope` dependency below, not here; most
    public-API endpoints only need read access.
    """
    authorization = f"{credentials.scheme} {credentials.credentials}" if credentials else None
    token = _resolve_api_token(session, authorization)
    user = session.get(User, token.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")

    token.last_used_at = datetime.utcnow()
    session.add(token)
    session.commit()
    return user


def require_api_token_write_scope(
    session: Session = Depends(get_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(api_token_scheme),
) -> None:
    """Gate for public-API endpoints that mutate state (e.g. triggering a
    scan); a `read`-scoped token must not be able to do this even though
    it authenticates fine for GETs."""
    authorization = f"{credentials.scheme} {credentials.credentials}" if credentials else None
    token = _resolve_api_token(session, authorization)
    if token.scope != ApiTokenScope.READ_WRITE:
        raise HTTPException(status_code=403, detail="this token is read-only; a read_write token is required")


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, request: Request, response: Response, session: Session = Depends(get_session)):
    # Pre-auth endpoint, rate-limit by client IP to blunt password
    # brute-forcing. This is the most important limit in the app since it's
    # the only unauthenticated attack surface for credential guessing.
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(
        key=f"login:{client_ip}", limit=LOGIN_RATE_LIMIT, window_seconds=LOGIN_RATE_WINDOW_SECONDS
    )

    user = session.exec(select(User).where(User.email == payload.email)).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid email or password")

    token = create_session_token(user.id, user.token_version)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)


@router.post("/logout")
def logout(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    # Bump token_version so every previously-issued session token for this
    # user (including ones the client no longer has, e.g. other devices)
    # is immediately invalidated server-side, not just this one cookie.
    user.token_version += 1
    session.add(user)
    session.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)


class UpdateMeRequest(BaseModel):
    name: str


@router.patch("/me", response_model=UserOut)
def update_me(payload: UpdateMeRequest, user: User = Depends(current_user), session: Session = Depends(get_session)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    user.name = name
    session.add(user)
    session.commit()
    session.refresh(user)
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="new password must be at least 8 characters")

    user.password_hash = hash_password(payload.new_password)
    # Same revocation pattern as logout: bump token_version so every
    # previously-issued session token (this device and any other) is
    # immediately invalid, not just the current cookie.
    user.token_version += 1
    session.add(user)
    session.commit()

    # Re-issue a fresh session for THIS request/device so the user isn't
    # logged out by their own password change, matching login()'s cookie.
    token = create_session_token(user.id, user.token_version)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return {"ok": True}


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


def require_security_reviewer(user: User = Depends(current_user)) -> User:
    """Reviewing/approving an ignore request on a real vulnerability finding
    is a security-team action - security_engineer or admin, not any
    authenticated user (matches the admin-only gate already applied to
    policy-as-code, for the same reason: both can make a real finding stop
    blocking a merge)."""
    if user.role not in ("admin", "security_engineer"):
        raise HTTPException(status_code=403, detail="security engineer or admin role required")
    return user


def _resolve_workspace_id(
    session: Session,
    *,
    workspace_id: int | None,
    target_id: int | None,
    finding_id: int | None,
) -> int | None:
    """Resolve the workspace a request operates on from whichever
    identifying parameter the route actually carries. Most workspace-scoped
    routers (targets/PR guardrail/SBOM/discovery) take target_id; findings
    routes take finding_id one hop further out."""
    if workspace_id is not None:
        return workspace_id
    if target_id is not None:
        target = session.get(Target, target_id)
        return target.workspace_id if target else None
    if finding_id is not None:
        finding = session.get(Finding, finding_id)
        if not finding:
            return None
        target = session.get(Target, finding.target_id)
        return target.workspace_id if target else None
    return None


def enforce_workspace_role(
    session: Session,
    user: User,
    min_role: WorkspaceRole,
    *,
    workspace_id: int | None = None,
    target_id: int | None = None,
    finding_id: int | None = None,
) -> None:
    """Issue #32: gate a workspace-scoped action on the caller holding at
    least `min_role` for that workspace via WorkspaceMembership. A global
    admin always passes, the workspace role model layers on top of the
    existing global admin/user/viewer role, it doesn't replace it. Callers
    that already resolved a User/Target upstream can reuse it directly;
    otherwise pass whichever of workspace_id/target_id/finding_id the route
    has (see _resolve_workspace_id).

    Used both as the body of require_workspace_role (for routes where the
    resolving id is a plain path/query param FastAPI can bind by name) and
    called directly inside handlers whose id lives inside a JSON body
    (e.g. POST /api/targets' workspace_id), where a Depends-based dependency
    can't see it.
    """
    if user.role == "admin":
        return
    resolved = _resolve_workspace_id(
        session, workspace_id=workspace_id, target_id=target_id, finding_id=finding_id
    )
    if resolved is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    membership = session.exec(
        select(WorkspaceMembership).where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.workspace_id == resolved,
        )
    ).first()
    if not membership or WORKSPACE_ROLE_RANK[membership.role] < WORKSPACE_ROLE_RANK[min_role]:
        raise HTTPException(
            status_code=403,
            detail=f"{min_role.value} role or higher required for this workspace",
        )


def accessible_workspace_ids(session: Session, user: User) -> list[int] | None:
    """Issue #57: the set of workspace ids a caller's GET/list requests may
    return rows from. `None` means "no filter, sees everything"; reserved
    for global admins, mirroring the existing admin bypass in
    enforce_workspace_role. Non-admins get the (possibly empty) list of
    workspaces they hold a WorkspaceMembership in; a user with zero
    memberships gets `[]` so list endpoints correctly return nothing rather
    than erroring or (the #57 bug) returning every workspace's data.

    #32 already gated the write paths (targets/findings mutations) via
    enforce_workspace_role/require_workspace_role. This is the read-path
    counterpart: GET/list routes on findings and targets never filtered by
    workspace at all, so any authenticated user (including a viewer)
    could see every workspace's findings and targets.
    """
    if user.role == "admin":
        return None
    return list(
        session.exec(
            select(WorkspaceMembership.workspace_id).where(WorkspaceMembership.user_id == user.id)
        ).all()
    )


def require_workspace_role(min_role: WorkspaceRole):
    """Dependency factory for routes that operate on one workspace's
    resources. FastAPI binds sub-dependency parameters to the request's
    path/query params by name, so this works unmodified on any route that
    takes target_id, workspace_id, or finding_id as a plain (non-body)
    parameter; e.g.:

        @router.post("/{target_id}")
        def generate_sbom(target_id: int, user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)), ...):

    Routes where the resolving id is nested in a JSON body instead (e.g.
    CreateTargetRequest.workspace_id) can't use this form, call
    enforce_workspace_role directly in the handler body instead.
    """

    def _dependency(
        target_id: int | None = None,
        workspace_id: int | None = None,
        finding_id: int | None = None,
        user: User = Depends(current_user),
        session: Session = Depends(get_session),
    ) -> User:
        enforce_workspace_role(
            session, user, min_role, workspace_id=workspace_id, target_id=target_id, finding_id=finding_id
        )
        return user

    return _dependency
