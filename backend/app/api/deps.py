from fastapi import Header, HTTPException
from sqlmodel import Session, select

from app.core.db import engine
from app.models.models import Workspace


def get_session():
    with Session(engine) as session:
        yield session


def require_workspace(x_api_key: str = Header(...)) -> Workspace:
    with Session(engine) as session:
        ws = session.exec(select(Workspace).where(Workspace.api_key == x_api_key)).first()
        if not ws:
            raise HTTPException(status_code=401, detail="invalid workspace API key")
        return ws
