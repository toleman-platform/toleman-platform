"""SameSite cookies still accompany requests from hostile sibling subdomains."""
import pytest
from sqlmodel import Session

from tests.conftest import _login
from app.core.config import settings
from app.models.models import User


@pytest.mark.parametrize("origin", [
    "https://evil.example.com", "null", "https://app.example.com.evil.test",
    "http://app.example.com", "https://app.example.com:444",
])
def test_untrusted_origin_cannot_revoke_session(client, engine, monkeypatch, origin):
    monkeypatch.setattr(settings, "public_base_url", "https://app.example.com")
    _, uid = _login(client, engine)
    with Session(engine) as session:
        version = session.get(User, uid).token_version
    response = client.post("/api/auth/logout", headers={"Origin": origin})
    assert response.status_code == 403
    with Session(engine) as session:
        assert session.get(User, uid).token_version == version
    assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize("method,path,payload", [
    ("PATCH", "/api/auth/me", {"name": "Attacker"}),
    ("POST", "/api/auth/change-password", {"current_password": "whatever123", "new_password": "attacker123"}),
    ("PUT", "/api/dashboard/layout", {"widgets": []}),
    ("POST", "/api/targets/bulk-pipeline-integrate", {"target_ids": [1]}),
])
def test_cookie_mutations_share_origin_check(client, engine, method, path, payload):
    _login(client, engine)
    response = client.request(method, path, json=payload, headers={"Origin": "https://evil.example.com"})
    assert response.status_code == 403
    assert response.json()["detail"] == "untrusted request origin"


@pytest.mark.parametrize("origin", [
    "https://app.example.com", "https://api.example.com", "https://staging.example.com",
    "http://testserver", None,
])
def test_allowed_origins_and_nonbrowser_requests_can_logout(client, engine, monkeypatch, origin):
    monkeypatch.setattr(settings, "public_base_url", "https://app.example.com")
    monkeypatch.setattr(settings, "public_api_url", "https://api.example.com")
    monkeypatch.setattr(settings, "extra_cors_origins", "https://staging.example.com")
    _login(client, engine)
    headers = {"Origin": origin} if origin is not None else {}
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_untrusted_origin_can_read_session_without_mutating_it(client, engine):
    _login(client, engine)
    assert client.get("/api/auth/me", headers={"Origin": "https://evil.example.com"}).status_code == 200
