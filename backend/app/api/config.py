from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.jira_integration import test_jira_connection
from app.core.siem_export import test_siem_webhook
from app.core.slack_integration import test_slack_webhook
from app.models.models import PlatformConfig, Severity

router = APIRouter(prefix="/api/config", tags=["config"])

VALID_AI_PROVIDERS = {"anthropic", "openai_compatible"}
VALID_AUTO_CREATE_SEVERITIES = {s.value for s in Severity}


class UpdateConfigRequest(BaseModel):
    # All fields are optional so a save only needs to send what changed (e.g.
    # switching provider without re-entering the other provider's key).
    # None = leave unchanged; "" clears the field.
    ai_provider: str | None = None
    anthropic_api_key: str | None = None
    openai_compatible_base_url: str | None = None
    openai_compatible_api_key: str | None = None
    openai_compatible_model: str | None = None
    # Slack (issue #74). None = leave unchanged; "" clears the webhook URL.
    slack_webhook_url: str | None = None
    # Jira (issue #74). None = leave unchanged; "" clears the field.
    jira_url: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str | None = None
    # "Critical"/"High"/"Medium"/"Low"/"Informational", or "" to disable
    # auto-create. None = leave unchanged.
    jira_auto_create_severity: str | None = None
    # SIEM export (issue #114). None = leave unchanged; "" clears the field.
    siem_webhook_url: str | None = None
    siem_export_severity: str | None = None


class TestSlackRequest(BaseModel):
    # Optional override so the "Test Connection" button can verify a
    # not-yet-saved URL typed into the form; falls back to the saved config
    # when omitted.
    webhook_url: str | None = None


class TestJiraRequest(BaseModel):
    jira_url: str | None = None
    jira_api_token: str | None = None


class TestSiemRequest(BaseModel):
    webhook_url: str | None = None


def get_platform_config(session: Session) -> PlatformConfig | None:
    return session.exec(select(PlatformConfig)).first()


def _serialize(config: PlatformConfig | None) -> dict:
    return {
        # Never echo back the raw keys - report only whether one is set, same
        # pattern used for GitHub App secrets.
        "anthropic_api_key_set": bool(config and config.anthropic_api_key),
        "ai_provider": (config.ai_provider if config else None) or "anthropic",
        "openai_compatible_base_url": (config.openai_compatible_base_url if config else "") or "",
        "openai_compatible_api_key_set": bool(config and config.openai_compatible_api_key),
        "openai_compatible_model": (config.openai_compatible_model if config else "") or "",
        # Slack (issue #74) - never echo the raw webhook URL back, same
        # never-echo-raw-secret pattern as the keys above.
        "slack_webhook_url_set": bool(config and config.slack_webhook_url),
        # Jira (issue #74) - url/project key/issue type are not secrets so
        # they're returned as-is (needed to repopulate the form); the API
        # token follows the never-echo pattern.
        "jira_url": (config.jira_url if config else "") or "",
        "jira_api_token_set": bool(config and config.jira_api_token),
        "jira_project_key": (config.jira_project_key if config else "") or "",
        "jira_issue_type": (config.jira_issue_type if config else "") or "Task",
        "jira_auto_create_severity": (config.jira_auto_create_severity if config else None),
        # SIEM export (issue #114) - webhook URL follows the never-echo-raw-
        # secret pattern; export threshold returned as-is like the Jira
        # auto-create threshold above.
        "siem_webhook_url_set": bool(config and config.siem_webhook_url),
        "siem_export_severity": (config.siem_export_severity if config else None),
    }


@router.get("")
def get_config(session: Session = Depends(get_session)):
    config = get_platform_config(session)
    return _serialize(config)


@router.post("")
def update_config(payload: UpdateConfigRequest, session: Session = Depends(get_session)):
    config = get_platform_config(session)
    if not config:
        config = PlatformConfig()

    if payload.ai_provider is not None:
        if payload.ai_provider not in VALID_AI_PROVIDERS:
            raise HTTPException(status_code=400, detail=f"ai_provider must be one of {sorted(VALID_AI_PROVIDERS)}")
        config.ai_provider = payload.ai_provider
    if payload.anthropic_api_key is not None:
        config.anthropic_api_key = payload.anthropic_api_key
    if payload.openai_compatible_base_url is not None:
        config.openai_compatible_base_url = payload.openai_compatible_base_url.rstrip("/")
    if payload.openai_compatible_api_key is not None:
        config.openai_compatible_api_key = encrypt_secret(payload.openai_compatible_api_key)
    if payload.openai_compatible_model is not None:
        config.openai_compatible_model = payload.openai_compatible_model
    if payload.slack_webhook_url is not None:
        config.slack_webhook_url = encrypt_secret(payload.slack_webhook_url)
    if payload.jira_url is not None:
        config.jira_url = payload.jira_url.rstrip("/")
    if payload.jira_api_token is not None:
        config.jira_api_token = encrypt_secret(payload.jira_api_token)
    if payload.jira_project_key is not None:
        config.jira_project_key = payload.jira_project_key
    if payload.jira_issue_type is not None:
        config.jira_issue_type = payload.jira_issue_type
    if payload.jira_auto_create_severity is not None:
        if payload.jira_auto_create_severity == "":
            config.jira_auto_create_severity = None
        elif payload.jira_auto_create_severity not in VALID_AUTO_CREATE_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"jira_auto_create_severity must be one of {sorted(VALID_AUTO_CREATE_SEVERITIES)}",
            )
        else:
            config.jira_auto_create_severity = payload.jira_auto_create_severity
    if payload.siem_webhook_url is not None:
        config.siem_webhook_url = encrypt_secret(payload.siem_webhook_url)
    if payload.siem_export_severity is not None:
        if payload.siem_export_severity == "":
            config.siem_export_severity = None
        elif payload.siem_export_severity not in VALID_AUTO_CREATE_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"siem_export_severity must be one of {sorted(VALID_AUTO_CREATE_SEVERITIES)}",
            )
        else:
            config.siem_export_severity = payload.siem_export_severity

    session.add(config)
    session.commit()
    session.refresh(config)
    return _serialize(config)


@router.post("/test-slack")
def test_slack(payload: TestSlackRequest, session: Session = Depends(get_session)):
    """Real test message sent to the configured (or supplied) Slack incoming
    webhook. Never fabricates success -- returns the real HTTP outcome."""
    webhook_url = payload.webhook_url
    if not webhook_url:
        config = get_platform_config(session)
        if config and config.slack_webhook_url:
            webhook_url = decrypt_secret(config.slack_webhook_url)

    if not webhook_url:
        raise HTTPException(status_code=400, detail="No Slack webhook URL configured or supplied")

    ok, message = test_slack_webhook(webhook_url)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True, "message": message}


@router.post("/test-jira")
def test_jira(payload: TestJiraRequest, session: Session = Depends(get_session)):
    """Real authenticated call to the configured (or supplied) Jira instance
    to confirm the URL + API token are valid. Never fabricates success."""
    jira_url = payload.jira_url
    api_token = payload.jira_api_token

    config = get_platform_config(session)
    if not jira_url:
        jira_url = config.jira_url if config else None
    if not api_token:
        if config and config.jira_api_token:
            api_token = decrypt_secret(config.jira_api_token)

    if not jira_url or not api_token:
        raise HTTPException(status_code=400, detail="Jira URL and API token are required")

    ok, message = test_jira_connection(jira_url, api_token)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True, "message": message}


@router.post("/test-siem")
def test_siem(payload: TestSiemRequest, session: Session = Depends(get_session)):
    """Real test event POSTed to the configured (or supplied) SIEM webhook.
    Never fabricates success -- returns the real HTTP outcome."""
    webhook_url = payload.webhook_url
    if not webhook_url:
        config = get_platform_config(session)
        if config and config.siem_webhook_url:
            webhook_url = decrypt_secret(config.siem_webhook_url)

    if not webhook_url:
        raise HTTPException(status_code=400, detail="No SIEM webhook URL configured or supplied")

    ok, message = test_siem_webhook(webhook_url)
    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"success": True, "message": message}
