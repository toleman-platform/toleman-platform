from datetime import datetime
from enum import Enum
from typing import Optional
from sqlmodel import SQLModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class FindingState(str, Enum):
    OPEN = "Open"
    ACCEPTED_RISK = "Accepted Risk"
    FALSE_POSITIVE = "False Positive"
    WONT_FIX = "Won't Fix"
    MITIGATED = "Mitigated"
    REOPENED = "Reopened"


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    name: str
    password_hash: str
    role: UserRole = UserRole.ADMIN
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Workspace(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id")
    name: str
    api_key: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Target(SQLModel, table=True):
    """A repository / cluster being scanned."""
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    name: str
    repo_url: str
    default_branch: str = "main"
    label: str = "Dev"  # Prod, Dev, Internal, Public, or custom
    criticality_weight: int = 1  # 1-5
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Project(SQLModel, table=True):
    """Specific file/image scope within a Target (currently 1:1 with Target for MVP)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    tool: str
    branch: str
    status: str = "running"  # running, completed, failed
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings_count: int = 0


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    project_id: Optional[int] = Field(default=None, foreign_key="project.id")
    scan_id: Optional[int] = Field(default=None, foreign_key="scan.id")

    dedup_hash: str = Field(index=True)
    tool: str
    rule_id: str
    title: str
    description: str = ""
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    severity: Severity
    priority_score: int = 0

    branch: str = "main"
    state: FindingState = FindingState.OPEN
    state_reason: str = ""

    cve_id: Optional[str] = None
    epss_score: Optional[float] = None
    kev_listed: bool = False

    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    mitigated_at: Optional[datetime] = None


class PlatformConfig(SQLModel, table=True):
    """Single-row runtime configuration, editable via Admin > Global Integrations."""
    id: Optional[int] = Field(default=None, primary_key=True)
    anthropic_api_key: Optional[str] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class GitHubAppConfig(SQLModel, table=True):
    """Created once via the App Manifest flow. Single row for this MVP (single-tenant)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    app_id: str
    slug: str
    client_id: str
    client_secret: str
    private_key_pem: str
    webhook_secret: str
    html_url: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class GitHubInstallation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    installation_id: int = Field(unique=True, index=True)
    account_login: str
    account_type: str
    workspace_id: int = Field(foreign_key="workspace.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingStateLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id")
    from_state: str
    to_state: str
    reason: str = ""
    actor: str = "system"
    created_at: datetime = Field(default_factory=datetime.utcnow)
