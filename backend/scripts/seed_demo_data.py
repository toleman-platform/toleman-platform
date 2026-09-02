#!/usr/bin/env python3
"""Randomized versatile demo data generator for Toleman.

Usage:
    # Run in Docker Compose (pipe script into container):
    docker compose exec -T backend python - < backend/scripts/seed_demo_data.py

    # Or run locally:
    cd backend && python scripts/seed_demo_data.py --count 200 --clean
"""
import argparse
import hashlib
import json
import random
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# Ensure app package is discoverable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlmodel import Session, select, delete
from app.core.db import engine
from app.core.security import hash_password
from app.models.models import (
    AiBomComponent,
    ApiEndpoint,
    CveEnrichment,
    DiscoveryRun,
    Finding,
    FindingState,
    FindingStateLog,
    Group,
    IgnoreStatus,
    Organization,
    PolicyRule,
    PolicyRuleType,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
    Scan,
    SbomComponent,
    SbomRun,
    Severity,
    SlaRule,
    Target,
    TargetGroup,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)

# ----------------- Templates for Randomized Generation -----------------

VULN_TEMPLATES = [
    # (Title pattern, Tool, Rule ID, Severity, File paths, CVE, EPSS range, KEV prob, Category)
    ("Hardcoded {provider} Secret API Key", "gitleaks", "{provider_slug}-api-key", Severity.CRITICAL, ["services/{service}/client.py", "config/{service}_secrets.json", "src/auth/{service}.ts"], None, None, 0.0, "secret"),
    ("Unencrypted RSA/ECC Private Key Committed", "gitleaks", "private-key", Severity.CRITICAL, ["certs/{service}_server.key", "config/jwt_{service}.pem"], None, None, 0.0, "secret"),
    ("SQL Injection in {module} Query Builder", "gosec", "G201", Severity.CRITICAL, ["pkg/db/{module}.go", "internal/repository/{module}_repo.go"], None, (0.6, 0.95), 0.3, "sast"),
    ("Remote Code Execution via Insecure Deserialization", "semgrep", "java.lang.security.audit.object-deserialization", Severity.CRITICAL, ["src/main/java/com/acme/{module}/PayloadParser.java"], "CVE-2021-44228", (0.9, 0.99), 0.9, "sca"),
    ("Unsafe Torch/Pickle Model Deserialization (RCE)", "modelscan", "MODELSCAN_UNSAFE_PICKLE", Severity.CRITICAL, ["models/{service}/classifier_v{ver}.pkl", "weights/detector_{ver}.pt"], "CVE-2024-34340", (0.5, 0.85), 0.1, "ai_model"),
    ("Container Breakout via Leaked File Descriptor", "trivy", "CVE-2024-21626", Severity.CRITICAL, ["Dockerfile", "deploy/Dockerfile.{service}"], "CVE-2024-21626", (0.7, 0.92), 0.8, "container"),
    ("Publicly Accessible S3 Bucket with Write Access", "checkov", "CKV_AWS_57", Severity.CRITICAL, ["terraform/{service}_storage.tf", "infra/s3.tf"], None, None, 0.0, "iac"),
    ("Blind NoSQL Injection in {module} Search", "semgrep", "javascript.express.mongodb-nosql-injection", Severity.CRITICAL, ["routes/{module}.js", "controllers/{module}Controller.ts"], None, (0.3, 0.7), 0.1, "sast"),

    # HIGH
    ("Cross-Site Scripting (Stored XSS) in {module}", "semgrep", "javascript.express.security.audit.xss.direct-response-write", Severity.HIGH, ["views/{module}/render.js", "src/components/{module}View.tsx"], None, (0.2, 0.5), 0.1, "sast"),
    ("Server-Side Request Forgery (SSRF) in {module} Fetcher", "semgrep", "python.lang.security.audit.unvalidated-url-requests", Severity.HIGH, ["app/{module}/fetcher.py", "services/{service}/webhook_sender.py"], None, (0.4, 0.8), 0.4, "sast"),
    ("Broken Object Level Authorization (BOLA/IDOR) in {module} API", "semgrep", "generic.auth.missing-tenant-ownership-check", Severity.HIGH, ["controllers/{module}.js", "routes/api/{module}.py"], None, (0.1, 0.4), 0.0, "sast"),
    ("OpenSSH Remote Code Execution (regreSSHion)", "trivy", "CVE-2024-6387", Severity.HIGH, ["Dockerfile", "base/Dockerfile"], "CVE-2024-6387", (0.6, 0.9), 0.7, "container"),
    ("Prompt Injection in {module} LLM Agent", "semgrep", "ai.prompt-injection.unfiltered-user-context", Severity.HIGH, ["agents/{module}_agent.py", "src/llm/{module}_chain.py"], None, (0.1, 0.3), 0.0, "ai_model"),
    ("Heap Buffer Overflow in libwebp", "trivy", "CVE-2023-4863", Severity.HIGH, ["package.json", "go.mod"], "CVE-2023-4863", (0.8, 0.95), 0.9, "sca"),
    ("Insecure TLS 1.0/1.1 Protocol Enabled", "gosec", "G402", Severity.HIGH, ["pkg/network/{service}_tls.go", "internal/transport/server.go"], None, (0.05, 0.15), 0.0, "sast"),
    ("Weak JWT Signing Secret (Dictionary Word)", "semgrep", "javascript.jwt.security.jwt-hardcoded-secret", Severity.HIGH, ["middleware/auth.js", "src/security/jwt.ts"], None, (0.3, 0.6), 0.1, "sast"),

    # MEDIUM
    ("Sensitive Data Exposure in Verbose Error Logs", "semgrep", "python.logging.security.audit.sensitive-param-logged", Severity.MEDIUM, ["app/core/{module}.py", "src/utils/logger.ts"], None, (0.01, 0.1), 0.0, "sast"),
    ("Missing CSRF Token on {module} State-Changing Route", "gosec", "G104", Severity.MEDIUM, ["pkg/handlers/{module}.go", "internal/api/{module}.go"], None, (0.05, 0.2), 0.0, "sast"),
    ("Cross-Origin Resource Sharing (CORS) Wildcard Allowed", "semgrep", "javascript.cors.wildcard", Severity.MEDIUM, ["server.js", "src/app.ts"], None, (0.02, 0.1), 0.0, "sast"),
    ("Requests Session Header Leak on Redirect", "trivy", "CVE-2023-32681", Severity.MEDIUM, ["requirements.txt", "Pipfile"], "CVE-2023-32681", (0.2, 0.4), 0.0, "sca"),
    ("Weak Cryptographic Hash (MD5/SHA1) for Checksums", "gosec", "G401", Severity.MEDIUM, ["pkg/hash/{module}.go", "internal/util/crypto.go"], None, (0.01, 0.05), 0.0, "sast"),
    ("Missing Rate Limiting on Authentication Route", "semgrep", "generic.rate-limit.missing-on-auth", Severity.MEDIUM, ["routes/{module}_auth.js", "controllers/login.ts"], None, (0.1, 0.3), 0.0, "sast"),
    ("Security Group Ingress Open to 0.0.0.0/0 on Management Port", "checkov", "CKV_AWS_24", Severity.MEDIUM, ["terraform/sg_{service}.tf", "infra/networking.tf"], None, None, 0.0, "iac"),

    # LOW / INFO
    ("Missing Content-Security-Policy (CSP) Header", "semgrep", "javascript.helmet.missing-csp", Severity.LOW, ["server.js", "src/middleware/headers.ts"], None, (0.01, 0.05), 0.0, "sast"),
    ("Server Header Leaks Verbose Framework Version", "semgrep", "javascript.express.security.audit.x-powered-by", Severity.LOW, ["app.js", "src/main.ts"], None, (0.01, 0.02), 0.0, "sast"),
    ("Insecure File Permissions (0777) on Temp Storage", "gosec", "G302", Severity.LOW, ["pkg/fs/{module}.go", "internal/storage/temp.go"], None, (0.01, 0.03), 0.0, "sast"),
    ("OpenAPI Swagger Documentation Publicly Exposed in Prod", "semgrep", "python.fastapi.audit.docs-exposed", Severity.INFO, ["app/main.py", "src/server.ts"], None, (0.01, 0.01), 0.0, "sast"),
    ("Information Disclosure in robots.txt Disallow Directives", "semgrep", "web.robots-txt.sensitive-paths", Severity.INFO, ["public/robots.txt", "static/robots.txt"], None, (0.01, 0.01), 0.0, "sast"),
]

PROVIDERS = [
    ("Stripe Production", "stripe"),
    ("AWS IAM Admin", "aws"),
    ("GitHub Personal Access", "github"),
    ("OpenAI Platform", "openai"),
    ("Slack Bot Webhook", "slack"),
    ("Anthropic API", "anthropic"),
    ("SendGrid Master", "sendgrid"),
    ("Datadog API", "datadog"),
]

SERVICES = ["billing", "auth", "checkout", "portal", "analytics", "fraud", "rag", "inventory", "gateway", "ledger"]
MODULES = ["payments", "tokens", "users", "orders", "invoices", "reports", "embeddings", "sessions", "tenants", "webhooks"]

PACKAGES = [
    ("react", "18.2.0", "npm", "pkg:npm/react@18.2.0"),
    ("next", "14.1.0", "npm", "pkg:npm/next@14.1.0"),
    ("jsonwebtoken", "8.5.1", "npm", "pkg:npm/jsonwebtoken@8.5.1"),
    ("express", "4.18.2", "npm", "pkg:npm/express@4.18.2"),
    ("axios", "1.6.7", "npm", "pkg:npm/axios@1.6.7"),
    ("torch", "2.1.2", "pip", "pkg:pypi/torch@2.1.2"),
    ("transformers", "4.37.2", "pip", "pkg:pypi/transformers@4.37.2"),
    ("langchain", "0.1.6", "pip", "pkg:pypi/langchain@0.1.6"),
    ("chromadb", "0.4.22", "pip", "pkg:pypi/chromadb@0.4.22"),
    ("openai", "1.12.0", "pip", "pkg:pypi/openai@1.12.0"),
    ("fastapi", "0.109.0", "pip", "pkg:pypi/fastapi@0.109.0"),
    ("github.com/gin-gonic/gin", "v1.9.1", "go", "pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
    ("google.golang.org/grpc", "v1.62.0", "go", "pkg:golang/google.golang.org/grpc@v1.62.0"),
    ("go.uber.org/zap", "v1.27.0", "go", "pkg:golang/go.uber.org/zap@v1.27.0"),
    ("org.apache.logging.log4j:log4j-core", "2.14.1", "maven", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
    ("org.springframework.boot:spring-boot-starter-web", "2.5.4", "maven", "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4"),
]

AI_MODELS = [
    ("meta-llama/Llama-3-8B-Instruct", "machine-learning-model", "v1.0", "huggingface", "src/inference/llm_judge.py"),
    ("openai/whisper-large-v3", "machine-learning-model", "2023-11", "hosted-api", "services/audio/transcribe.py"),
    ("xgboost-fraud-v4.safetensors", "machine-learning-model", "sha256:e3b0c442", "local", "models/weights/xgboost_fraud.safetensors"),
    ("acme-credit-transactions-2025", "data", "v2025.01", "local", "data/training/transactions_q1.parquet"),
    ("text-embedding-3-small", "machine-learning-model", "unknown", "hosted-api", "rag/embeddings.py"),
    ("gpt-4o-2024-05-13", "machine-learning-model", "2024-05-13", "hosted-api", "agents/copilot.py"),
    ("acme-internal-knowledge-base-v3", "data", "v3.2", "local", "data/vector_store/chroma_db/"),
    ("mistralai/Mistral-7B-Instruct-v0.2", "machine-learning-model", "v0.2", "huggingface", "models/rag_config.json"),
]


def seed_random_data(session: Session, count: int = 150, clean: bool = False) -> None:
    now = datetime.utcnow()
    print(f"🎲 Generating {count} randomized versatile records across Toleman...")

    if clean:
        print("🧹 Cleaning existing data...")
        session.exec(delete(FindingStateLog))
        session.exec(delete(PRGuardrailFinding))
        session.exec(delete(PRGuardrailScan))
        session.exec(delete(Finding))
        session.exec(delete(Scan))
        session.exec(delete(SbomComponent))
        session.exec(delete(SbomRun))
        session.exec(delete(AiBomComponent))
        session.exec(delete(ApiEndpoint))
        session.exec(delete(DiscoveryRun))
        session.commit()

    # 1. Organization & Workspaces
    org = session.exec(select(Organization).where(Organization.name == "Acme Corp")).first()
    if not org:
        org = Organization(name="Acme Corp")
        session.add(org)
        session.commit()
        session.refresh(org)

    workspaces = {}
    ws_configs = [
        ("production", "toleman_key_prod_sec_01"),
        ("staging", "toleman_key_stag_sec_02"),
        ("ai-research", "toleman_key_aire_sec_03"),
    ]
    for ws_name, key in ws_configs:
        ws = session.exec(select(Workspace).where(Workspace.name == ws_name, Workspace.organization_id == org.id)).first()
        if not ws:
            ws = Workspace(name=ws_name, organization_id=org.id, api_key=key)
            session.add(ws)
            session.commit()
            session.refresh(ws)
        workspaces[ws_name] = ws

    ws_prod = workspaces["production"]
    ws_staging = workspaces["staging"]
    ws_ai = workspaces["ai-research"]

    # 2. Users & Memberships
    users_data = [
        ("sarah.sec@acme.corp", "Sarah Chen", UserRole.SECURITY_ENGINEER),
        ("dave.dev@acme.corp", "Dave Miller", UserRole.DEVELOPER),
        ("alex.lead@acme.corp", "Alex Rivera", UserRole.ADMIN),
        ("rachel.qa@acme.corp", "Rachel Vance", UserRole.VIEWER),
    ]
    for email, name, role in users_data:
        u = session.exec(select(User).where(User.email == email)).first()
        if not u:
            u = User(email=email, name=name, password_hash=hash_password("changeme123"), role=role)
            session.add(u)
            session.commit()
            session.refresh(u)
            session.add(WorkspaceMembership(user_id=u.id, workspace_id=ws_prod.id, role=WorkspaceRole.SECURITY_ENGINEER if "sec" in email else WorkspaceRole.DEVELOPER))
            session.add(WorkspaceMembership(user_id=u.id, workspace_id=ws_staging.id, role=WorkspaceRole.DEVELOPER))
            session.add(WorkspaceMembership(user_id=u.id, workspace_id=ws_ai.id, role=WorkspaceRole.DEVELOPER))
    session.commit()

    # 3. Target Groups
    groups_def = [
        ("PCI-DSS Scope", "#ef4444", ws_prod.id),
        ("Core Platform", "#3b82f6", ws_prod.id),
        ("Customer Facing", "#10b981", ws_prod.id),
        ("AI & LLM Services", "#f59e0b", ws_prod.id),
        ("Internal Tooling", "#8b5cf6", ws_staging.id),
    ]
    groups = {}
    for name, color, ws_id in groups_def:
        g = session.exec(select(Group).where(Group.name == name, Group.workspace_id == ws_id)).first()
        if not g:
            g = Group(name=name, color=color, workspace_id=ws_id)
            session.add(g)
            session.commit()
            session.refresh(g)
        groups[name] = g

    # 4. Target Repositories
    targets_def = [
        ("payment-gateway", "https://github.com/securego/gosec.git", ws_prod.id, "Prod", 5, "Payments Team", "production", "active", False, "", "https://api.payments.acme.corp", "PCI-DSS Scope"),
        ("auth-identity-service", "https://github.com/OWASP/NodeGoat.git", ws_prod.id, "Prod", 5, "Identity & IAM", "production", "active", False, "", "https://auth.acme.corp", "Core Platform"),
        ("customer-portal-web", "https://github.com/juice-shop/juice-shop.git", ws_prod.id, "Prod", 4, "Frontend Experience", "production", "active", False, "", "https://app.acme.corp", "Customer Facing"),
        ("ml-fraud-detector", "https://github.com/huggingface/transformers.git", ws_prod.id, "Prod", 4, "AI Risk Engineering", "production", "active", True, "PyTorch, Safetensors, Transformers, Scikit-learn", "https://fraud-api.acme.corp", "AI & LLM Services"),
        ("llm-rag-copilot", "https://github.com/langchain-ai/langchain.git", ws_prod.id, "Internal", 3, "GenAI Lab", "staging", "active", True, "LangChain, ChromaDB, OpenAI API, LlamaIndex", "https://rag-dev.acme.corp", "AI & LLM Services"),
        ("inventory-service", "https://github.com/pallets/flask.git", ws_staging.id, "Dev", 2, "Logistics Dev", "staging", "active", False, "", "https://inventory.acme.corp", "Internal Tooling"),
        ("cloud-infra-terraform", "https://github.com/hashicorp/terraform.git", ws_prod.id, "Prod", 4, "DevOps / SRE", "production", "active", False, "", None, "Core Platform"),
        ("legacy-ledger-sync", "https://github.com/spring-projects/spring-boot.git", ws_prod.id, "Internal", 3, "Legacy Ops", "production", "maintenance", False, "", None, "PCI-DSS Scope"),
    ]
    targets = []
    for name, repo_url, ws_id, label, crit, owner, env, lifecycle, is_ai, signals, api_url, grp_name in targets_def:
        t = session.exec(select(Target).where(Target.name == name, Target.workspace_id == ws_id)).first()
        if not t:
            t = Target(
                name=name,
                repo_url=repo_url,
                workspace_id=ws_id,
                default_branch="main",
                label=label,
                criticality_weight=crit,
                owner=owner,
                environment=env,
                lifecycle=lifecycle,
                is_ai_repo=is_ai,
                is_ai_repo_signals=signals,
                api_base_url=api_url,
                pipeline_integrated=True,
            )
            session.add(t)
            session.commit()
            session.refresh(t)
            if grp_name in groups:
                session.add(TargetGroup(target_id=t.id, group_id=groups[grp_name].id))
                session.commit()
        targets.append(t)

    # 5. SLA & Policy Rules
    sla_configs = [(Severity.CRITICAL, 7), (Severity.HIGH, 14), (Severity.MEDIUM, 30), (Severity.LOW, 90)]
    for sev, days in sla_configs:
        existing = session.exec(select(SlaRule).where(SlaRule.workspace_id == ws_prod.id, SlaRule.severity == sev, SlaRule.group_id == None)).first()
        if not existing:
            session.add(SlaRule(workspace_id=ws_prod.id, group_id=None, severity=sev, days_to_fix=days))

    policy_configs = [
        (PolicyRuleType.BLOCK_SEVERITY, "High", "Block PR merge on any new High or Critical vulnerability"),
        (PolicyRuleType.SUPPRESS_RULE, "go.gorilla.csrf.missing-cookie", "Suppressed for internal health-check endpoints"),
        (PolicyRuleType.SUPPRESS_LICENSE, "MIT", "Allow standard MIT licensed libraries"),
    ]
    for rtype, val, reason in policy_configs:
        existing = session.exec(select(PolicyRule).where(PolicyRule.workspace_id == ws_prod.id, PolicyRule.value == val)).first()
        if not existing:
            session.add(PolicyRule(workspace_id=ws_prod.id, rule_type=rtype, value=val, reason=reason, created_by="sarah.sec@acme.corp", active=True))
    session.commit()

    # 6. Scans across multiple tools
    tools_list = ["semgrep", "gitleaks", "trivy", "gosec", "modelscan", "checkov", "bandit"]
    for tgt in targets:
        for tool in random.sample(tools_list, k=random.randint(2, 4)):
            days_ago = random.randint(1, 45)
            start_t = now - timedelta(days=days_ago, hours=random.randint(1, 12))
            is_failed = random.random() < 0.08
            comp_t = None if is_failed else start_t + timedelta(minutes=random.randint(1, 10))
            s = Scan(
                target_id=tgt.id,
                tool=tool,
                branch=tgt.default_branch,
                status="failed" if is_failed else "completed",
                started_at=start_t,
                completed_at=comp_t,
                findings_count=0 if is_failed else random.randint(2, 25),
                error="Git clone failed: connection timeout" if is_failed else "",
            )
            session.add(s)
    session.commit()

    # 7. Randomized Diverse Findings
    created_findings = 0
    state_choices = [FindingState.OPEN] * 70 + [FindingState.MITIGATED] * 10 + [FindingState.FALSE_POSITIVE] * 8 + [FindingState.ACCEPTED_RISK] * 7 + [FindingState.REOPENED] * 5

    for i in range(count):
        tmpl = random.choice(VULN_TEMPLATES)
        tgt = random.choice(targets)
        prov_name, prov_slug = random.choice(PROVIDERS)
        service = random.choice(SERVICES)
        module = random.choice(MODULES)
        ver = f"{random.randint(1, 4)}.{random.randint(0, 9)}"

        title = tmpl[0].format(provider=prov_name, service=service, module=module, ver=ver)
        rule_id = tmpl[2].format(provider_slug=prov_slug, service=service, module=module, ver=ver)
        file_path_tmpl = random.choice(tmpl[4])
        file_path = file_path_tmpl.format(service=service, module=module, ver=ver)
        tool = tmpl[1]
        sev = tmpl[3]
        cve_id = tmpl[5]

        epss_range = tmpl[6]
        epss = round(random.uniform(*epss_range), 4) if epss_range else None
        kev = random.random() < tmpl[7]
        state = random.choice(state_choices)

        line_start = random.randint(10, 400)
        line_end = line_start + random.randint(0, 15)

        crit_weight = tgt.criticality_weight
        sev_weight = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}[sev]
        epss_multiplier = (epss or 0.1) * 10
        kev_bonus = 20 if kev else 0
        priority = min(99, int(crit_weight * sev_weight * 3 + epss_multiplier + kev_bonus))

        days_first_seen = random.randint(1, 80)
        f_seen = now - timedelta(days=days_first_seen, hours=random.randint(1, 20))
        l_seen = now - timedelta(hours=random.randint(1, 24))
        mit_at = now - timedelta(days=random.randint(1, 10)) if state == FindingState.MITIGATED else None

        dedup_str = f"{tgt.id}:{tool}:{rule_id}:{file_path}:{line_start}:{uuid.uuid4().hex[:8]}"
        dedup_hash = hashlib.sha256(dedup_str.encode()).hexdigest()

        f_obj = Finding(
            target_id=tgt.id,
            dedup_hash=dedup_hash,
            tool=tool,
            rule_id=rule_id,
            title=title,
            description=f"Automated scan alert detected in {file_path}. Threat category: {tmpl[8]}.",
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            severity=sev,
            priority_score=priority,
            branch=tgt.default_branch,
            state=state,
            state_reason="Security triage decision" if state != FindingState.OPEN else "",
            cve_id=cve_id,
            epss_score=epss,
            kev_listed=kev,
            first_seen=f_seen,
            last_seen=l_seen,
            mitigated_at=mit_at,
        )
        session.add(f_obj)
        session.commit()
        session.refresh(f_obj)
        created_findings += 1

        if state != FindingState.OPEN:
            session.add(FindingStateLog(
                finding_id=f_obj.id,
                from_state="Open",
                to_state=state.value,
                reason="Triage review completed",
                actor=random.choice(["sarah.sec@acme.corp", "alex.lead@acme.corp"]),
                created_at=f_seen + timedelta(days=random.randint(1, 5)),
            ))

    session.commit()
    print(f"✨ Findings generated: {created_findings} records")

    # 8. SBOM & AI-BOM components
    for tgt in targets:
        for pkg, ver, ptype, purl in random.sample(PACKAGES, k=random.randint(4, 10)):
            existing = session.exec(select(SbomComponent).where(SbomComponent.target_id == tgt.id, SbomComponent.name == pkg)).first()
            if not existing:
                session.add(SbomComponent(
                    target_id=tgt.id,
                    branch=tgt.default_branch,
                    name=pkg,
                    version=ver,
                    package_type=ptype,
                    purl=purl,
                    source="trivy,github",
                    first_seen=now - timedelta(days=random.randint(10, 40)),
                    last_seen=now,
                ))
        if tgt.is_ai_repo:
            for mname, ctype, mver, src, ev in random.sample(AI_MODELS, k=random.randint(2, 5)):
                existing = session.exec(select(AiBomComponent).where(AiBomComponent.target_id == tgt.id, AiBomComponent.name == mname)).first()
                if not existing:
                    session.add(AiBomComponent(
                        target_id=tgt.id,
                        branch=tgt.default_branch,
                        name=mname,
                        component_type=ctype,
                        version=mver,
                        source=src,
                        evidence=ev,
                        first_seen=now - timedelta(days=random.randint(10, 30)),
                        last_seen=now,
                    ))
    session.commit()

    # 9. API Discovery Endpoints
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    frameworks = ["fastapi", "express", "gin", "spring-boot", "flask"]
    for tgt in targets:
        for mod in random.sample(MODULES, k=random.randint(3, 7)):
            method = random.choice(methods)
            route = f"/api/v1/{mod}" + ("/:id" if method in ["GET", "PUT", "DELETE"] and random.random() < 0.5 else "")
            existing = session.exec(select(ApiEndpoint).where(ApiEndpoint.target_id == tgt.id, ApiEndpoint.method == method, ApiEndpoint.route == route)).first()
            if not existing:
                session.add(ApiEndpoint(
                    target_id=tgt.id,
                    branch=tgt.default_branch,
                    framework=random.choice(frameworks),
                    method=method,
                    route=route,
                    file_path=f"src/routes/{mod}.ts",
                    line=random.randint(15, 180),
                    first_seen=now - timedelta(days=random.randint(5, 30)),
                    last_seen=now,
                ))
    session.commit()

    # 10. PR Guardrail Runs
    for tgt in targets:
        pr_statuses = [PRGuardrailStatus.PASSED, PRGuardrailStatus.BLOCKED, PRGuardrailStatus.OVERRIDDEN]
        for pr_num in range(101, 101 + random.randint(2, 5)):
            status = random.choice(pr_statuses)
            pr_scan = PRGuardrailScan(
                target_id=tgt.id,
                pr_number=pr_num,
                pr_title=f"feat({random.choice(MODULES)}): improve {random.choice(SERVICES)} reliability",
                branch=f"feature/{random.choice(MODULES)}-update",
                status=status,
                new_findings_count=0 if status == PRGuardrailStatus.PASSED else random.randint(1, 4),
                highest_new_severity=None if status == PRGuardrailStatus.PASSED else random.choice(["Critical", "High", "Medium"]),
                new_endpoints_count=random.randint(0, 2),
                override_reason="Approved exception by Security Lead" if status == PRGuardrailStatus.OVERRIDDEN else "",
                tools_run="semgrep,gitleaks,trivy",
                scan_scope="diff",
                files_scanned=random.randint(2, 12),
                created_at=now - timedelta(days=random.randint(1, 15)),
                completed_at=now - timedelta(days=random.randint(1, 15), minutes=-3),
            )
            session.add(pr_scan)
            session.commit()
            session.refresh(pr_scan)

            if status != PRGuardrailStatus.PASSED:
                session.add(PRGuardrailFinding(
                    pr_scan_id=pr_scan.id,
                    tool="semgrep",
                    rule_id="security.audit.vulnerability",
                    title="Potential security regression in PR branch",
                    file_path=f"src/{random.choice(MODULES)}.ts",
                    line_start=random.randint(20, 100),
                    severity=pr_scan.highest_new_severity or "High",
                    ignore_status=IgnoreStatus.REQUESTED if status == PRGuardrailStatus.BLOCKED else IgnoreStatus.APPROVED,
                    ignore_requested_by="dave.dev@acme.corp",
                    ignore_requested_reason="Development test artifact",
                ))
    session.commit()
    print("🎉 All randomized data successfully generated and committed!")


def main():
    parser = argparse.ArgumentParser(description="Generate randomized versatile demo data for Toleman")
    parser.add_argument("--count", type=int, default=150, help="Number of findings to generate (default: 150)")
    parser.add_argument("--clean", action="store_true", help="Wipe existing demo data before seeding")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    with Session(engine) as session:
        seed_random_data(session, count=args.count, clean=args.clean)


if __name__ == "__main__":
    main()
