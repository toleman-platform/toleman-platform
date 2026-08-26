# Security Policy

Toleman is a security product, so a vulnerability here can affect the
security posture of every deployment that relies on it. Reports are welcome
and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** A public
report is visible to everyone, including anyone who would use it, before
there is a fix to upgrade to.

Instead, use GitHub's private vulnerability reporting on this repository:

> **Security** tab → **Report a vulnerability**

That opens a private advisory visible only to the maintainers. If you cannot
use it, email **shivanshu.0811@gmail.com** with "SECURITY" in the subject.

## What to include

A report is easiest to act on when it contains:

- What an attacker can achieve, not only what is technically wrong
- The affected component (backend API, frontend, MCP server, scanner
  runner, PR Guardrail, GitHub App integration) and version or commit
- Steps to reproduce, ideally a minimal case
- Any prerequisites, authentication, a particular role, a specific
  configuration

## What to expect

- **Acknowledgement within 3 working days.** If you have not heard back,
  please assume the message was missed and send a follow-up.
- An assessment of severity and impact, shared with you.
- A fix developed privately, released, and disclosed via a GitHub Security
  Advisory once a version containing it is available.
- Credit in the advisory, unless you would rather stay anonymous.

This is a small project without a paid bounty programme. What is offered is
a prompt response, a real fix, and public credit.

## Scope

In scope: this repository, the backend API, the frontend, the MCP server,
the scanner runner and its sandboxing, PR Guardrail, the GitHub App
integration, authentication and session handling, secret storage and
encryption, and the published container images.

Out of scope:

- Vulnerabilities in the bundled third-party scanners themselves (Trivy,
  Semgrep, Gitleaks, gosec, ModelScan). Report those upstream; see NOTICE
  for each project. If Toleman *invokes* one unsafely, that is in scope.
- Findings that require an attacker to already hold administrator
  credentials on the deployment.
- The known-insecure local development defaults (`ADMIN_PASSWORD`,
  `SESSION_SECRET`, `WORKSPACE_API_KEY`). These are documented, and
  `validate_production_secrets()` refuses to start a non-local deployment
  that still uses them. A way to *bypass* that check is very much in scope.

## Deploying Toleman securely

If you are running Toleman rather than auditing it, the essentials:

- Set `ENVIRONMENT` to something other than `local`, which enforces that
  `SESSION_SECRET` and `ADMIN_PASSWORD` are changed from their defaults.
- Set `PLATFORM_ENCRYPTION_KEY` explicitly. Without it a fresh key is
  generated per process, and every previously encrypted secret (GitHub App
  credentials, Slack/Jira/SIEM webhooks, the AI provider key) becomes
  undecryptable on restart.
- Set `COOKIE_SECURE=True` behind TLS.
- Change the seeded admin account's password before exposing the instance.
