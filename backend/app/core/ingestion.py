import logging
from datetime import datetime
from sqlmodel import Session, select

from app.models.models import Finding, FindingState, FindingStateLog, PlatformConfig, Scan, Severity, Target
from app.core.dedup import compute_dedup_hash
from app.core.scoring import compute_priority_score
from app.core.epss import fetch_epss_scores
from app.core.kev import fetch_kev_cve_set
from app.core.jira_integration import create_jira_ticket_for_finding, jira_configured

logger = logging.getLogger(__name__)

# Severity is ordered least->most severe (Severity enum declaration order);
# used to resolve "auto-create for X and anything at least as severe" from a
# single PlatformConfig.jira_auto_create_severity threshold.
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _meets_auto_create_threshold(severity: Severity, threshold: str) -> bool:
    try:
        threshold_severity = Severity(threshold)
    except ValueError:
        return False
    return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(threshold_severity)


def _maybe_auto_create_jira_ticket(session: Session, finding: Finding) -> None:
    """Issue #74 v1 auto-ticket-creation: fires a real Jira issue-creation
    call when PlatformConfig.jira_auto_create_severity is set and this new
    finding's severity meets that threshold. Best-effort -- a Jira outage or
    misconfiguration must not fail the whole ingestion/scan, so failures are
    logged, not raised."""
    config = session.exec(select(PlatformConfig)).first()
    if not config or not config.jira_auto_create_severity:
        return
    if not jira_configured(config):
        return
    if not _meets_auto_create_threshold(finding.severity, config.jira_auto_create_severity):
        return

    try:
        ok, result = create_jira_ticket_for_finding(config, finding)
    except Exception:
        logger.exception("Auto-create Jira ticket failed for finding %s", finding.id)
        return

    if not ok:
        logger.warning("Auto-create Jira ticket failed for finding %s: %s", finding.id, result)


def ingest_findings(session: Session, target: Target, scan: Scan, tool: str, branch: str, parsed: list[dict]) -> int:
    """
    Shared ingestion path for Push (CI/CD) and Pull (native) scans.

    Logic (per architecture spec):
      hash exists -> update last_seen
      hash new -> create Finding
      hash present in earlier scan of same target/branch but absent this run -> Mitigated
    """
    seen_hashes = set()
    # New Finding rows created this run, so the Jira auto-create hook below
    # can fire after commit (once each has a real primary key id).
    newly_created: list[Finding] = []

    # Batch EPSS/KEV lookups once per ingestion run (not per-finding) against the
    # distinct CVE IDs present in this parsed batch.
    cve_ids = sorted({item["cve_id"] for item in parsed if item.get("cve_id")})
    epss_scores = fetch_epss_scores(cve_ids) if cve_ids else {}
    kev_set = fetch_kev_cve_set() if cve_ids else set()

    for item in parsed:
        dedup_hash = compute_dedup_hash(
            rule_id=item["rule_id"],
            file_path=item["file_path"],
            tool=tool,
            snippet=item.get("snippet", ""),
            line_start=item.get("line_start"),
        )
        seen_hashes.add(dedup_hash)

        existing = session.exec(
            select(Finding).where(Finding.dedup_hash == dedup_hash, Finding.target_id == target.id, Finding.branch == branch)
        ).first()

        if existing:
            # epss_score/kev_listed are intentionally left as whatever was set at
            # creation time on rescans -- re-fetching per-finding on every rescan
            # isn't worth the network cost; MVP tradeoff, staleness is acceptable.
            existing.last_seen = datetime.utcnow()
            existing.scan_id = scan.id
            if existing.state == FindingState.MITIGATED:
                _transition(session, existing, FindingState.REOPENED, "reappeared in scan")
            session.add(existing)
            continue

        severity = item["severity"]
        finding_cve_id = item.get("cve_id")
        epss_score = epss_scores.get(finding_cve_id) if finding_cve_id else None
        kev_listed = finding_cve_id in kev_set if finding_cve_id else False
        finding = Finding(
            target_id=target.id,
            scan_id=scan.id,
            dedup_hash=dedup_hash,
            tool=tool,
            rule_id=item["rule_id"],
            title=item["title"] or item["rule_id"],
            description=item.get("description", ""),
            file_path=item["file_path"],
            line_start=item.get("line_start"),
            line_end=item.get("line_end"),
            severity=severity,
            priority_score=compute_priority_score(
                severity, target.criticality_weight, epss_score=epss_score, kev_listed=kev_listed
            ),
            branch=branch,
            cve_id=finding_cve_id,
            epss_score=epss_score,
            kev_listed=kev_listed,
        )
        session.add(finding)
        newly_created.append(finding)

    session.commit()

    # Auto-create Jira tickets for net-new findings meeting the configured
    # severity threshold (issue #74 v1) -- after commit so each finding has
    # a real id to reference/link. Best-effort, never blocks ingestion.
    for finding in newly_created:
        session.refresh(finding)
        _maybe_auto_create_jira_ticket(session, finding)

    # mark findings absent from this run (same target+branch+tool, still Open) as Mitigated
    stale = session.exec(
        select(Finding).where(
            Finding.target_id == target.id,
            Finding.branch == branch,
            Finding.tool == tool,
            Finding.state == FindingState.OPEN,
        )
    ).all()
    for f in stale:
        if f.dedup_hash not in seen_hashes:
            _transition(session, f, FindingState.MITIGATED, "not present in latest scan")

    session.commit()

    scan.findings_count = len(parsed)
    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    session.add(scan)
    session.commit()

    return len(parsed)


def _transition(session: Session, finding: Finding, to_state: FindingState, reason: str, actor: str = "system"):
    log = FindingStateLog(finding_id=finding.id, from_state=finding.state, to_state=to_state, reason=reason, actor=actor)
    finding.state = to_state
    if to_state == FindingState.MITIGATED:
        finding.mitigated_at = datetime.utcnow()
    session.add(finding)
    session.add(log)
