import logging
from sqlmodel import Session, select

from app.models.models import Finding, FindingState, FindingStateLog, NotificationEventType, PlatformConfig, Scan, ScoringSignal, Severity, Target
from app.core.dedup import compute_dedup_hash
from app.core.cve_enrichment import warm_cve_enrichment
from app.core.scoring import compute_priority_score
from app.core.scoring_config import cvss_for_enrichment, enrichment_map, workspace_scoring_weights
from app.core.fixability import UNKNOWN, fixability_for_enrichment
from app.core.epss import fetch_epss_scores
from app.core.kev import fetch_kev_cve_set
from app.core.crypto import decrypt_secret
from app.core.jira_integration import create_jira_ticket_for_finding, jira_configured
from app.core.notifications import dispatch_notification
from app.core.siem_export import send_finding_to_siem
from app.core.fp_learning import apply_auto_suppression, find_matching_rule
from app.core.time import utcnow

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
    finding's severity meets that threshold. Best-effort; a Jira outage or
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


def _maybe_export_to_siem(session: Session, target: Target, finding: Finding) -> None:
    """Issue #114: fires a real webhook POST when PlatformConfig.siem_webhook_url
    is set and this new finding's severity meets siem_export_severity. Same
    best-effort philosophy as the Jira hook above; a SIEM webhook outage
    must not fail the whole ingestion/scan."""
    config = session.exec(select(PlatformConfig)).first()
    if not config or not config.siem_webhook_url or not config.siem_export_severity:
        return
    if not _meets_auto_create_threshold(finding.severity, config.siem_export_severity):
        return

    try:
        webhook_url = decrypt_secret(config.siem_webhook_url)
        ok, result = send_finding_to_siem(webhook_url, finding, target)
    except Exception:
        logger.exception("SIEM export failed for finding %s", finding.id)
        return

    if not ok:
        logger.warning("SIEM export failed for finding %s: %s", finding.id, result)


def _maybe_notify_new_finding(session: Session, target: Target, finding: Finding) -> None:
    """Issue #73 notification dispatch, same hook point as #74's Jira
    auto-create above: fires for every net-new Finding right after it gets a
    real id. Two independent triggers can both fire for the same finding
    (e.g. a Critical finding that's also KEV-listed); each is its own
    NotificationEventType/preference, not a single combined event, so a user
    can opt into "tell me about KEV CVEs" without also getting every
    Critical SAST finding. Best-effort, same as the Jira hook: a delivery
    failure must never break ingestion.
    """
    try:
        if finding.severity == Severity.CRITICAL:
            dispatch_notification(
                session,
                workspace_id=target.workspace_id,
                event_type=NotificationEventType.CRITICAL_FINDING,
                subject=f"New critical finding: {finding.title or finding.rule_id}",
                detail=f"{target.name} · {finding.tool} · {finding.file_path}"
                + (f":{finding.line_start}" if finding.line_start else ""),
            )
        if finding.kev_listed:
            dispatch_notification(
                session,
                workspace_id=target.workspace_id,
                event_type=NotificationEventType.KEV_CVE,
                subject=f"KEV-listed CVE affects {target.name}: {finding.cve_id}",
                detail=f"{finding.title or finding.rule_id} · {finding.tool} · {finding.file_path}"
                + (f":{finding.line_start}" if finding.line_start else ""),
            )
        if finding.tool == "osv-malware":
            # Issue #179: a malicious dependency is the sharpest case of the
            # "distinct event" reasoning above; someone who wants to be paged
            # for a compromised dependency must not also get every Critical
            # SAST finding (and vice versa). See the enum's own docstring.
            dispatch_notification(
                session,
                workspace_id=target.workspace_id,
                event_type=NotificationEventType.MALICIOUS_PACKAGE,
                subject=f"Malicious package detected: {finding.title}",
                detail=f"{target.name} · {finding.rule_id}",
            )
    except Exception:
        logger.exception("Notification dispatch failed for finding %s", finding.id)


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

    # (#201) This workspace's scoring weights, resolved once for the whole
    # run rather than per finding; an unconfigured workspace gets the
    # shipped baseline, which scores identically to before #201 existed.
    weights = workspace_scoring_weights(session, target.workspace_id)

    # The CVSS-exploitability and fixability signals read the CveEnrichment
    # cache, whose only other writer is a human opening a finding's detail
    # view. Left at that, those signals would fire only for CVEs somebody
    # had already browsed -- so this warms the cache for the CVEs in this
    # batch, but ONLY when the workspace actually weights one of them above
    # zero. On the shipped baseline (both 0.0) nothing is fetched and this
    # run makes exactly the network calls it made before #201; the cost
    # arrives with the feature rather than with the upgrade.
    #
    # Deliberately before the loop: get_cve_enrichment commits its own row,
    # and running that partway through would commit half-built Finding rows
    # with it. Nothing of this run's is in the session yet at this point.
    if cve_ids and any(
        weights.get(signal, 0.0) > 0
        for signal in (ScoringSignal.CVSS_EXPLOITABILITY, ScoringSignal.FIXABILITY)
    ):
        warm_cve_enrichment(session, cve_ids)

    # Read after the warm-up so this run's findings are scored against what
    # it just fetched. Still only a cache read: a CVE the warm-up could not
    # resolve (upstream down, or beyond this run's lookup budget) leaves
    # both signals unestablished, which contributes nothing rather than
    # subtracting anything, and a later scan re-scores it upward once the
    # data lands. The failsafe direction.
    enrichments = enrichment_map(session, cve_ids)

    def score_for(severity, finding_cve_id, epss_score, kev_listed) -> int:
        """One finding's priority, from this run's weights and signals.

        Shared by the create and the re-score paths below so a finding
        cannot be scored one way on first sight and another way on the next,
        which is the whole failure this closes.
        """
        enrichment = enrichments.get(finding_cve_id) if finding_cve_id else None
        return compute_priority_score(
            severity,
            target.criticality_weight,
            epss_score=epss_score,
            kev_listed=kev_listed,
            cvss=cvss_for_enrichment(enrichment),
            cve_id=finding_cve_id,
            target_label=target.label,
            target_environment=target.environment,
            target_owner=target.owner,
            fixability=fixability_for_enrichment(enrichment) if finding_cve_id else UNKNOWN,
            weights=weights,
        )

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
            # creation time on rescans, re-fetching per-finding on every rescan
            # isn't worth the network cost; MVP tradeoff, staleness is acceptable.
            existing.last_seen = utcnow()
            existing.scan_id = scan.id
            # (#201) Re-score every time a scan observes the finding again.
            #
            # priority_score used to be write-once at creation, which was
            # survivable while the formula was three hardcoded constants and
            # actively broken once it became configurable: after a weight
            # change the backlog would hold two scoring regimes at once,
            # `ORDER BY priority_score` would be comparing numbers computed
            # under different rules, and the detail view's `stale` flag
            # would never clear. Worse than the upgrade-time re-rank this
            # issue works hardest to avoid, because it never converges.
            #
            # Cheap: the weights, the target metadata and the enrichment
            # rows are all already in hand, and the stored epss/kev are
            # reused rather than re-fetched, so this adds no queries and no
            # network calls to the rescan path.
            existing.priority_score = score_for(
                existing.severity, existing.cve_id, existing.epss_score, existing.kev_listed
            )
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
            priority_score=score_for(severity, finding_cve_id, epss_score, kev_listed),
            branch=branch,
            cve_id=finding_cve_id,
            epss_score=epss_score,
            kev_listed=kev_listed,
        )
        session.add(finding)
        newly_created.append(finding)

    session.commit()

    # False-positive auto-suppression (issue #76); runs before the Jira/
    # notification hooks below, on purpose: a finding matching a learned
    # false-positive rule (same rule_id+tool+file basename previously
    # triaged FALSE_POSITIVE, anywhere in this workspace; see
    # app.core.fp_learning) is not a real net-new alert, so it must not
    # trigger a Jira ticket or a critical/KEV notification. It's still
    # created as a real Finding row (not silently dropped) so it stays
    # visible/auditable/revertable in the normal findings UI, just already
    # in the FALSE_POSITIVE state instead of Open.
    for finding in newly_created:
        session.refresh(finding)
        rule = find_matching_rule(session, target.workspace_id, finding.rule_id, finding.tool, finding.file_path)
        if rule:
            apply_auto_suppression(session, rule, finding)
    session.commit()

    # Auto-create Jira tickets for net-new findings meeting the configured
    # severity threshold (issue #74 v1); after commit so each finding has
    # a real id to reference/link. Best-effort, never blocks ingestion.
    for finding in newly_created:
        session.refresh(finding)
        if finding.state == FindingState.FALSE_POSITIVE:
            continue  # auto-suppressed above, not a real net-new alert
        _maybe_auto_create_jira_ticket(session, finding)
        _maybe_export_to_siem(session, target, finding)
        _maybe_notify_new_finding(session, target, finding)

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
    scan.completed_at = utcnow()
    session.add(scan)
    session.commit()

    return len(parsed)


def _transition(session: Session, finding: Finding, to_state: FindingState, reason: str, actor: str = "system"):
    log = FindingStateLog(finding_id=finding.id, from_state=finding.state, to_state=to_state, reason=reason, actor=actor)
    finding.state = to_state
    if to_state == FindingState.MITIGATED:
        finding.mitigated_at = utcnow()
    session.add(finding)
    session.add(log)
