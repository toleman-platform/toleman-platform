from datetime import datetime
from sqlmodel import Session, select

from app.models.models import Finding, FindingState, FindingStateLog, Scan, Target
from app.core.dedup import compute_dedup_hash
from app.core.scoring import compute_priority_score
from app.core.epss import fetch_epss_scores
from app.core.kev import fetch_kev_cve_set


def ingest_findings(session: Session, target: Target, scan: Scan, tool: str, branch: str, parsed: list[dict]) -> int:
    """
    Shared ingestion path for Push (CI/CD) and Pull (native) scans.

    Logic (per architecture spec):
      hash exists -> update last_seen
      hash new -> create Finding
      hash present in earlier scan of same target/branch but absent this run -> Mitigated
    """
    seen_hashes = set()

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

    session.commit()

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
