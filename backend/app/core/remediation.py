"""Group findings into the upgrades that would actually close them (#247).

The findings list presents N rows against one package and leaves the reader
to work out that they collapse into a single version bump. On this repo's own
requirements.txt that was the difference between reading 34 rows and taking 6
actions.

This answers the question the list does not: **what is the smallest set of
upgrades that closes the most findings, and what does each one leave behind?**

Two properties this must not get wrong, both about overstating:

* The recommended version is the *lowest* version that clears every grouped
  CVE; the smallest upgrade that does the job, not the newest release. A
  recommendation to jump further than necessary gets ignored, and rightly.
* `unresolved` is reported explicitly. If three of five CVEs on a package
  have a fix and two do not, "upgrade to X fixes 3 issues" is true and
  "upgrading fixes this package" is not. Never round up.

The same rule applies to the *empty* answer, which is why
`enrichment_coverage` exists alongside the grouping. An empty plan has at
least two unrelated causes -- nothing has been looked up for these CVEs yet,
or advisories were looked up and none of them names a fixed version -- and
only the second is a statement about fixes. A caller that cannot tell them
apart can only guess, and the guess that gets rendered is invariably the
confident one ("no upgrade resolves these"), asserted over data that was
never measured. So the plan is returned with the counts behind it:
how many CVE-bearing open findings there are, how many have an enrichment
row at all, how many of those rows came from an advisory record, and how
many carry any fixed-version data.
"""

import json
from collections import defaultdict

from sqlmodel import Session, select

from app.models.models import CveEnrichment, Finding, FindingState


def parse_version(raw: str) -> tuple:
    """Comparable form of a version string.

    Numeric segments compare numerically so 0.9.0 sorts below 0.10.0, which
    plain string ordering gets backwards. Non-numeric segments (rc tags,
    dates, commit-ish) fall back to string comparison, tagged so the two
    never compare against each other and raise.
    """
    parts = []
    for chunk in str(raw).replace("-", ".").split("."):
        parts.append((0, int(chunk), "") if chunk.isdigit() else (1, 0, chunk))
    return tuple(parts)


def _fixes_by_package(row: CveEnrichment) -> dict[str, list[str]]:
    """package name -> fixed versions this advisory offers for it."""
    if not row.fixed_versions:
        return {}
    try:
        entries = json.loads(row.fixed_versions)
    except (TypeError, ValueError):
        return {}
    out: dict[str, list[str]] = defaultdict(list)
    for entry in entries or []:
        package = entry.get("package")
        fixed = entry.get("fixed")
        if package and fixed:
            out[str(package)].append(str(fixed))
    return out


def _open_cve_findings(session: Session, target_id: int) -> list[Finding]:
    """This target's open findings that carry a CVE id.

    The whole feature is keyed off `Finding.cve_id`, so a finding without one
    (SAST, secrets, IaC, licence) is invisible to it by construction. That is
    also why the coverage counts start from this population rather than from
    every open finding: "no fix plan" on a target whose findings are all SAST
    is a different fact from "no fix plan" on 40 open CVEs.
    """
    return list(
        session.exec(
            select(Finding).where(
                Finding.target_id == target_id,
                Finding.state == FindingState.OPEN,
                Finding.cve_id.is_not(None),
            )
        ).all()
    )


def _enrichment_by_cve(session: Session, findings: list[Finding]) -> dict[str, CveEnrichment]:
    """Cached enrichment rows for the CVEs these findings name, by CVE id.

    A CVE with no row here has never been looked up. That absence is exactly
    what `enrichment_coverage` reports: a missing row is *unmeasured*, and
    must never be read as "this CVE has no fix".
    """
    if not findings:
        return {}
    rows = session.exec(
        select(CveEnrichment).where(CveEnrichment.cve_id.in_({f.cve_id for f in findings}))
    ).all()
    return {r.cve_id: r for r in rows}


def enrichment_coverage(findings: list[Finding], by_cve: dict[str, CveEnrichment]) -> dict:
    """How much is actually known about the CVEs an empty plan came from.

    Returns::

        {"cve_findings": 40,            # open findings carrying a CVE id
         "distinct_cves": 31,           # distinct CVE ids among them
         "enriched_findings": 12,       # ...whose CVE has an enrichment row
         "findings_with_advisory": 9,   # ...whose row came from an OSV record
         "findings_with_fix_data": 0}   # ...whose row names a fixed version

    Counted per finding rather than per CVE because the plan is counted per
    finding too ("fixes 3 findings"), so the two sets of numbers are directly
    comparable; `distinct_cves` is carried alongside for the lookup-shaped
    question ("how many CVEs would have to be fetched").

    `enriched_findings` counts rows, not answers. `get_cve_enrichment` caches
    a both-sources-not-found row when an upstream lookup fails, so a row is
    proof that something was attempted, and `findings_with_advisory` is the
    narrower claim that OSV actually returned a record for that CVE. Only
    `findings_with_fix_data == 0` *with* `findings_with_advisory > 0` is a
    measured "no fixed version is published"; the other zeroes are silence.
    """
    enriched = 0
    with_advisory = 0
    with_fix_data = 0
    for finding in findings:
        row = by_cve.get(finding.cve_id)
        if row is None:
            continue
        enriched += 1
        if row.osv_found:
            with_advisory += 1
        # Same parse the grouping uses, so "has fix data" here cannot drift
        # from "produced a plan" there: a row whose JSON is unparseable, or
        # whose entries carry no `fixed`, counts as no fix data in both.
        if _fixes_by_package(row):
            with_fix_data += 1
    return {
        "cve_findings": len(findings),
        "distinct_cves": len({f.cve_id for f in findings}),
        "enriched_findings": enriched,
        "findings_with_advisory": with_advisory,
        "findings_with_fix_data": with_fix_data,
    }


def remediation_plan(session: Session, target_id: int) -> dict:
    """The per-package upgrades for a target, plus the coverage behind them.

    ``{"plans": [...], "coverage": {...}}`` -- `plans` is exactly what
    `group_remediations` returns, `coverage` is `enrichment_coverage`. Both
    are derived from a single pass over the same findings and enrichment
    rows, so the counts always describe the plan they ship with.

    `plans == []` and `coverage["findings_with_fix_data"] == 0` are the same
    condition by construction: a finding with parseable fix data always
    produces a bucket, and a bucket with anything in `fixed` always produces
    a plan.
    """
    findings = _open_cve_findings(session, target_id)
    by_cve = _enrichment_by_cve(session, findings)
    return {
        "plans": _group_by_package(findings, by_cve),
        "coverage": enrichment_coverage(findings, by_cve),
    }


def group_remediations(session: Session, target_id: int) -> list[dict]:
    """Open findings for a target, grouped into per-package upgrades.

    Returns, most findings-closed first::

        [{"package": "starlette",
          "ecosystem": "PyPI",
          "upgrade_to": "0.40.0",
          "fixes": [{"cve_id": ..., "finding_id": ..., "severity": ...}],
          "fixes_count": 3,
          "unresolved": [{"cve_id": ..., "finding_id": ...}],
          "highest_severity": "High"}]

    A package appears only if at least one of its findings has a known fix;
    a package where nothing is fixable is not a remediation, it is just bad
    news, and belongs in the findings list rather than an action card.
    """
    findings = _open_cve_findings(session, target_id)
    return _group_by_package(findings, _enrichment_by_cve(session, findings))


def _group_by_package(findings: list[Finding], by_cve: dict[str, CveEnrichment]) -> list[dict]:
    """The grouping itself, over findings and enrichment rows already loaded."""
    if not findings:
        return []

    # package -> {"fixed": [(finding, [versions])], "unfixed": [finding]}
    buckets: dict[str, dict] = defaultdict(lambda: {"fixed": [], "unfixed": [], "ecosystem": None})

    for finding in findings:
        row = by_cve.get(finding.cve_id)
        fixes = _fixes_by_package(row) if row else {}
        if not fixes:
            # No advisory, or an advisory with no fix. Either way there is no
            # package name to group under from OSV, so this finding cannot be
            # attributed to an upgrade. Deliberately dropped rather than
            # bucketed under a guessed package: a wrong grouping would send
            # someone to upgrade something unrelated.
            continue
        for package, versions in fixes.items():
            bucket = buckets[package]
            bucket["fixed"].append((finding, versions))
            if bucket["ecosystem"] is None and row is not None:
                bucket["ecosystem"] = _ecosystem_for(row, package)

    # Second pass: within each package, any open finding whose advisory names
    # that package but offers no fixed version is genuinely left behind by the
    # upgrade, and has to be reported.
    for finding in findings:
        row = by_cve.get(finding.cve_id)
        if row is None or _fixes_by_package(row):
            continue
        for package, bucket in buckets.items():
            if row.osv_found and _advisory_mentions(row, package):
                bucket["unfixed"].append(finding)

    results = []
    for package, bucket in buckets.items():
        if not bucket["fixed"]:
            continue
        # The lowest version that clears every grouped CVE: take each CVE's
        # own lowest fix, then the highest of those. Anything lower leaves at
        # least one CVE open, and anything higher is a bigger upgrade than
        # the evidence supports.
        per_cve_minimums = [min(versions, key=parse_version) for _, versions in bucket["fixed"]]
        upgrade_to = max(per_cve_minimums, key=parse_version)

        fixes = [
            {
                "cve_id": f.cve_id,
                "finding_id": f.id,
                "severity": _severity_str(f.severity),
                "title": f.title,
            }
            for f, _ in bucket["fixed"]
        ]
        results.append({
            "package": package,
            "ecosystem": bucket["ecosystem"],
            "upgrade_to": upgrade_to,
            "fixes": fixes,
            "fixes_count": len(fixes),
            "unresolved": [
                {"cve_id": f.cve_id, "finding_id": f.id, "severity": _severity_str(f.severity)}
                for f in bucket["unfixed"]
            ],
            "highest_severity": _highest(fixes),
        })

    # Most findings closed first; ties broken by severity, so a single
    # Critical outranks a single Low.
    results.sort(key=lambda r: (r["fixes_count"], _severity_rank(r["highest_severity"])), reverse=True)
    return results


SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}


def _severity_rank(name: str | None) -> int:
    return SEVERITY_RANK.get(name or "", 0)


def _severity_str(severity) -> str:
    return getattr(severity, "value", severity)


def _highest(fixes: list[dict]) -> str | None:
    if not fixes:
        return None
    return max((f["severity"] for f in fixes), key=_severity_rank)


def _ecosystem_for(row: CveEnrichment, package: str) -> str | None:
    try:
        for entry in json.loads(row.fixed_versions or "[]") or []:
            if entry.get("package") == package:
                return entry.get("ecosystem")
    except (TypeError, ValueError):
        pass
    return None


def _advisory_mentions(row: CveEnrichment, package: str) -> bool:
    """Does this advisory name `package` at all, fixed or not?

    Conservative: an advisory we cannot parse is treated as not mentioning
    the package, so a parse failure under-reports `unresolved` rather than
    inventing a blocker against an upgrade that may be fine.
    """
    try:
        entries = json.loads(row.fixed_versions or "[]") or []
    except (TypeError, ValueError):
        return False
    return any(e.get("package") == package for e in entries)
