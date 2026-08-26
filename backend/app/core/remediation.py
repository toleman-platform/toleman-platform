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
    findings = session.exec(
        select(Finding).where(
            Finding.target_id == target_id,
            Finding.state == FindingState.OPEN,
            Finding.cve_id.is_not(None),
        )
    ).all()
    if not findings:
        return []

    rows = session.exec(
        select(CveEnrichment).where(CveEnrichment.cve_id.in_({f.cve_id for f in findings}))
    ).all()
    by_cve = {r.cve_id: r for r in rows}

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
