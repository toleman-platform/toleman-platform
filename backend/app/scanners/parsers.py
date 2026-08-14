"""Normalize raw tool output into the platform's standard Finding schema.

Each parser returns a list of dicts with keys:
  rule_id, title, description, file_path, line_start, line_end, severity, snippet, cve_id
"""
from app.models.models import Severity


def _map_severity(raw: str) -> Severity:
    raw = (raw or "").strip().lower()
    if raw in ("critical",):
        return Severity.CRITICAL
    if raw in ("high", "error"):
        return Severity.HIGH
    if raw in ("medium", "moderate", "warning"):
        return Severity.MEDIUM
    if raw in ("low", "note", "info", "informational", "unknown"):
        return Severity.LOW
    return Severity.INFO


def parse_semgrep(raw: dict) -> list[dict]:
    out = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        out.append({
            "rule_id": r.get("check_id", "unknown"),
            "title": extra.get("message", r.get("check_id", ""))[:200],
            "description": extra.get("message", ""),
            "file_path": r.get("path", ""),
            "line_start": r.get("start", {}).get("line"),
            "line_end": r.get("end", {}).get("line"),
            "severity": _map_severity(extra.get("severity", "")),
            "snippet": extra.get("lines", ""),
            "cve_id": None,
        })
    return out


def parse_gitleaks(raw: list) -> list[dict]:
    out = []
    for r in raw:
        out.append({
            "rule_id": r.get("RuleID", "secret"),
            "title": f"Secret detected: {r.get('RuleID', 'secret')}",
            "description": r.get("Description", ""),
            "file_path": r.get("File", ""),
            "line_start": r.get("StartLine"),
            "line_end": r.get("EndLine"),
            "severity": Severity.HIGH,
            "snippet": r.get("Match", ""),
            "cve_id": None,
        })
    return out


def parse_trivy(raw: dict) -> list[dict]:
    out = []
    for result in raw.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            out.append({
                "rule_id": v.get("VulnerabilityID", "unknown"),
                "title": v.get("Title", v.get("VulnerabilityID", ""))[:200],
                "description": v.get("Description", ""),
                "file_path": target,
                "line_start": None,
                "line_end": None,
                "severity": _map_severity(v.get("Severity", "")),
                "snippet": f"{v.get('PkgName','')}@{v.get('InstalledVersion','')}",
                "cve_id": v.get("VulnerabilityID"),
            })
        for m in result.get("Misconfigurations", []) or []:
            out.append({
                "rule_id": m.get("ID", "unknown"),
                "title": m.get("Title", "")[:200],
                "description": m.get("Description", ""),
                "file_path": target,
                "line_start": (m.get("CauseMetadata") or {}).get("StartLine"),
                "line_end": (m.get("CauseMetadata") or {}).get("EndLine"),
                "severity": _map_severity(m.get("Severity", "")),
                "snippet": "",
                "cve_id": None,
            })
    return out


def parse_trivy_license(raw: dict) -> list[dict]:
    """Trivy license-scan output (`trivy fs --scanners license`).

    Distinct from parse_trivy: license results live under Results[].Licenses[]
    rather than Vulnerabilities/Misconfigurations.
    """
    out = []
    for result in raw.get("Results", []):
        target = result.get("Target", "")
        for lic in result.get("Licenses", []) or []:
            name = lic.get("Name", "unknown")
            pkg_name = lic.get("PkgName", "")
            file_path = lic.get("FilePath") or target
            out.append({
                "rule_id": f"license:{name}",
                "title": f"{name} license detected in {pkg_name}"[:200] if pkg_name else f"{name} license detected"[:200],
                "description": f"License {name} detected for package {pkg_name}".strip(),
                "file_path": file_path,
                "line_start": None,
                "line_end": None,
                "severity": _map_severity(lic.get("Severity", "")),
                "snippet": pkg_name,
                "cve_id": None,
            })
    return out


def parse_trivy_sbom(raw: dict) -> list[dict]:
    """Trivy CycloneDX SBOM output (`trivy fs --format cyclonedx`).

    Distinct schema from the JSON-format parsers above: a flat CycloneDX 1.x
    `components` array rather than Results[].Vulnerabilities[]. Only
    type == "library" entries are real dependencies -- "application"
    components describe the manifest file itself (e.g. requirements.txt)
    and aren't a package. Package type/ecosystem (pip, npm, gomod, ...)
    comes from the CycloneDX property named "aquasecurity:trivy:PkgType".
    """
    out = []
    for c in raw.get("components", []):
        if c.get("type") != "library":
            continue
        package_type = ""
        for prop in c.get("properties", []) or []:
            if prop.get("name") == "aquasecurity:trivy:PkgType":
                package_type = prop.get("value", "")
                break
        out.append({
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "package_type": package_type,
            "purl": c.get("purl", ""),
        })
    return out


def parse_gosec(raw: dict) -> list[dict]:
    out = []
    for issue in raw.get("Issues", []):
        out.append({
            "rule_id": issue.get("rule_id", "unknown"),
            "title": issue.get("details", "")[:200],
            "description": issue.get("details", ""),
            "file_path": issue.get("file", ""),
            "line_start": int(issue.get("line", "0").split("-")[0] or 0) or None,
            "line_end": None,
            "severity": _map_severity(issue.get("severity", "")),
            "snippet": issue.get("code", ""),
            "cve_id": None,
        })
    return out


def parse_checkov(raw: dict | list) -> list[dict]:
    """Checkov JSON output (issue #75 IaC integration).

    Shape varies with how many IaC frameworks Checkov found files for in
    the scanned repo: a single dict (one framework, e.g. only Terraform
    present) or a list of per-framework dicts (Terraform + Kubernetes +
    ...). Normalize both to a flat list of "reports" before walking
    results.failed_checks -- only failed checks are findings; passed_checks
    are intentionally not surfaced as anything (there's no "informational
    passed control" concept in OSP's Finding model).
    """
    reports = raw if isinstance(raw, list) else [raw]
    out = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        results = report.get("results") or {}
        for check in results.get("failed_checks", []) or []:
            file_line_range = check.get("file_line_range") or [None, None]
            out.append({
                "rule_id": check.get("check_id", "unknown"),
                "title": (check.get("check_name") or check.get("check_id", ""))[:200],
                "description": check.get("check_name", ""),
                "file_path": check.get("file_path", "").lstrip("/"),
                "line_start": file_line_range[0] if file_line_range else None,
                "line_end": file_line_range[1] if len(file_line_range) > 1 else None,
                "severity": _map_severity(check.get("severity") or "medium"),
                "snippet": check.get("resource", ""),
                "cve_id": None,
            })
    return out


def parse_tfsec(raw: dict) -> list[dict]:
    """tfsec JSON output (`tfsec <path> --format json`), issue #75 IaC
    integration. `results` is null (not an empty list) when tfsec finds
    nothing, so this must tolerate `raw.get("results")` being `None`."""
    out = []
    for r in raw.get("results") or []:
        location = r.get("location") or {}
        out.append({
            "rule_id": r.get("long_id") or r.get("rule_id", "unknown"),
            "title": (r.get("description") or r.get("rule_description") or "")[:200],
            "description": r.get("description", ""),
            "file_path": location.get("filename", ""),
            "line_start": location.get("start_line"),
            "line_end": location.get("end_line"),
            "severity": _map_severity(r.get("severity", "")),
            "snippet": r.get("resource", ""),
            "cve_id": None,
        })
    return out


def parse_sarif(raw: dict) -> list[dict]:
    """Generic SARIF 2.1.0 parser — covers most CI-pushed SAST tool output."""
    out = []
    for run in raw.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "sarif")
        rules_index = {
            r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_meta = rules_index.get(rule_id, {})
            level = result.get("level") or rule_meta.get("defaultConfiguration", {}).get("level", "warning")
            locations = result.get("locations", [])
            file_path, line_start, line_end = "", None, None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line_start = region.get("startLine")
                line_end = region.get("endLine", line_start)
            out.append({
                "rule_id": rule_id,
                "title": (result.get("message", {}).get("text", rule_id))[:200],
                "description": result.get("message", {}).get("text", ""),
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "severity": _map_severity(level),
                "snippet": "",
                "cve_id": None,
                "tool_name": tool_name,
            })
    return out


# Shared by app/api/scans.py (synchronous "Pull" scan endpoint) and
# app/tasks/scan_tasks.py (async Celery scan task) -- both dispatch on
# tool name to pick the parser for runner.run_tool's raw output.
PARSER_MAP = {
    "semgrep": parse_semgrep,
    "gitleaks": parse_gitleaks,
    "trivy": parse_trivy,
    "trivy-license": parse_trivy_license,
    "trivy-sbom": parse_trivy_sbom,
    "gosec": parse_gosec,
    "checkov": parse_checkov,
    "tfsec": parse_tfsec,
}
