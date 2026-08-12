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
