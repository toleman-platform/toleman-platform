"""Normalize raw tool output into the platform's standard Finding schema.

Each parser returns a list of dicts with keys:
  rule_id, title, description, file_path, line_start, line_end, severity, snippet, cve_id
"""
from app.core.github_dependency_graph import parse_spdx_packages
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


def parse_noseyparker(raw: list) -> list[dict]:
    """noseyparker report JSON (#255).

    Two shape differences from every other parser here:

    * The report is finding-oriented, not match-oriented: one entry per
      (rule, secret) with a `matches` list of every place it occurs. We emit
      one finding per match, so two files leaking the same key are two
      findings to triage rather than one that is half-fixed after the first
      edit.
    * Paths arrive absolute, under `matches[].provenance[].path`. Callers
      normalize against the repo root (runner.normalize_file_path), same as
      every other tool.

    Severity is HIGH across the board, matching parse_gitleaks: a committed
    credential is not a gradient. noseyparker carries a `score` field, but it
    was null on every match in the benchmark corpus, so deriving severity
    from it would be inventing a signal that is not there.
    """
    out = []
    for finding in raw or []:
        rule = finding.get("rule_name") or "secret"
        for match in finding.get("matches") or []:
            provenance = (match.get("provenance") or [{}])[0]
            path = provenance.get("path") or ""
            span = (match.get("location") or {}).get("source_span") or {}
            snippet = (match.get("snippet") or {}).get("matching") or ""
            out.append({
                "rule_id": rule,
                "title": f"Secret detected: {rule}",
                "description": "",
                "file_path": path,
                "line_start": (span.get("start") or {}).get("line"),
                "line_end": (span.get("end") or {}).get("line"),
                "severity": Severity.HIGH,
                # Truncated: this is the matched secret itself. It is already
                # stored for triage context, but an unbounded blob (a whole
                # PEM key) in a finding row, a PR comment and a SIEM export is
                # both noisy and needlessly wide exposure.
                "snippet": snippet[:200],
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


# Fallback ecosystem-from-purl map for the CycloneDX upload branch below,
# used only when the `aquasecurity:trivy:PkgType` property is absent (e.g.
# an SBOM produced by a tool other than Trivy). Deliberately not reused for
# the SPDX branch -- that goes through app.core.github_dependency_graph's own
# parse_spdx_packages (the same parser app.tasks.sbom_tasks.run_sbom_generation
# already uses for the automatic GitHub-dependency-graph union), which keeps
# GitHub-sourced components consistent regardless of which endpoint imported
# them, rather than this module growing a second, slightly different SPDX
# parser (issue #227).
PURL_TYPE_TO_PACKAGE_TYPE = {
    "pypi": "pip",
    "npm": "npm",
    "golang": "gomod",
    "maven": "maven",
    "gem": "gem",
    "cargo": "cargo",
    "composer": "composer",
    "nuget": "nuget",
}


def _purl_type(purl: str) -> str:
    """`pkg:pypi/anthropic@0.121.0` -> `pypi` (the segment between `pkg:` and
    the first `/`). Empty for anything that isn't a purl."""
    if not purl.startswith("pkg:"):
        return ""
    body = purl[len("pkg:"):]
    return body.split("/", 1)[0] if "/" in body else body


def parse_sbom_upload(raw: dict) -> list[dict]:
    """Parse an uploaded SBOM document into the standard
    {name, version, package_type, purl} component dicts (#227).

    Auto-detects the two supported JSON formats: CycloneDX (a top-level
    `components` array) and SPDX (a top-level `packages` array, or GitHub's
    `sbom` wrapper). CycloneDX package_type comes from the
    `aquasecurity:trivy:PkgType` property when present and otherwise falls
    back to the purl type; SPDX reuses
    app.core.github_dependency_graph.parse_spdx_packages so an uploaded
    GitHub SBOM parses identically to one fetched automatically.
    """
    doc = raw.get("sbom", raw)
    if "components" in doc:
        out = []
        for c in doc.get("components", []) or []:
            if c.get("type") != "library":
                continue
            package_type = ""
            for prop in c.get("properties", []) or []:
                if prop.get("name") == "aquasecurity:trivy:PkgType":
                    package_type = prop.get("value", "")
                    break
            purl = c.get("purl", "")
            if not package_type and purl:
                ptype = _purl_type(purl)
                package_type = PURL_TYPE_TO_PACKAGE_TYPE.get(ptype, ptype)
            out.append({
                "name": c.get("name", ""),
                "version": c.get("version", ""),
                "package_type": package_type,
                "purl": purl,
            })
        return out
    if "packages" in doc:
        # parse_spdx_packages expects GitHub's own {"sbom": {...}} wrapper
        # shape -- re-wrap here so a bare, unwrapped SPDX export (what a
        # user's own tooling produces) parses the same as one fetched
        # automatically, since `doc` above already unwrapped it if present.
        return parse_spdx_packages({"sbom": doc})
    return []

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


def parse_nuclei(raw: list[dict]) -> list[dict]:
    """Issue #72: nuclei `-jsonl` output -> standard Finding schema.

    Unlike every other parser here, this is ACTIVE-scan output (a real HTTP
    probe against a live endpoint), not a static source-code finding --
    `file_path` deliberately carries the discovered route/matched URL
    instead of a repo-relative path, since there's no source file for a
    runtime detection to point at. `cve_id` is pulled from nuclei's own
    classification metadata when the matched template maps to one (many
    nuclei templates -- default-login checks, misconfig detections -- have
    no CVE at all, which is fine; cve_id stays None rather than fabricated).
    """
    out = []
    for r in raw:
        info = r.get("info", {}) or {}
        classification = info.get("classification") or {}
        cve_id = classification.get("cve-id")
        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else None
        template_id = r.get("template-id", "unknown")
        name = info.get("name", template_id)
        matched_at = r.get("matched-at") or r.get("host", "")
        extracted = r.get("extracted-results") or []
        snippet = r.get("matcher-name") or (extracted[0] if extracted else "")
        out.append({
            "rule_id": template_id,
            "title": name[:200],
            "description": info.get("description", "") or name,
            "file_path": matched_at,
            "line_start": None,
            "line_end": None,
            "severity": _map_severity(info.get("severity", "")),
            "snippet": snippet,
            "cve_id": cve_id,
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
    passed control" concept in Rikugan's Finding model).
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


# Pickle opcodes that hand an attacker arbitrary code execution the instant
# a model is loaded. modelscan already rates these CRITICAL itself, but the
# floor is applied independently (issue #186): this is the one severity in
# the platform that must not be able to drift down through a settings file,
# a scanner-config change, or a future modelscan release retuning its own
# ratings. There is no such thing as a low-severity arbitrary-code primitive
# sitting in a checked-in weights file.
UNSAFE_DESERIALIZATION_OPERATORS = frozenset(
    {"system", "exec", "eval", "popen", "spawn", "fork", "run", "check_output", "call", "load", "loads"}
)
UNSAFE_DESERIALIZATION_MODULES = frozenset(
    {"os", "posix", "nt", "subprocess", "builtins", "__builtin__", "commands", "pty", "socket"}
)


def parse_modelscan(raw: dict) -> list[dict]:
    """modelscan JSON output (issue #186) -- unsafe operators found in
    serialized model files. Shape pinned against a real modelscan 0.8.8 run
    against a pickle whose __reduce__ calls os.system, not a guessed schema:

        {"summary": {...}, "issues": [{"description", "operator", "module",
         "source", "scanner", "severity"}], "errors": []}

    `source` is the model file, relative to the scanned path. There is no
    line number -- the finding is the file itself, which is why line_start
    and line_end are None rather than a fabricated 1.
    """
    out = []
    for issue in raw.get("issues") or []:
        operator = (issue.get("operator") or "").strip()
        module = (issue.get("module") or "").strip()

        severity = _map_severity(issue.get("severity", ""))
        if operator.lower() in UNSAFE_DESERIALIZATION_OPERATORS and module.lower() in UNSAFE_DESERIALIZATION_MODULES:
            severity = Severity.CRITICAL

        qualified = f"{module}.{operator}" if module and operator else (operator or "unknown")
        description = issue.get("description") or f"Unsafe operator {qualified} in a serialized model file"
        out.append({
            "rule_id": issue.get("scanner") or "modelscan",
            "title": f"Unsafe operator '{qualified}' in model file"[:200],
            "description": (
                f"{description} Loading this file executes the operator: deserializing an untrusted "
                f"model is arbitrary code execution, not a parsing step."
            ),
            "file_path": issue.get("source", ""),
            "line_start": None,
            "line_end": None,
            "severity": severity,
            "snippet": qualified,
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
    # Issue #189: same output shape as semgrep -- it *is* semgrep, just with
    # Rikugan's curated LLM ruleset -- so it reuses the parser verbatim.
    "semgrep-llm": parse_semgrep,
    "gitleaks": parse_gitleaks,
    "noseyparker": parse_noseyparker,
    "trivy": parse_trivy,
    "trivy-license": parse_trivy_license,
    "gosec": parse_gosec,
    "checkov": parse_checkov,
    "tfsec": parse_tfsec,
    "modelscan": parse_modelscan,
}
