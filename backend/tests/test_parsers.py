from app.models.models import Severity
from app.scanners.parsers import (
    parse_checkov,
    parse_gitleaks,
    parse_gosec,
    parse_sarif,
    parse_semgrep,
    parse_tfsec,
    parse_trivy,
    parse_trivy_license,
)


def test_parse_semgrep_maps_fields():
    raw = {
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": "app/db.py",
                "start": {"line": 10},
                "end": {"line": 12},
                "extra": {"message": "possible SQLi", "severity": "ERROR", "lines": "query(x)"},
            }
        ]
    }
    out = parse_semgrep(raw)
    assert len(out) == 1
    f = out[0]
    assert f["rule_id"] == "python.lang.security.audit.sqli"
    assert f["file_path"] == "app/db.py"
    assert f["line_start"] == 10
    assert f["line_end"] == 12
    assert f["severity"] == Severity.HIGH


def test_parse_semgrep_empty_results():
    assert parse_semgrep({"results": []}) == []
    assert parse_semgrep({}) == []


def test_parse_gitleaks_maps_secret_as_high():
    raw = [{"RuleID": "aws-key", "File": "config.py", "StartLine": 3, "Match": "AKIA..."}]
    out = parse_gitleaks(raw)
    assert len(out) == 1
    assert out[0]["severity"] == Severity.HIGH
    assert out[0]["rule_id"] == "aws-key"


def test_parse_trivy_vulnerabilities_and_misconfigs():
    raw = {
        "Results": [
            {
                "Target": "go.mod",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-1234", "Title": "bad thing", "Severity": "HIGH", "PkgName": "gin", "InstalledVersion": "1.0.0"}
                ],
                "Misconfigurations": [
                    {"ID": "AVD-1", "Title": "no user set", "Severity": "MEDIUM", "CauseMetadata": {"StartLine": 5, "EndLine": 6}}
                ],
            }
        ]
    }
    out = parse_trivy(raw)
    assert len(out) == 2
    vuln = next(f for f in out if f["cve_id"] == "CVE-2024-1234")
    assert vuln["severity"] == Severity.HIGH
    misconfig = next(f for f in out if f["rule_id"] == "AVD-1")
    assert misconfig["severity"] == Severity.MEDIUM
    assert misconfig["line_start"] == 5


def test_parse_gosec_extracts_start_line_from_range():
    raw = {"Issues": [{"rule_id": "G101", "details": "hardcoded creds", "file": "main.go", "line": "12-14", "severity": "HIGH", "code": "pw := \"x\""}]}
    out = parse_gosec(raw)
    assert out[0]["line_start"] == 12
    assert out[0]["severity"] == Severity.HIGH


def test_parse_sarif_extracts_location_and_level():
    raw = {
        "runs": [
            {
                "tool": {"driver": {"name": "MySASTTool", "rules": []}},
                "results": [
                    {
                        "ruleId": "no-eval",
                        "level": "error",
                        "message": {"text": "avoid eval()"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 7, "endLine": 7}}}
                        ],
                    }
                ],
            }
        ]
    }
    out = parse_sarif(raw)
    assert len(out) == 1
    assert out[0]["rule_id"] == "no-eval"
    assert out[0]["file_path"] == "src/app.js"
    assert out[0]["line_start"] == 7
    assert out[0]["severity"] == Severity.HIGH


def test_parse_sarif_no_runs():
    assert parse_sarif({}) == []


def test_parse_trivy_license_maps_each_severity_tier():
    raw = {
        "Results": [
            {
                "Target": "go.mod",
                "Licenses": [
                    {"Severity": "UNKNOWN", "Name": "Unlicense", "PkgName": "foo", "FilePath": "go.mod"},
                    {"Severity": "LOW", "Name": "MIT", "PkgName": "bar", "FilePath": "go.mod"},
                    {"Severity": "MEDIUM", "Name": "MPL-2.0", "PkgName": "baz", "FilePath": "go.mod"},
                    {"Severity": "HIGH", "Name": "AGPL-3.0", "PkgName": "qux", "FilePath": "go.mod"},
                    {"Severity": "CRITICAL", "Name": "GPL-3.0", "PkgName": "quux", "FilePath": "go.mod"},
                ],
            }
        ]
    }
    out = parse_trivy_license(raw)
    assert len(out) == 5

    by_pkg = {f["snippet"]: f for f in out}
    assert by_pkg["foo"]["severity"] == Severity.LOW  # UNKNOWN maps to LOW per _map_severity
    assert by_pkg["bar"]["severity"] == Severity.LOW
    assert by_pkg["baz"]["severity"] == Severity.MEDIUM
    assert by_pkg["qux"]["severity"] == Severity.HIGH
    assert by_pkg["quux"]["severity"] == Severity.CRITICAL

    gpl = by_pkg["quux"]
    assert gpl["rule_id"] == "license:GPL-3.0"
    assert gpl["title"] == "GPL-3.0 license detected in quux"
    assert gpl["file_path"] == "go.mod"
    assert gpl["cve_id"] is None
    assert gpl["line_start"] is None
    assert gpl["line_end"] is None


def test_parse_trivy_license_missing_licenses_array():
    raw = {"Results": [{"Target": "go.mod"}]}
    assert parse_trivy_license(raw) == []


def test_parse_trivy_license_empty_licenses_array():
    raw = {"Results": [{"Target": "go.mod", "Licenses": []}]}
    assert parse_trivy_license(raw) == []


def test_parse_trivy_license_empty_results():
    assert parse_trivy_license({}) == []


def test_parse_trivy_license_multiple_results():
    raw = {
        "Results": [
            {
                "Target": "go.mod",
                "Licenses": [
                    {"Severity": "LOW", "Name": "MIT", "PkgName": "foo", "FilePath": "go.mod"},
                ],
            },
            {
                "Target": "package-lock.json",
                "Licenses": [
                    {"Severity": "HIGH", "Name": "GPL-2.0", "PkgName": "bar", "FilePath": "package-lock.json"},
                    {"Severity": "CRITICAL", "Name": "AGPL-3.0", "PkgName": "baz", "FilePath": "package-lock.json"},
                ],
            },
        ]
    }
    out = parse_trivy_license(raw)
    assert len(out) == 3
    assert {f["file_path"] for f in out} == {"go.mod", "package-lock.json"}
    assert {f["rule_id"] for f in out} == {"license:MIT", "license:GPL-2.0", "license:AGPL-3.0"}


def test_parse_checkov_single_framework_dict():
    raw = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                    "file_path": "/main.tf",
                    "file_line_range": [10, 15],
                    "severity": "HIGH",
                    "resource": "aws_s3_bucket.this",
                }
            ],
            "passed_checks": [{"check_id": "CKV_AWS_1"}],
        },
    }
    out = parse_checkov(raw)
    assert len(out) == 1
    f = out[0]
    assert f["rule_id"] == "CKV_AWS_20"
    assert f["file_path"] == "main.tf"
    assert f["line_start"] == 10
    assert f["line_end"] == 15
    assert f["severity"] == Severity.HIGH
    assert f["snippet"] == "aws_s3_bucket.this"


def test_parse_checkov_multi_framework_list():
    raw = [
        {"check_type": "terraform", "results": {"failed_checks": [{"check_id": "CKV_AWS_20", "file_path": "/main.tf", "file_line_range": [1, 2]}]}},
        {"check_type": "kubernetes", "results": {"failed_checks": [{"check_id": "CKV_K8S_8", "file_path": "/deploy.yaml", "file_line_range": [3, 4]}]}},
    ]
    out = parse_checkov(raw)
    assert len(out) == 2
    assert {f["rule_id"] for f in out} == {"CKV_AWS_20", "CKV_K8S_8"}


def test_parse_checkov_no_severity_defaults_medium():
    raw = {"results": {"failed_checks": [{"check_id": "CKV_1", "file_path": "/a.tf", "file_line_range": [1, 1]}]}}
    out = parse_checkov(raw)
    assert out[0]["severity"] == Severity.MEDIUM


def test_parse_checkov_empty():
    assert parse_checkov({}) == []
    assert parse_checkov([]) == []


def test_parse_tfsec_maps_fields():
    raw = {
        "results": [
            {
                "long_id": "aws-s3-enable-bucket-encryption",
                "description": "Bucket does not have encryption enabled",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.this",
                "location": {"filename": "main.tf", "start_line": 4, "end_line": 9},
            }
        ]
    }
    out = parse_tfsec(raw)
    assert len(out) == 1
    f = out[0]
    assert f["rule_id"] == "aws-s3-enable-bucket-encryption"
    assert f["file_path"] == "main.tf"
    assert f["line_start"] == 4
    assert f["line_end"] == 9
    assert f["severity"] == Severity.HIGH
    assert f["snippet"] == "aws_s3_bucket.this"


def test_parse_tfsec_null_results():
    assert parse_tfsec({"results": None}) == []
    assert parse_tfsec({}) == []
