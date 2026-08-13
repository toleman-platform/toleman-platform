from pathlib import Path

from app.scanners.runner import normalize_file_path


def test_strips_scan_scoped_clone_dir_prefix():
    repo_path = Path("/tmp/osp-scans/govwa-abc123")
    absolute = "/tmp/osp-scans/govwa-abc123/vulnerability/idor/idor.go"
    assert normalize_file_path(absolute, repo_path) == "vulnerability/idor/idor.go"


def test_same_relative_file_normalizes_identically_across_different_scan_dirs():
    """The actual bug: two scans of the same file, in two different
    scan-scoped clone dirs, must normalize to the same relative path -
    otherwise their dedup_hash never matches and dedup silently breaks."""
    file_a = "/tmp/osp-scans/govwa-scan1/util/database/database.go"
    file_b = "/tmp/osp-scans/govwa-scan2/util/database/database.go"
    normalized_a = normalize_file_path(file_a, Path("/tmp/osp-scans/govwa-scan1"))
    normalized_b = normalize_file_path(file_b, Path("/tmp/osp-scans/govwa-scan2"))
    assert normalized_a == normalized_b == "util/database/database.go"


def test_already_relative_path_passed_through():
    assert normalize_file_path("go.mod", Path("/tmp/osp-scans/govwa-abc123")) == "go.mod"


def test_empty_path_passed_through():
    assert normalize_file_path("", Path("/tmp/osp-scans/govwa-abc123")) == ""


def test_path_outside_repo_root_passed_through_unchanged():
    outside = "/etc/passwd"
    assert normalize_file_path(outside, Path("/tmp/osp-scans/govwa-abc123")) == outside
