import base64
import subprocess
from pathlib import Path

import pytest

from app.scanners import runner
from app.scanners.runner import RepoCloneError, clone_error_message, clone_repo, normalize_file_path


def test_strips_scan_scoped_clone_dir_prefix():
    repo_path = Path("/tmp/toleman-scans/govwa-abc123")
    absolute = "/tmp/toleman-scans/govwa-abc123/vulnerability/idor/idor.go"
    assert normalize_file_path(absolute, repo_path) == "vulnerability/idor/idor.go"


def test_same_relative_file_normalizes_identically_across_different_scan_dirs():
    """The actual bug: two scans of the same file, in two different
    scan-scoped clone dirs, must normalize to the same relative path -
    otherwise their dedup_hash never matches and dedup silently breaks."""
    file_a = "/tmp/toleman-scans/govwa-scan1/util/database/database.go"
    file_b = "/tmp/toleman-scans/govwa-scan2/util/database/database.go"
    normalized_a = normalize_file_path(file_a, Path("/tmp/toleman-scans/govwa-scan1"))
    normalized_b = normalize_file_path(file_b, Path("/tmp/toleman-scans/govwa-scan2"))
    assert normalized_a == normalized_b == "util/database/database.go"


def test_already_relative_path_passed_through():
    assert normalize_file_path("go.mod", Path("/tmp/toleman-scans/govwa-abc123")) == "go.mod"


def test_empty_path_passed_through():
    assert normalize_file_path("", Path("/tmp/toleman-scans/govwa-abc123")) == ""


def test_path_outside_repo_root_passed_through_unchanged():
    outside = "/etc/passwd"
    assert normalize_file_path(outside, Path("/tmp/toleman-scans/govwa-abc123")) == outside


# --- Issue #54: git-clone argument injection + GitHub token leakage -------
#
# clone_repo used to build `["git", "clone", "--depth", "1", "--branch",
# branch, clone_url, dest]` with no validation and no "--" separator, so a
# repo_url starting with "-" (e.g. "--upload-pack=/bin/sh", controllable by
# any authenticated user who can create a Target) would be parsed by git as
# a flag instead of a positional URL. Separately, the GitHub token used to be
# embedded directly in clone_url, so a failed clone's CalledProcessError
# (whose str()/repr() includes the full argv) could leak the token into any
# log line or API response that surfaced it. These tests cover both fixes.
# (No real network access is used, subprocess.run is monkeypatched, same
# style as tests/test_scan_isolation.py.)


def _fake_run_recording(calls):
    """Stand-in for subprocess.run that records the argv/env it was called
    with (instead of hitting the network) and fakes a successful clone by
    creating the destination directory."""

    def _fake_run(cmd, check=False, capture_output=False, text=False, env=None):
        calls.append({"cmd": cmd, "env": env})
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return _fake_run


@pytest.fixture
def recorded_calls(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))
    monkeypatch.setattr(runner.subprocess, "run", _fake_run_recording(calls))
    return calls


def test_repo_url_starting_with_dash_rejected_before_subprocess(recorded_calls):
    """The core argument-injection fix: a repo_url that looks like a git flag
    must never reach subprocess.run at all."""
    with pytest.raises(RepoCloneError):
        clone_repo("--upload-pack=touch /tmp/pwned;", "main")
    assert recorded_calls == []


def test_non_https_url_rejected_before_subprocess(recorded_calls):
    with pytest.raises(RepoCloneError):
        clone_repo("git://github.com/acme/widgets.git", "main")
    assert recorded_calls == []


def test_non_github_host_rejected_before_subprocess(recorded_calls):
    with pytest.raises(RepoCloneError):
        clone_repo("https://evil.example.com/acme/widgets.git", "main")
    assert recorded_calls == []


def test_url_with_no_repo_path_rejected(recorded_calls):
    with pytest.raises(RepoCloneError):
        clone_repo("https://github.com/", "main")
    assert recorded_calls == []


def test_branch_starting_with_dash_rejected_before_subprocess(recorded_calls):
    with pytest.raises(RepoCloneError):
        clone_repo("https://github.com/acme/widgets.git", "--upload-pack=/bin/sh")
    assert recorded_calls == []


def test_clone_argv_has_double_dash_separator_before_positional_url(recorded_calls):
    """Even a validated, well-formed URL must be positionally separated from
    flags; defense in depth alongside the validation above."""
    clone_repo("https://github.com/acme/widgets.git", "main")

    assert len(recorded_calls) == 1
    cmd = recorded_calls[0]["cmd"]
    assert cmd[0] == "git"
    assert cmd[1] == "clone"
    assert "--" in cmd
    sep_index = cmd.index("--")
    url_index = cmd.index("https://github.com/acme/widgets.git")
    assert sep_index == url_index - 1, "URL must immediately follow the; separator"
    assert cmd[url_index + 1] == cmd[-1], "dest dir must immediately follow the URL"


def test_token_never_present_in_argv(recorded_calls):
    token = "ghp_supersecrettoken1234567890"  # noqa: S105 - test fixture, not a real credential
    clone_repo("https://github.com/acme/widgets.git", "main", github_token=token)

    cmd = recorded_calls[0]["cmd"]
    assert all(token not in str(part) for part in cmd)


def test_token_delivered_via_env_header_not_url(recorded_calls):
    """Token must be injected as an http.extraHeader via the environment
    (git's GIT_CONFIG_* mechanism), not embedded in the clone URL."""
    token = "ghp_supersecrettoken1234567890"  # noqa: S105
    clone_repo("https://github.com/acme/widgets.git", "main", github_token=token)

    cmd = recorded_calls[0]["cmd"]
    url_arg = next(part for part in cmd if part.startswith("https://"))
    assert url_arg == "https://github.com/acme/widgets.git"
    assert "x-access-token" not in url_arg
    assert "@" not in url_arg

    env = recorded_calls[0]["env"]
    # HTTP Basic, not Bearer; git's http backend rejects gho_ OAuth tokens
    # under Bearer (see clone_repo's docstring). The token must still never
    # appear in the header verbatim as a bare Bearer credential, and must
    # never reach the URL, which the assertions above cover.
    expected = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {expected}"
    assert env["GIT_CONFIG_KEY_0"] == "http.extraheader"
    # The decoded header still carries the token, so it must be confined to
    # the environment; never argv, where it would leak into str(exc) on a
    # failed clone. That is the property this test exists to protect.
    assert not any(token in part for part in cmd)


def test_no_token_env_vars_set_when_no_token_given(recorded_calls):
    clone_repo("https://github.com/acme/widgets.git", "main")
    env = recorded_calls[0]["env"]
    assert "GIT_CONFIG_VALUE_0" not in env


def test_called_process_error_never_carries_token(tmp_path, monkeypatch):
    """A failed clone's CalledProcessError, str(), .cmd, and .stderr; must
    never contain the token, since callers have historically surfaced these
    directly in API responses (app/api/scans.py, pr_guardrail_executor.py).

    Uses a transient failure (unresolvable host) deliberately. A *permanent*
    cause now raises RepoCloneError instead of CalledProcessError so Celery
    stops retrying it; that path's scrubbing is covered by
    test_clone_failure_diagnosis.py::test_token_is_scrubbed_before_classification.
    Git really does echo the credential-bearing URL in this message, which is
    why the scrub has to run before anything else touches stderr.
    """
    token = "ghp_supersecrettoken1234567890"  # noqa: S105

    def _failing_run(cmd, check=False, capture_output=False, text=False, env=None):
        raise subprocess.CalledProcessError(
            returncode=128,
            cmd=cmd,
            output="",
            stderr=(
                f"fatal: unable to access 'https://{token}@github.com/acme/widgets.git/': "
                "Could not resolve host: github.com"
            ),
        )

    monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))
    monkeypatch.setattr(runner.subprocess, "run", _failing_run)

    with pytest.raises(subprocess.CalledProcessError) as excinfo:
        clone_repo("https://github.com/acme/widgets.git", "main", github_token=token)

    exc = excinfo.value
    assert token not in str(exc)
    assert token not in repr(exc)
    assert token not in exc.stderr
    assert "***REDACTED***" in exc.stderr
    assert clone_error_message(exc) == "git clone failed (exit code 128)"


def test_repo_clone_error_message_is_safe_and_descriptive(recorded_calls):
    try:
        clone_repo("--upload-pack=/bin/sh", "main")
    except RepoCloneError as exc:
        assert clone_error_message(exc) == str(exc)
    else:
        pytest.fail("expected RepoCloneError")


# --- Issue #298: VPN/client-cert-gated target hosts -----------------------


def test_non_github_host_still_rejected_when_not_in_extra_clone_hosts(recorded_calls):
    with pytest.raises(RepoCloneError):
        clone_repo("https://gitlab.internal.corp/team/project.git", "main")
    assert recorded_calls == []


def test_extra_clone_hosts_allows_an_operator_configured_host(recorded_calls, monkeypatch):
    monkeypatch.setattr(runner.settings, "extra_clone_hosts", "gitlab.internal.corp")
    clone_repo("https://gitlab.internal.corp/team/project.git", "main")
    assert len(recorded_calls) == 1
    cmd = recorded_calls[0]["cmd"]
    assert "https://gitlab.internal.corp/team/project.git" in cmd


def test_github_token_never_sent_to_a_non_github_allowed_host(recorded_calls, monkeypatch):
    """The credential-leak fix: a workspace's GitHub PAT must never be
    attached when the target host isn't actually github.com, even though
    resolve_github_token has no idea what host it will be used against.

    Doesn't assert "no GIT_CONFIG_* env vars set at all": this sandbox's own
    git setup already has some ambient (GIT_CONFIG_COUNT=3 for its own
    github.com SSH rewriting, unrelated to this call), which clone_repo
    correctly leaves untouched when it has nothing of its own to add. The
    actual property under test is narrower and more direct: the token value
    itself must not appear anywhere in the env clone_repo built.
    """
    monkeypatch.setattr(runner.settings, "extra_clone_hosts", "gitlab.internal.corp")
    token = "ghp_supersecrettoken1234567890"  # noqa: S105
    clone_repo("https://gitlab.internal.corp/team/project.git", "main", github_token=token)

    env = recorded_calls[0]["env"]
    assert all(token not in str(v) for v in env.values())
    cmd = recorded_calls[0]["cmd"]
    assert all(token not in str(part) for part in cmd)


def test_github_token_still_sent_to_github(recorded_calls):
    token = "ghp_supersecrettoken1234567890"  # noqa: S105
    clone_repo("https://github.com/acme/widgets.git", "main", github_token=token)
    env = recorded_calls[0]["env"]
    assert env["GIT_CONFIG_KEY_0"] == "http.extraheader"


def test_client_cert_and_key_written_to_git_config_and_cleaned_up(tmp_path, monkeypatch):
    """clone_repo deletes the temp cert dir in `finally` right after the
    subprocess call, before returning -- so the file content/permissions
    have to be captured *during* the (faked) subprocess.run call, same
    approach as test_client_cert_temp_dir_cleaned_up_even_on_clone_failure
    below, not by inspecting paths after clone_repo already returned.
    """
    monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))
    monkeypatch.setattr(runner.settings, "extra_clone_hosts", "gitlab.internal.corp")
    cert_pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
    key_pem = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
    captured = {}

    def _run_and_capture(cmd, check=False, capture_output=False, text=False, env=None):
        captured["env"] = env
        captured["cert_path"] = env["GIT_CONFIG_VALUE_0"]
        captured["key_path"] = env["GIT_CONFIG_VALUE_1"]
        captured["cert_content"] = Path(captured["cert_path"]).read_text()
        captured["key_content"] = Path(captured["key_path"]).read_text()
        captured["cert_mode"] = oct(Path(captured["cert_path"]).stat().st_mode)[-3:]
        captured["key_mode"] = oct(Path(captured["key_path"]).stat().st_mode)[-3:]
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", _run_and_capture)

    clone_repo(
        "https://gitlab.internal.corp/team/project.git", "main",
        client_cert_pem=cert_pem, client_key_pem=key_pem,
    )

    # GIT_CONFIG_COUNT=2 is what actually governs what git reads, so only
    # indices 0/1 matter here; this sandbox's own ambient git setup already
    # has other GIT_CONFIG_KEY_N entries at higher indices (unrelated SSH
    # rewriting), which git ignores once COUNT caps it at 2.
    env = captured["env"]
    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_0"] == "http.sslCert"
    assert env["GIT_CONFIG_KEY_1"] == "http.sslKey"

    assert captured["cert_content"] == cert_pem
    assert captured["key_content"] == key_pem
    assert captured["cert_mode"] == "600"
    assert captured["key_mode"] == "600"

    # Cleaned up after the call returns, success or not, so nothing lingers
    # on disk past the single clone that needed it.
    assert not Path(captured["cert_path"]).exists()
    assert not Path(captured["key_path"]).exists()
    assert not Path(captured["cert_path"]).parent.exists()


def test_client_cert_temp_dir_cleaned_up_even_on_clone_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))
    monkeypatch.setattr(runner.settings, "extra_clone_hosts", "gitlab.internal.corp")
    captured = {}

    def _failing_run(cmd, check=False, capture_output=False, text=False, env=None):
        captured["cert_path"] = env["GIT_CONFIG_VALUE_0"]
        raise subprocess.CalledProcessError(returncode=128, cmd=cmd, output="", stderr="fatal: boom")

    monkeypatch.setattr(runner.subprocess, "run", _failing_run)

    with pytest.raises(subprocess.CalledProcessError):
        clone_repo(
            "https://gitlab.internal.corp/team/project.git", "main",
            client_cert_pem="fake-cert",
        )

    assert not Path(captured["cert_path"]).exists()
    assert not Path(captured["cert_path"]).parent.exists()


def test_proxy_url_sets_https_and_http_proxy_env(recorded_calls, monkeypatch):
    monkeypatch.setattr(runner.settings, "extra_clone_hosts", "gitlab.internal.corp")
    clone_repo(
        "https://gitlab.internal.corp/team/project.git", "main",
        proxy_url="http://vpn-gateway.internal.corp:3128",
    )
    env = recorded_calls[0]["env"]
    assert env["HTTPS_PROXY"] == "http://vpn-gateway.internal.corp:3128"
    assert env["HTTP_PROXY"] == "http://vpn-gateway.internal.corp:3128"


def test_no_proxy_env_set_when_no_proxy_url_given(recorded_calls, monkeypatch):
    # Isolated from whatever the *real* environment already has (a sandbox
    # or CI runner behind its own outbound proxy legitimately sets these);
    # the property under test is "clone_repo doesn't add its own", not
    # "the ambient environment never has one".
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    clone_repo("https://github.com/acme/widgets.git", "main")
    env = recorded_calls[0]["env"]
    assert "HTTPS_PROXY" not in env
    assert "HTTP_PROXY" not in env
