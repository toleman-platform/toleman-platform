"""A failed clone must say why, and must not be retried when retrying is futile.

Both behaviours came from one real incident. A deployment had two private
repositories registered and no GitHub credentials configured in the worker
container. Every scan and discovery run failed, and the only signal was:

    CalledProcessError(128, ['git', 'clone', '--depth', '1', ...])
    scan.error = "git clone failed after retries"

Exit 128 is what git returns for a missing repo, a missing branch, a bad URL
*and* absent credentials, so the log said nothing about which. On top of that,
`RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)` meant each doomed
clone was attempted four times with backoff -- seven queued scans produced
roughly fifty identical tracebacks and no diagnosis.

The safety property that produced the vague message is real and is preserved:
nothing here may echo raw stderr, argv, paths, or a token. These tests pin
both halves -- useful message, no leak.
"""

import subprocess

import pytest

from app.scanners import runner
from app.scanners.runner import RepoCloneError, _classify_clone_stderr, clone_error_message

# Verbatim git output, captured by reproducing each case against a real remote.
AUTH = "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
AUTH_FAILED = "remote: Invalid username or password.\nfatal: Authentication failed for 'https://github.com/x/y.git/'"
NO_REPO = "remote: Repository not found.\nfatal: repository 'https://github.com/x/y.git/' not found"
NO_BRANCH = "fatal: Remote branch nope not found in upstream origin"
FORBIDDEN = "remote: Permission denied\nfatal: unable to access: The requested URL returned error: 403 Forbidden"
DNS = "fatal: unable to access 'https://github.com/x/y.git/': Could not resolve host: github.com"
HANGUP = "fatal: the remote end hung up unexpectedly"


class TestClassification:
    @pytest.mark.parametrize("stderr", [AUTH, AUTH_FAILED])
    def test_missing_credentials_names_the_fix(self, stderr):
        msg = _classify_clone_stderr(stderr)
        assert msg is not None
        assert "GITHUB_TOKEN" in msg or "GitHub App" in msg

    def test_missing_repository(self):
        assert "not found" in (_classify_clone_stderr(NO_REPO) or "").lower()

    def test_missing_branch_points_at_the_target_setting(self):
        msg = _classify_clone_stderr(NO_BRANCH) or ""
        assert "branch" in msg.lower()

    def test_permission_denied(self):
        assert "denied" in (_classify_clone_stderr(FORBIDDEN) or "").lower()

    @pytest.mark.parametrize("stderr", [DNS, HANGUP, "", "something nobody has seen before"])
    def test_transient_and_unknown_stay_retryable(self, stderr):
        # None is the signal that means "leave it as CalledProcessError, let
        # Celery retry". Misclassifying a network blip as permanent would be
        # the opposite failure: a scan abandoned on a hiccup.
        assert _classify_clone_stderr(stderr) is None


class TestNoLeak:
    """The whole reason the message was vague. It must stay non-leaky."""

    def test_message_never_echoes_stderr_contents(self):
        stderr = (
            "fatal: could not read Username for 'https://github.com'\n"
            "/tmp/rikugan-scans/secret-path-9f2\n"
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        msg = _classify_clone_stderr(stderr) or ""
        assert "ghp_" not in msg
        assert "/tmp/rikugan-scans" not in msg
        assert "secret-path" not in msg

    def test_clone_error_message_never_echoes_argv(self):
        exc = subprocess.CalledProcessError(
            128, ["git", "clone", "--depth", "1", "--", "https://github.com/x/y.git", "/tmp/rikugan-scans/y-1"]
        )
        exc.stderr = AUTH
        msg = clone_error_message(exc)
        assert "/tmp/rikugan-scans" not in msg
        assert "git clone --depth" not in msg


class TestCloneErrorMessage:
    def test_prefers_the_actionable_cause_over_the_exit_code(self):
        exc = subprocess.CalledProcessError(128, ["git", "clone"])
        exc.stderr = AUTH
        msg = clone_error_message(exc)
        assert "exit code" not in msg
        assert "credentials" in msg.lower()

    def test_falls_back_to_exit_code_when_cause_is_unrecognised(self):
        exc = subprocess.CalledProcessError(128, ["git", "clone"])
        exc.stderr = HANGUP
        assert "exit code 128" in clone_error_message(exc)

    def test_repo_clone_error_passes_through(self):
        assert clone_error_message(RepoCloneError("invalid branch name: 'x y'")) == "invalid branch name: 'x y'"


class TestNotRetried:
    """The retry half. RepoCloneError is deliberately excluded from every
    task's RETRYABLE_EXCEPTIONS, so raising it is what stops the storm."""

    def _run_clone(self, monkeypatch, stderr, tmp_path):
        monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))

        def boom(*a, **k):
            exc = subprocess.CalledProcessError(128, ["git", "clone"])
            exc.stderr = stderr
            exc.stdout = ""
            raise exc

        monkeypatch.setattr(runner.subprocess, "run", boom)
        return runner.clone_repo("https://github.com/acme/repo", "main", None)

    def test_permanent_failure_raises_the_non_retryable_type(self, monkeypatch, tmp_path):
        with pytest.raises(RepoCloneError) as ei:
            self._run_clone(monkeypatch, AUTH, tmp_path)
        assert "credentials" in str(ei.value).lower()

    def test_permanent_failure_is_not_a_CalledProcessError(self, monkeypatch, tmp_path):
        # This is the assertion that actually prevents the retry storm:
        # autoretry_for=(CalledProcessError,) must not catch it.
        with pytest.raises(RepoCloneError) as ei:
            self._run_clone(monkeypatch, NO_REPO, tmp_path)
        assert not isinstance(ei.value, subprocess.CalledProcessError)

    def test_transient_failure_still_raises_CalledProcessError(self, monkeypatch, tmp_path):
        with pytest.raises(subprocess.CalledProcessError):
            self._run_clone(monkeypatch, DNS, tmp_path)

    def test_every_task_excludes_RepoCloneError_from_retries(self):
        from app.tasks import discovery_tasks, sbom_tasks, scan_tasks

        for module in (scan_tasks, discovery_tasks, sbom_tasks):
            assert not issubclass(RepoCloneError, module.RETRYABLE_EXCEPTIONS), module.__name__

    def test_token_is_scrubbed_before_classification(self, monkeypatch, tmp_path):
        """Scrubbing must happen first -- otherwise a token could reach the
        classifier and, in a future change, a message."""
        monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))
        token = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

        def boom(*a, **k):
            exc = subprocess.CalledProcessError(128, ["git", "clone"])
            exc.stderr = f"{AUTH}\ntoken was {token}"
            exc.stdout = ""
            raise exc

        monkeypatch.setattr(runner.subprocess, "run", boom)
        with pytest.raises(RepoCloneError) as ei:
            runner.clone_repo("https://github.com/acme/repo", "main", token)
        assert token not in str(ei.value)
