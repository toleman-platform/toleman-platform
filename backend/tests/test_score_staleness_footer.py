"""#271: a PR comment must say its severities have an as-of date.

Every severity in a PR Guardrail comment derives from priority_score
(app/core/scoring.py), which folds in EPSS and CISA KEV -- both of which
move. A finding rendered Medium when the comment was posted can genuinely be
Critical by the time someone reviews the PR two days later, because CISA
added its CVE to KEV in between. Nothing in the comment said so.

Same instinct as tools_failed/tools_skipped (#243, #253) -- a result is only
true as of when it ran -- applied to score freshness rather than scan
completeness.
"""

from datetime import datetime

from app.core.pr_guardrail_executor import render_comment
from app.models.models import PRGuardrailStatus

SCANNED_AT = datetime(2026, 8, 22, 9, 30)


class TestStalenessFooter:
    def test_comment_states_the_as_of_time(self):
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"], scanned_at=SCANNED_AT,
        )
        assert "2026-08-22 09:30 UTC" in body
        assert "may have changed since" in body

    def test_footer_appears_on_a_clean_pass_too(self):
        """Not only when something scored high. A reader cannot know whether
        a score moved without being told the number has an as-of date at
        all -- so the disclaimer is unconditional, like the scanned-with
        line beside it."""
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"], scanned_at=SCANNED_AT,
        )
        assert "EPSS/KEV" in body

    def test_footer_appears_on_a_blocked_scan(self):
        body = render_comment(
            [], [], PRGuardrailStatus.BLOCKED, 1, 1,
            tools_run=["semgrep"], scanned_at=SCANNED_AT,
        )
        assert "may have changed since" in body

    def test_it_points_somewhere_current(self):
        """Saying "this may be stale" without saying where the fresh number
        lives just leaves the reader stuck."""
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"], scanned_at=SCANNED_AT,
        )
        assert "Rikugan" in body

    def test_omitted_entirely_when_no_timestamp_is_supplied(self):
        """Backwards-compatible default, matching how tools_run/scan_scope
        already behave for callers predating their feature."""
        body = render_comment([], [], PRGuardrailStatus.PASSED, 1, 1, tools_run=["semgrep"])
        assert "may have changed since" not in body
        assert "EPSS/KEV" not in body

    def test_does_not_disturb_the_diff_scope_or_tools_lines(self):
        """The footer is additive -- #243's scope note and the scanned-with
        line must both survive alongside it."""
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"],
            tools_skipped={"trivy": "no dependency manifest changed"},
            scan_scope="diff", files_scanned=3,
            scanned_at=SCANNED_AT,
        )
        assert "Diff-scoped scan" in body
        assert "Scanned with: semgrep" in body
        assert "no dependency manifest changed" in body
        assert "may have changed since" in body

    def test_footer_is_last(self):
        """It qualifies everything above it, so it reads as a footnote to
        the whole comment rather than to whichever section it landed in."""
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"], scanned_at=SCANNED_AT,
        )
        assert body.rstrip().endswith("</sub>")
        assert body.index("may have changed since") > body.index("Scanned with")
