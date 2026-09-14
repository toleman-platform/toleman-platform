"""Whether a scan run can be trusted to have actually checked anything (#229).

The bug this exists for: six trivy processes were launched concurrently
against one shared vulnerability-DB cache. One of them read the cache while
another was replacing it, and came back with exit code 0, valid JSON and an
empty ``Vulnerabilities`` array. ``ingest_findings`` could not tell that
apart from "scanned the repo, it is clean", so it mitigated five live
High/Medium vulnerabilities and the platform reported a clean repo.

The distinction this module restores is the one ``app/core/osv_malware.py``
already draws, where ``None`` (check failed) and ``{}`` (check completed,
nothing found) are deliberately different values so an OSV outage cannot
read as an all-clear. A scanner CLI has no equivalent: it returns bytes, and
zero findings look identical whichever way they were produced. So the
runner assembles the evidence separately -- DB freshness, warnings the tool
wrote to stderr, whether the tool reported examining anything at all -- and
hands it here.

Deliberately additive: a ``ScanHealth`` starts healthy and is *degraded* by
named reasons. Every reason is a sentence a user can read, because it is
shown to them; "suspect" with no explanation is only marginally better than
a silent false all-clear, and the standing rule in this codebase is that a
failed, skipped or unknown check must never render as clean.
"""

from dataclasses import dataclass, field

# The verdicts persisted on Scan.health.
#
# UNKNOWN is not a failure state and is not the same as SUSPECT. It is what a
# row carries when nobody assessed it: every Scan that predates this feature,
# plus any ingestion path that has no evidence to offer. Collapsing it into
# either of the other two would be a claim we cannot support -- into HEALTHY
# it would assert a check we never verified, into SUSPECT it would paint a
# year of legitimate scan history with a warning users would learn to ignore.
HEALTHY = "healthy"
SUSPECT = "suspect"
UNKNOWN = "unknown"

# Bound on what gets persisted in Scan.health_note. Long enough for several
# real reasons, short enough that a tool dumping its stderr into one cannot
# bloat every scan row.
MAX_NOTE_LENGTH = 500


@dataclass
class ScanHealth:
    """Evidence about one tool invocation, collected as it runs.

    ``healthy`` is a *positive* claim: this run produced no signal that it
    was incomplete. It is what the ingestion path requires before a
    zero-finding result is allowed to mitigate anything.
    """

    tool: str
    # Why this run is not trusted. Empty means nothing went wrong, which is
    # the only thing that makes the run authoritative.
    reasons: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.reasons

    @property
    def status(self) -> str:
        return HEALTHY if self.healthy else SUSPECT

    def degrade(self, reason: str) -> None:
        """Record a reason this run may not have checked what it claims.

        Deduplicated: a PER_FILE tool is invoked once per file and can emit
        the same warning on every one of them, which would otherwise fill
        the note with the same sentence fifty times.
        """
        if reason and reason not in self.reasons:
            self.reasons.append(reason)

    def summary(self) -> str:
        """One line naming every reason, for Scan.health_note and logs."""
        text = "; ".join(self.reasons)
        if len(text) > MAX_NOTE_LENGTH:
            return text[: MAX_NOTE_LENGTH - 1] + "…"
        return text


def trusted(tool: str) -> ScanHealth:
    """A healthy ScanHealth for a path whose caller asserts the run happened.

    Used where the evidence comes from outside this platform (a CI job
    posting SARIF that declares its own invocation successful) rather than
    from a scanner we ran ourselves. Spelled out as its own constructor so
    those call sites read as a deliberate assertion, not as the accidental
    default that shipping ``ScanHealth(tool)`` inline would look like.
    """
    return ScanHealth(tool=tool)
