"""CVSS base-vector decomposition (#201, phase 1).

`CveEnrichment` has stored NVD's CVSS *vector string* since #71, but only
the aggregate `cvss_score` was ever read. That aggregate rolls impact and
exploitability into one number, so the platform could show "9.8" and still
not answer the question a triager actually asks: can this be reached over
the network, does it need a logged-in account, does it need someone to click
something? Those live in the vector, one letter each.

This module turns the vector string into the four exploitability metrics the
issue names -- Attack Vector, Attack Complexity, Privileges Required, User
Interaction -- plus a 0..1 exploitability sub-score derived from them, which
`app.core.scoring` consumes as one configurable signal slot.

Two rules shape everything below.

**Unknown is not benign.** An absent, truncated, or unparseable vector
yields `None` for every metric and `None` (never 0.0) for the sub-score.
`None` means "we did not establish this" and must reach scoring as an
*absent* signal, which contributes nothing. It must never be rendered as
"low exploitability", which is a claim we have not earned. The distinction
is the same one #246 draws between `no_known_fix` and `unknown`.

**Partial knowledge is scored on what is known.** The sub-score is the mean
of the metrics we actually decoded, not a product across all four with
unknowns filled in. A product would let a single missing metric silently
drag a network-reachable, no-privileges CVE toward the bottom of the list --
treating "we didn't parse it" as evidence of safety.

Be precise about what that mean does and does not guarantee, because an
earlier version of this comment overclaimed it:

  * It DOES guarantee that a partially-decoded vector never scores worse
    than no vector at all, because the scoring engine treats an absent
    sub-score as a zero-point contribution and every contribution is
    non-negative. That is the property the failsafe rule actually needs.
  * It does NOT make the sub-score monotonic in information. `AV:P` on its
    own means 0.15, while the same vector fully decoded
    (`AV:P/AC:H/PR:H/UI:R`) means 0.7875 -- decoding *more* of a
    hard-to-exploit vector raises its sub-score, because the mean is over a
    different set of metrics each time. Within a population of
    consistently-formed v3/v4 vectors (which is what NVD emits -- all four
    base metrics are mandatory) this never arises; it is a property of
    truncated input, not of real advisories.

**CVSS v2 does not produce a sub-score at all.** v2 vectors are still
decoded for display (AV and AC; v2 has no PR or UI metric, and mapping its
`Au` authentication metric onto Privileges Required would assert an
equivalence the specs do not make), but `exploitability()` returns None for
them. A mean over {AV, AC} is simply not the same quantity as a mean over
{AV, AC, PR, UI}, and an engine that ranks findings against each other
cannot mix the two: `AV:N/AC:L/Au:M` would score 1.00 where its v3
counterpart `AV:N/AC:L/PR:H/UI:R` scores 0.68, so every v2 CVE would float
above comparable v3 ones. That is not a rounding artifact but a systematic
bias, because `app.core.nvd.fetch_nvd_cve` falls back to `cvssMetricV2`
precisely for older CVEs -- turning the signal on would have quietly
promoted a whole cohort. Unknown (contributing nothing) is the honest
answer for a vector whose vocabulary cannot express what we weight.

Handles CVSS v3.0/v3.1 and v4.0 for scoring, plus v2 for display. v2 is not
hypothetical here: those vectors are already in the database.
"""

from dataclasses import dataclass

# Canonical, lowercase names for each metric value. Stored and returned in
# this vocabulary rather than the raw single letters so the persisted
# columns and the API are readable without a CVSS spec open alongside.
#
# Keyed by (metric, raw letter). Values that exist in only one version are
# accepted regardless of the declared version: v3 has no UI:A and v4 has no
# UI:R, so a single combined table stays unambiguous, and being lenient
# about a vector that mixes them costs nothing (the result is still a
# metric we positively decoded).
ATTACK_VECTOR_VALUES = {
    "N": "network",
    "A": "adjacent",
    "L": "local",
    "P": "physical",
}

ATTACK_COMPLEXITY_VALUES = {
    "L": "low",
    "H": "high",
    # v2 only; v3/v4 collapsed Medium into Low/High.
    "M": "medium",
}

PRIVILEGES_REQUIRED_VALUES = {
    "N": "none",
    "L": "low",
    "H": "high",
}

USER_INTERACTION_VALUES = {
    "N": "none",
    # v3.x
    "R": "required",
    # v4.0 split "required" into Passive (the victim is doing something
    # ordinary) and Active (the victim must be led into a specific action).
    "P": "passive",
    "A": "active",
}

# Per-value exploitability contribution, 0..1, roughly tracking the relative
# weights CVSS itself assigns in its exploitability sub-equation. Deliberately
# our own table rather than the spec's exact coefficients: the spec's numbers
# are calibrated to feed CVSS's own base-score formula, and we are feeding a
# different one. What matters here is the ordering (network > adjacent >
# local > physical, and so on) and that the spread is wide enough for the
# signal to actually separate findings.
_ATTACK_VECTOR_EXPLOITABILITY = {"network": 1.0, "adjacent": 0.62, "local": 0.35, "physical": 0.15}
_ATTACK_COMPLEXITY_EXPLOITABILITY = {"low": 1.0, "medium": 0.70, "high": 0.44}
_PRIVILEGES_REQUIRED_EXPLOITABILITY = {"none": 1.0, "low": 0.62, "high": 0.27}
_USER_INTERACTION_EXPLOITABILITY = {"none": 1.0, "passive": 0.62, "required": 0.45, "active": 0.45}

# metric attribute -> (vector key, accepted values, exploitability table)
_METRICS = (
    ("attack_vector", "AV", ATTACK_VECTOR_VALUES, _ATTACK_VECTOR_EXPLOITABILITY),
    ("attack_complexity", "AC", ATTACK_COMPLEXITY_VALUES, _ATTACK_COMPLEXITY_EXPLOITABILITY),
    ("privileges_required", "PR", PRIVILEGES_REQUIRED_VALUES, _PRIVILEGES_REQUIRED_EXPLOITABILITY),
    ("user_interaction", "UI", USER_INTERACTION_VALUES, _USER_INTERACTION_EXPLOITABILITY),
)

_METRIC_LABELS = {
    "attack_vector": "Attack Vector",
    "attack_complexity": "Attack Complexity",
    "privileges_required": "Privileges Required",
    "user_interaction": "User Interaction",
}

SUPPORTED_VERSIONS = ("2.0", "3.0", "3.1", "4.0")


@dataclass(frozen=True)
class CvssDecomposition:
    """The four exploitability metrics of one CVSS base vector.

    Every field is `None` when that metric was not positively decoded.
    `None` is "not established", never "benign" -- see the module docstring.
    """

    version: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None

    @property
    def known_metrics(self) -> dict[str, str]:
        """Only the metrics we actually decoded, keyed by attribute name."""
        return {
            name: value
            for name, _key, _values, _table in _METRICS
            if (value := getattr(self, name)) is not None
        }

    @property
    def is_unknown(self) -> bool:
        """True when nothing at all was established.

        Note this is about the *metrics*, not the version: a vector string
        whose `CVSS:3.1` prefix parsed but whose metrics were all garbage is
        as unknown as no vector at all, and must be treated that way.
        """
        return not self.known_metrics

    def exploitability(self) -> float | None:
        """0..1 exploitability sub-score, or None when it cannot be derived.

        Mean over the decoded metrics only. Returning `None` rather than 0.0
        for an underivable vector is the whole point: the caller has to
        decide what "we don't know" means, and `app.core.scoring` decides it
        means "this signal contributes nothing", not "this is hard to
        exploit".

        None for a v2 vector even though AV/AC decoded fine -- see the
        module docstring. v2 has no PR or UI metric at all, so its mean is
        over a smaller and systematically more favourable metric set, and
        these numbers are compared against each other.
        """
        if self.version == "2.0":
            return None
        scores = [
            table[value]
            for name, _key, _values, table in _METRICS
            if (value := getattr(self, name)) is not None
        ]
        if not scores:
            return None
        return sum(scores) / len(scores)

    def describe(self) -> str:
        """Human-readable summary for the score breakdown and the UI, e.g.
        "Attack Vector: network, Attack Complexity: low, Privileges
        Required: none". Names the metrics we know and says nothing about
        the ones we do not."""
        known = self.known_metrics
        if not known:
            return "no CVSS metrics decoded"
        return ", ".join(f"{_METRIC_LABELS[name]}: {value}" for name, value in known.items())


UNKNOWN_CVSS = CvssDecomposition()


def parse_cvss_vector(raw: str | None) -> CvssDecomposition:
    """Decompose a CVSS vector string. Never raises; never returns a
    fabricated metric.

    Accepts the prefixed form every v3.x/v4.0 vector uses
    (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
    `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/...`) and the bare v2 form
    (`AV:N/AC:L/Au:N/C:P/I:P/A:P`).

    Only *base* metrics are read. v3's temporal/environmental overrides
    (`MAV`, `MAC`, `MPR`, `MUI`) are deliberately ignored rather than
    silently substituted: they are an assessor's local re-scoring, this
    platform has its own environmental signals (target criticality,
    exposure) that would then double-count them, and an exact key match
    means an `MAV:L` can never be mistaken for `AV:L`.

    Anything unparseable -- empty, truncated, a sentence, a vector whose
    metric values are not in the spec's vocabulary -- yields `UNKNOWN_CVSS`
    rather than a partially-invented decomposition.
    """
    if not raw or not isinstance(raw, str):
        return UNKNOWN_CVSS

    tokens = [token.strip() for token in raw.strip().split("/") if token.strip()]
    if not tokens:
        return UNKNOWN_CVSS

    # Exact key -> raw value. Uppercased keys so `Au`/`au` both land as "AU";
    # values uppercased for the same reason (`av:n` is still AV:N).
    fields: dict[str, str] = {}
    version: str | None = None
    for token in tokens:
        key, _, value = token.partition(":")
        if not value:
            continue
        key = key.strip().upper()
        value = value.strip().upper()
        if key == "CVSS":
            # Only accept something shaped like a version number; "CVSS:yes"
            # is not a version, and recording it would make `version` a field
            # nothing can trust.
            major, _, minor = value.partition(".")
            if major.isdigit() and minor.isdigit():
                version = f"{major}.{minor}"
            continue
        fields[key] = value

    decoded: dict[str, str | None] = {}
    for name, vector_key, accepted, _table in _METRICS:
        decoded[name] = accepted.get(fields.get(vector_key, ""))

    if version is None and "AU" in fields:
        # No `CVSS:` prefix and an `Au` (Authentication) metric: that shape
        # only exists in v2. Worth naming rather than leaving version=None,
        # since it tells a reader why PR/UI came back unknown for a vector
        # that otherwise looks complete -- v2 has no such metrics to decode.
        version = "2.0"

    result = CvssDecomposition(version=version, **decoded)
    if result.is_unknown:
        # A prefix with no usable metrics is not more informative than no
        # vector at all, and carrying the version forward would make an
        # all-unknown decomposition look like it had been established.
        return UNKNOWN_CVSS
    return result
