"""Secret findings must carry enough to judge them (#481).

Toleman's own PR Guardrail blocked #480 with one High finding:

    generic-api-key — Secret detected —
    backend/app/scanners/rules/core/crypto/ruby-hardcoded-secret-key-base.yaml:28

The flagged line was a comment inside a Semgrep rule file, quoting
RailsGoat's published `secret_key_base` as the rule's validation evidence.
Zero risk, correctly-shaped match. But the finding carried only a severity,
a rule id, a path and a line -- none of the facts that settle it -- so
reaching the verdict meant opening the file.

Two of those facts are derivable from what gitleaks reports: the matched
value's length and its character class. "128 characters, hex" is what
`rails secret` and `openssl rand -hex` produce; "11 characters,
alphanumeric" is the shape of a placeholder. A reviewer can weigh that
without leaving the tool.

The secret itself is deliberately absent, not even a prefix. A finding is
visible to everyone who can see the workspace and travels into CSV
exports, SIEM events and Jira tickets, and a prefix is enough to confirm a
guess about which credential it is. Length and class carry the triage
signal without carrying the credential.
"""
from app.models.models import Severity
from app.scanners.parsers import describe_secret_shape, parse_gitleaks


def test_a_generated_hex_key_reads_as_one():
    """The exact shape of the false positive that prompted this."""
    shape = describe_secret_shape("2f1d90a26236c3245d96f5606c201a780dc9ca68" * 3 + "0d1e2f3a", 3.93)

    assert "128 characters" in shape
    assert "hex" in shape


def test_a_short_placeholder_reads_as_one():
    shape = describe_secret_shape("changeme123")

    assert "11 characters" in shape
    assert "alphanumeric" in shape


def test_character_classes_are_distinguished():
    assert "hex" in describe_secret_shape("deadbeef00")
    assert "digits" in describe_secret_shape("0123456789")
    assert "base64" in describe_secret_shape("YWJjZGVmZ2hpamtsbW5vcA==")
    assert "mixed" in describe_secret_shape("p@ssw0rd!with-symbols")


def test_base64url_is_not_reported_as_plain_base64():
    """`-` and `_` instead of `+` and `/`: the JWT alphabet, and a
    different provenance from a standard-base64 blob."""
    assert "base64url" in describe_secret_shape("abcABC123-_xyz")


def test_entropy_is_reported_not_judged():
    """What counts as "high" depends on the character class, so the number
    is surfaced rather than turned into a verdict this code would have to
    invent."""
    shape = describe_secret_shape("deadbeef", 2.5)

    assert "entropy 2.50" in shape


def test_entropy_is_omitted_when_the_scanner_did_not_supply_it():
    assert "entropy" not in describe_secret_shape("deadbeef")


def test_the_secret_itself_never_appears():
    """The load-bearing assertion. A prefix would be enough to confirm a
    guess about which credential this is, and findings travel into exports
    and tickets."""
    secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

    shape = describe_secret_shape(secret, 4.14)

    assert secret not in shape
    for size in (4, 6, 8, 12):
        assert secret[:size] not in shape, f"leaked a {size}-character prefix"
    assert secret[-4:] not in shape


def test_an_empty_secret_adds_nothing():
    assert describe_secret_shape("") == ""


def test_the_shape_is_appended_to_the_rule_description():
    """Gitleaks' own Description says what the rule looks for; the shape
    says what it actually matched. Both are useful, so neither replaces
    the other."""
    parsed = parse_gitleaks([
        {
            "RuleID": "generic-api-key",
            "Description": "Detected a Generic API Key.",
            "File": "config/app.rb",
            "StartLine": 28,
            "EndLine": 28,
            "Secret": "a" * 128,
            "Entropy": 3.5,
            "Match": 'secret_key_base = "' + "a" * 128 + '"',
        }
    ])

    assert len(parsed) == 1
    description = parsed[0]["description"]
    assert "Detected a Generic API Key." in description
    assert "128 characters" in description
    assert parsed[0]["severity"] == Severity.HIGH


def test_a_gitleaks_finding_with_no_secret_field_still_parses():
    """Not every rule populates Secret, and a parser that raised here
    would fail the whole scan over a missing optional field."""
    parsed = parse_gitleaks([
        {"RuleID": "x", "Description": "d", "File": "f", "StartLine": 1, "EndLine": 1}
    ])

    assert parsed[0]["description"] == "d"
