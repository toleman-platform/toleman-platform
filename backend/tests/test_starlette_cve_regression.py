"""Regression guard for #239: starlette@0.38.6 carried 7 real CVEs, including
an SSRF (CVE-2026-48818 / GHSA-wqp7-x3pw-xc5r), invisible to our SCA because
Trivy reads requirements.txt's direct pins and starlette was never one; it
arrived transitively through fastapi, whose own upper bound
(`starlette<0.39.0,>=0.37.2`) kept it there no matter what was requested
elsewhere.

requirements.txt now pins fastapi>=0.133.0 (the first release that drops that
upper bound entirely) and starlette==1.6.0 explicitly. This test is the
"regression test so a transitive High cannot pass silently again" the issue
asked for: it checks the versions actually *installed*, not the pin file, so
it fails the way the original bug would have; silently, if it weren't
checked at all.

1.3.1 is not an arbitrary floor. Queried directly against OSV for every
advisory affecting 0.38.6 (see the corresponding comment in
requirements.txt): 1.3.1 is the highest "fixed in" version among them, so it
is the true minimum that clears every known issue, not just the SSRF.
"""

import importlib.metadata as metadata

from packaging.version import Version


def test_starlette_clears_every_advisory_that_affected_0_38_6():
    installed = Version(metadata.version("starlette"))
    # The real floor, independently re-derivable: run
    #   curl -s -X POST https://api.osv.dev/v1/query \
    #     -d '{"package":{"name":"starlette","ecosystem":"PyPI"},"version":"0.38.6"}'
    # and take the highest "fixed" version across every returned advisory.
    minimum_safe = Version("1.3.1")
    assert installed >= minimum_safe, (
        f"starlette {installed} is below {minimum_safe}, the OSV-verified floor "
        "that clears every advisory affecting 0.38.6 (including the SSRF, "
        "GHSA-wqp7-x3pw-xc5r). A pin change let this regress; see #239."
    )


def test_fastapi_no_longer_caps_starlette_below_the_fix():
    """The mechanism, not just the outcome. fastapi's own upper bound is what
    silently held starlette at 0.38.6 regardless of what else was pinned,
    versions before 0.133.0 cap it below 0.39.0/0.41.0/0.42.0/etc, none of
    which reach 1.3.1. Pinning starlette alone without this would leave a
    landmine: some future edit that removes the explicit starlette pin (it
    looks redundant next to fastapi, which is exactly why it drifted
    unnoticed the first time) would silently fall back to fastapi's own,
    much older, constraint.
    """
    installed = Version(metadata.version("fastapi"))
    first_unbounded_release = Version("0.133.0")
    assert installed >= first_unbounded_release, (
        f"fastapi {installed} is older than {first_unbounded_release}; earlier "
        "releases cap starlette below the version that fixes #239's CVEs "
        "regardless of any explicit starlette pin in requirements.txt."
    )
