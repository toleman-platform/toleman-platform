"""Package-level autofix for the Fix Plan tab (#247 follow-up): raise one PR
per package upgrade, covering every open finding that upgrade resolves,
instead of the one-finding-at-a-time flow app.core.autofix's /raise-pr
endpoint already has.

Reuses app.core.autofix's manifest bumpers and GitHub-write plumbing
directly rather than forking them: `_bumper_for_path` decides which
manifest formats can be safely rewritten (requirements.txt/package.json/
go.mod, same restriction as the per-finding flow), and
`_commit_files_and_open_pr` is the exact branch-create/commit/PR-open
sequence `open_fix_pr` already uses, generalized to commit more than one
file on the same branch.

A Fix Plan "package row" (see app.core.remediation.group_remediations) can
span more than one manifest file for the same package -- two CVEs on the
same package can point at requirements.txt and requirements-dev.txt, or two
subprojects in a monorepo each with their own manifest -- and
PackageRemediation.fixes only carries finding_id/cve_id/severity/title, not
file_path, so the backing findings have to be reloaded to discover every
manifest that actually declares the package before a patch can be built.

No suppression-comment guard here, unlike raise_fix_pr_endpoint: that guard
exists because an AI or MCP client can hallucinate a patch that "fixes" a
finding by adding a `# nosemgrep`-style comment instead of changing
anything real. A version-bump regex substitution over a dependency manifest
cannot introduce a suppression comment by construction -- there is no code
path here that writes anything other than a version string into a pin
line.
"""
import json
import logging
import time

from sqlmodel import Session, select

import app.core.autofix as autofix
from app.core import target_lifecycle
from app.core.crypto import SecretDecryptionError
from app.core.remediation import group_remediations
from app.models.models import Finding, RemediationFixPr, Target

logger = logging.getLogger(__name__)


def find_package_finding_files(
    session: Session, target: Target, plan: dict
) -> dict[tuple[str, str], list[Finding]]:
    """`(ref, file_path) -> findings` for every finding behind `plan`'s
    package that names a real file. `ref` is each finding's own branch,
    falling back to the target's default branch -- same "which branch was
    this observed on" rule `autofix._deterministic_sca_patch` uses. Most
    findings on one target share a ref, but nothing guarantees it, so this
    groups by ref too rather than assuming a single one.
    """
    finding_ids = [f["finding_id"] for f in plan["fixes"]]
    if not finding_ids:
        return {}
    findings = session.exec(select(Finding).where(Finding.id.in_(finding_ids))).all()
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        if not finding.file_path:
            continue
        ref = finding.branch or target.default_branch
        grouped.setdefault((ref, finding.file_path), []).append(finding)
    return grouped


def build_package_patch_files(session: Session, target: Target, plan: dict) -> list[tuple[str, str, str]]:
    """`(ref, file_path, new_content)` for every manifest file that names
    `plan["package"]` and could be safely bumped to `plan["upgrade_to"]` --
    the PACKAGE-level version `_group_by_package` computed (the max of
    every grouped CVE's own lowest fix), never
    `autofix._sca_package_version` (that answers a narrower,
    single-finding question; using it here would under-bump a package with
    more than one open CVE).

    A file whose bumper can't find exactly one match is skipped, not
    failed -- a lockfile alongside the manifest, or a manifest the regex
    genuinely can't parse, are both real possibilities on a target with
    several findings on one package. Only when NO file could be bumped does
    `raise_package_fix_pr` below refuse the whole PR.
    """
    files_by_ref: dict[str, set[str]] = {}
    for ref, file_path in find_package_finding_files(session, target, plan):
        files_by_ref.setdefault(ref, set()).add(file_path)

    package = plan["package"]
    version = plan["upgrade_to"]
    results: list[tuple[str, str, str]] = []
    for ref, file_paths in files_by_ref.items():
        for file_path in file_paths:
            bumper = autofix._bumper_for_path(file_path)
            if bumper is None:
                continue
            fetched = autofix._fetch_file(session, target, ref, file_path)
            if fetched is None:
                continue
            content, _sha = fetched
            result = bumper(content, package, version)
            if result is None:
                continue
            old_str, new_str = result
            results.append((ref, file_path, content.replace(old_str, new_str, 1)))
    return results


def _slugify(name: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in name.strip().lower()).strip("-")
    return slug or "package"


class AlreadyRaisedError(Exception):
    """raise_package_fix_pr refused: every finding `plan["fixes"]` names is
    already covered by an existing RemediationFixPr row for this package,
    so opening another PR would be a redundant duplicate of one already
    open. Carries the existing PR's info so a caller can link to it (or
    treat a retry as a no-op success) instead of treating this as a
    failure.

    Checked at this function's own boundary rather than only by
    sweep_auto_raise_prs's pre-check, so EVERY caller (the manual
    single-package endpoint, the bulk "Raise all" batch, and the sweep)
    is protected the same way -- a double-click on "Raise PR", or a batch
    re-run before the first PR merges, must not open a second PR for the
    exact same fix."""

    def __init__(self, pr_url: str, pr_number: int, branch: str):
        self.pr_url = pr_url
        self.pr_number = pr_number
        self.branch = branch
        super().__init__(f"already covered by an existing PR: {pr_url}")


def raise_package_fix_pr(session: Session, target: Target, plan: dict, raised_by: str) -> dict:
    """Opens one PR bumping `plan["package"]` to `plan["upgrade_to"]` across
    every manifest file that names it, covering every finding in
    `plan["fixes"]`. Raises AlreadyRaisedError if every one of those
    findings is already covered by a prior raise for this package (see
    AlreadyRaisedError), and AutofixError if no manifest file could be
    bumped at all (never opens an empty PR). Records the PR in
    RemediationFixPr on success -- the record both this check and the
    auto-raise sweep read to recognize a package as already addressed.
    """
    current_ids = {f["finding_id"] for f in plan["fixes"]}
    covered_ids = _already_raised_finding_ids(session, target.id, plan["package"])
    if covered_ids is not None and current_ids <= covered_ids:
        prior = _latest_raised_pr(session, target.id, plan["package"])
        # prior cannot be None here: covered_ids came from at least one
        # RemediationFixPr row for this exact (target, package).
        raise AlreadyRaisedError(prior.pr_url, prior.pr_number, prior.branch)

    try:
        patches = build_package_patch_files(session, target, plan)
    except autofix.AutofixError:
        raise
    except SecretDecryptionError as exc:
        # Same PLATFORM_ENCRYPTION_KEY-mismatch failure mode
        # app.tasks.pipeline_tasks guards against explicitly: reading a
        # manifest file can resolve a stored GitHub token
        # (app.core.github_token.resolve_github_token), and a bare
        # ValueError subclass escaping this far would reach the API layer
        # uncaught -- past CORSMiddleware, past every AutofixError handler
        # every caller here relies on -- and surface to a browser as a
        # plain network failure with no CORS headers at all (see
        # app.api.targets.create_target's own comment on this exact class
        # of bug). Converted to AutofixError so it's always handled the
        # normal way instead.
        logger.exception(
            "raise_package_fix_pr: PLATFORM_ENCRYPTION_KEY mismatch reading %s's manifest on target %s",
            plan["package"], target.id,
        )
        raise autofix.AutofixError(
            "PLATFORM_ENCRYPTION_KEY mismatch -- the stored GitHub credentials for this target "
            "cannot be decrypted with the currently configured key. Reconnect the GitHub App or "
            "clone credential in Admin/Settings."
        ) from exc
    except Exception as exc:  # noqa: BLE001, last-resort catch so an
        # unexpected failure reading GitHub (a library exception neither
        # _fetch_file nor resolve_github_token already turns into a clean
        # None/AutofixError) can't escape uncaught the same way -- see the
        # SecretDecryptionError branch above for why that matters here
        # specifically, not just as defensive boilerplate.
        logger.exception(
            "raise_package_fix_pr: unexpected error building a patch for %s on target %s",
            plan["package"], target.id,
        )
        raise autofix.AutofixError(f"failed to read {plan['package']}'s manifest file(s) from GitHub") from exc

    if not patches:
        raise autofix.AutofixError(
            f"could not locate a version pin for {plan['package']} in any manifest file "
            "this target's open findings point at."
        )

    # Every patch shares one ref in the overwhelmingly common case (one
    # target, one default branch); when findings genuinely disagree, commit
    # to whichever ref most of the bumpable files matched, so the PR
    # captures the most of this fix rather than an arbitrary one file's ref.
    refs = [ref for ref, _, _ in patches]
    base_ref = max(set(refs), key=refs.count)
    files = [(file_path, new_content) for ref, file_path, new_content in patches if ref == base_ref]

    package = plan["package"]
    version = plan["upgrade_to"]
    resolved_cves = [f["cve_id"] for f in plan["fixes"]]
    unresolved = plan.get("unresolved") or []

    # Same "never round up" honesty rule the frontend PackageRow already
    # enforces (#247): the PR body states what this upgrade does NOT fix
    # whenever anything is left, rather than only listing what it closes.
    body_lines = [
        f"Automated fix from Toleman's Fix Plan: upgrade **{package}** to **{version}**.",
        "",
        f"Resolves {len(resolved_cves)} open finding{'s' if len(resolved_cves) != 1 else ''}: "
        + ", ".join(resolved_cves) + ".",
    ]
    if unresolved:
        unresolved_cves = [u["cve_id"] for u in unresolved]
        body_lines += [
            "",
            f"Does NOT resolve {len(unresolved_cves)} other open finding"
            f"{'s' if len(unresolved_cves) != 1 else ''} on this package (no fixed version published yet): "
            + ", ".join(unresolved_cves) + ".",
        ]
    body_lines += ["", "Opened automatically by Toleman's Fix Plan. Review the diff before merging."]
    pr_body = "\n".join(body_lines)

    branch_name = f"toleman/fix-pkg-{target.id}-{_slugify(package)}-{int(time.time())}"
    try:
        pr = autofix._commit_files_and_open_pr(
            session,
            target,
            ref=base_ref,
            branch_name=branch_name,
            files=files,
            commit_message=f"Fix: upgrade {package} to {version}",
            pr_title=f"Fix: upgrade {package} to {version}",
            pr_body=pr_body,
        )
    except autofix.AutofixError:
        raise
    except SecretDecryptionError as exc:
        # Same class of bug as build_package_patch_files' identical guard
        # above, here for the GitHub App's own private key (minted via
        # _installation_token_or_none -> get_installation_token) rather
        # than a stored clone token.
        logger.exception(
            "raise_package_fix_pr: could not decrypt the GitHub App key opening a PR for %s on target %s",
            package, target.id,
        )
        raise autofix.AutofixError(
            "PLATFORM_ENCRYPTION_KEY mismatch -- the GitHub App credentials for this target's "
            "workspace cannot be decrypted with the currently configured key. Reconnect the GitHub "
            "App in Admin > Global Integrations."
        ) from exc
    except Exception as exc:  # noqa: BLE001, see build_package_patch_files'
        # identical catch-all above for why this can't be allowed to
        # escape uncaught.
        logger.exception(
            "raise_package_fix_pr: unexpected error opening a PR for %s on target %s", package, target.id,
        )
        raise autofix.AutofixError(f"failed to open a PR for {package}") from exc

    session.add(RemediationFixPr(
        target_id=target.id,
        package=package,
        ecosystem=plan.get("ecosystem"),
        upgrade_to=version,
        finding_ids=json.dumps([f["finding_id"] for f in plan["fixes"]]),
        pr_url=pr["pr_url"],
        pr_number=pr["pr_number"],
        branch=pr["branch"],
        raised_by=raised_by,
    ))
    session.commit()
    return pr


def _already_raised_finding_ids(session: Session, target_id: int, package: str) -> set[int] | None:
    """The union of finding ids already covered by every PR previously
    raised for this `(target_id, package)`, or None if none has ever been
    raised. A plan whose current findings are all inside this set is
    already addressed; one naming a finding outside it (a new CVE landed on
    the same package since the last PR) is genuinely new."""
    rows = session.exec(
        select(RemediationFixPr).where(
            RemediationFixPr.target_id == target_id, RemediationFixPr.package == package
        )
    ).all()
    if not rows:
        return None
    covered: set[int] = set()
    for row in rows:
        try:
            covered.update(json.loads(row.finding_ids))
        except (TypeError, ValueError):
            continue
    return covered


def _latest_raised_pr(session: Session, target_id: int, package: str) -> RemediationFixPr | None:
    """The most recently raised PR on record for this `(target_id,
    package)`, to link back to when raise_package_fix_pr refuses a
    duplicate (AlreadyRaisedError). None only when _already_raised_finding_ids
    also returned None for the same pair, so callers that already checked
    coverage can treat this as always-present."""
    return session.exec(
        select(RemediationFixPr)
        .where(RemediationFixPr.target_id == target_id, RemediationFixPr.package == package)
        .order_by(RemediationFixPr.created_at.desc())
    ).first()


def sweep_auto_raise_prs(session: Session) -> dict:
    """The auto-raise sweep (#247 follow-up): for every target with
    `Target.auto_raise_fix_prs` on, raise a PR for every package in its Fix
    Plan that isn't already covered by a previously-raised PR.

    Celery-free (app.core never imports app.tasks -- see
    app.core.scan_schedules's docstring for the convention); the Celery
    task wrapper is app.tasks.remediation_tasks.sweep_auto_raise_prs_task.

    One target's failure (an unparseable plan, a revoked GitHub App token)
    must not stop the sweep for every other target -- the same per-row
    isolation app.tasks.schedule_tasks.dispatch_due_scan_schedules uses --
    and one package's AutofixError inside a target must not skip the rest
    of that target's plan either. Commits after each successful raise, not
    batched at the end, so a mid-sweep crash cannot lose the record of PRs
    already opened, which would otherwise cause them to be re-opened on the
    next tick (same reasoning dispatch_due_scan_schedules' docstring gives
    for its own per-row commits).

    "Already raised" is answered from RemediationFixPr, not a live GitHub
    PR-status poll -- a PR closed without merging will not be detected, so
    that package will not be re-raised automatically. Accepted MVP gap:
    polling GitHub's search API for every opted-in target's every package
    on every tick has no bounded budget in this design, while "we already
    recorded raising one for this exact finding set" is cheap and correct
    for the common case (nothing re-raises a PR that's still open).
    """
    summary = {
        "targets_considered": 0,
        "targets_opted_in": 0,
        "packages_considered": 0,
        "prs_raised": 0,
        "prs_skipped_already_raised": 0,
        "prs_failed": 0,
    }

    targets = session.exec(
        target_lifecycle.scannable_targets(select(Target).where(Target.auto_raise_fix_prs.is_(True)))
    ).all()
    summary["targets_considered"] = len(targets)

    for target in targets:
        summary["targets_opted_in"] += 1
        try:
            plans = group_remediations(session, target.id)
        except Exception:
            logger.exception("auto-raise sweep: failed to build fix plan for target %s", target.id)
            continue

        for plan in plans:
            summary["packages_considered"] += 1
            current_ids = {f["finding_id"] for f in plan["fixes"]}
            already = _already_raised_finding_ids(session, target.id, plan["package"])
            if already is not None and current_ids <= already:
                summary["prs_skipped_already_raised"] += 1
                continue
            try:
                raise_package_fix_pr(session, target, plan, raised_by="sweep")
                summary["prs_raised"] += 1
            except AlreadyRaisedError:
                # Race with a manual raise (or a concurrent sweep pass)
                # between the pre-check above and this call -- the shared
                # helper's own check (see AlreadyRaisedError) is what
                # actually prevents the duplicate PR; this is just the
                # summary counting it the same way the pre-check does.
                summary["prs_skipped_already_raised"] += 1
            except autofix.AutofixError:
                logger.warning(
                    "auto-raise sweep: failed to raise PR for %s on target %s",
                    plan["package"], target.id, exc_info=True,
                )
                summary["prs_failed"] += 1
            except Exception:
                logger.exception(
                    "auto-raise sweep: unexpected error raising PR for %s on target %s",
                    plan["package"], target.id,
                )
                summary["prs_failed"] += 1

    return summary
