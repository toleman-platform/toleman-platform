"""Pipeline integration (issue #66): generate a real per-target GitHub
Actions workflow that runs the same OSS scanners
`.github/workflows/self-scan.yml` runs against this repo itself (Semgrep,
Gitleaks, Trivy, plus gosec when the target is a Go repo) natively inside
the runner, then pushes each tool's SARIF output back into this platform
via `POST /api/ingest/{target_id}` -- the CI/CD push endpoint
`app/api/ingest.py` already exists for exactly this purpose.

IMPORTANT -- read `self-scan.yml`'s header comment before changing this:
GitHub's cloud runners cannot reach a backend running at localhost:8000, so
the generated workflow's ingest step depends on two GitHub Actions secrets
the *target repo's* owner must configure themselves:

  - ``RIKUGAN_API_URL``: a **publicly reachable** deployment of this platform
    (e.g. `docker-compose.yml` from #60, exposed via a real domain/tunnel).
    Pointing this at localhost:8000 will simply fail from GitHub's runners,
    the same problem self-scan.yml's own comment documents.
  - ``RIKUGAN_API_KEY``: the target's workspace API key (`GET
    /api/targets/{id}/workspace-key`).

Scanning still happens (and is reported in the job summary/artifacts)
regardless of whether the ingest step succeeds -- so this degrades to
"exactly self-scan.yml" rather than failing outright when Rikugan isn't
publicly reachable yet.
"""
import logging

import httpx
from sqlmodel import Session, select

from app.core.github import get_github_token, repo_slug_from_url
from app.core.tool_usage import tools_for_surface
from app.models.models import Finding, Target

logger = logging.getLogger(__name__)

WORKFLOW_PATH = ".github/workflows/rikugan-scan.yml"
WORKFLOW_FILENAME = "rikugan-scan.yml"

# Custom Workflow Builder (issue #35): the fixed catalog of scanners a
# PipelineWorkflowTemplate's step list may reference -- the same four jobs
# #66's default template always included (gosec conditionally). Keeping
# this a closed catalog (not an arbitrary user-supplied job) is deliberate:
# every job body below still comes from this file, never from user input,
# so a "custom workflow" can only reorder/toggle *which* of these known,
# reviewed scanner jobs run -- it can't inject arbitrary YAML/shell into a
# generated GitHub Actions file.
SUPPORTED_TOOLS = ["semgrep", "gitleaks", "trivy", "gosec"]


def detect_languages(target: Target) -> list[str]:
    """Real per-target language detection via GitHub's repo languages API
    (bytes-of-code-per-language) -- used as a fallback signal for whether to
    include the Go-only gosec job when the target has no scan history yet.
    Best-effort: returns [] on any failure rather than raising, since this
    only affects which optional job gets included."""
    slug = repo_slug_from_url(target.repo_url)
    token = get_github_token()
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        res = httpx.get(f"https://api.github.com/repos/{slug}/languages", headers=headers, timeout=15)
        if res.status_code == 200:
            return list(res.json().keys())
    except Exception:
        logger.warning("pipeline workflow: language detection failed for %s", slug, exc_info=True)
    return []


def detect_tool_set(session: Session, target: Target) -> dict:
    """Prefer real scan history for this target (what's already been run
    natively against it, see `Finding.tool`) over guessing from GitHub's
    language breakdown -- scan history is ground truth, language detection
    is only a fallback for a target that's never been scanned yet."""
    scanned_tools = session.exec(
        select(Finding.tool).where(Finding.target_id == target.id).distinct()
    ).all()
    if scanned_tools:
        return {"include_gosec": "gosec" in scanned_tools, "source": "scan_history", "languages": []}

    languages = detect_languages(target)
    if languages:
        return {"include_gosec": "Go" in languages, "source": "github_languages", "languages": languages}

    # No scan history and language detection failed/unreachable -- default
    # to the same tool set self-scan.yml uses for a non-Go repo rather than
    # guessing wrong in either direction.
    return {"include_gosec": False, "source": "default", "languages": []}


_SEMGREP_JOB = """
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Semgrep
        run: pip install semgrep
      - name: Run Semgrep
        run: semgrep scan --config=auto --sarif --output=semgrep.sarif || true
      - uses: actions/upload-artifact@v4
        with:
          name: semgrep-results
          path: semgrep.sarif
      - name: Push results to Rikugan
        if: always()
        env:
          RIKUGAN_API_URL: ${{ secrets.RIKUGAN_API_URL }}
          RIKUGAN_API_KEY: ${{ secrets.RIKUGAN_API_KEY }}
        run: |
          if [ -n "$RIKUGAN_API_URL" ] && [ -f semgrep.sarif ]; then
            curl -sS -X POST "$RIKUGAN_API_URL/api/ingest/__TARGET_ID__?tool=semgrep&branch=${{ github.ref_name }}" \\
              -H "X-API-Key: $RIKUGAN_API_KEY" -H "Content-Type: application/json" \\
              --data-binary @semgrep.sarif \\
              || echo "Rikugan ingest push failed -- RIKUGAN_API_URL must be a publicly reachable Rikugan deployment, not localhost"
          else
            echo "Skipping Rikugan push: set the RIKUGAN_API_URL/RIKUGAN_API_KEY repo secrets to enable it."
          fi
"""

_GITLEAKS_JOB = """
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Install Gitleaks
        run: |
          curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar xz gitleaks
      - name: Run Gitleaks
        run: |
          ./gitleaks detect --source . --report-format sarif --report-path gitleaks.sarif --no-git --exit-code 0
      - uses: actions/upload-artifact@v4
        with:
          name: gitleaks-results
          path: gitleaks.sarif
      - name: Push results to Rikugan
        if: always()
        env:
          RIKUGAN_API_URL: ${{ secrets.RIKUGAN_API_URL }}
          RIKUGAN_API_KEY: ${{ secrets.RIKUGAN_API_KEY }}
        run: |
          if [ -n "$RIKUGAN_API_URL" ] && [ -f gitleaks.sarif ]; then
            curl -sS -X POST "$RIKUGAN_API_URL/api/ingest/__TARGET_ID__?tool=gitleaks&branch=${{ github.ref_name }}" \\
              -H "X-API-Key: $RIKUGAN_API_KEY" -H "Content-Type: application/json" \\
              --data-binary @gitleaks.sarif \\
              || echo "Rikugan ingest push failed -- RIKUGAN_API_URL must be a publicly reachable Rikugan deployment, not localhost"
          else
            echo "Skipping Rikugan push: set the RIKUGAN_API_URL/RIKUGAN_API_KEY repo secrets to enable it."
          fi
"""

_TRIVY_JOB = """
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy (filesystem scan)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: sarif
          output: trivy.sarif
          scan-ref: .
      - uses: actions/upload-artifact@v4
        with:
          name: trivy-results
          path: trivy.sarif
      - name: Push results to Rikugan
        if: always()
        env:
          RIKUGAN_API_URL: ${{ secrets.RIKUGAN_API_URL }}
          RIKUGAN_API_KEY: ${{ secrets.RIKUGAN_API_KEY }}
        run: |
          if [ -n "$RIKUGAN_API_URL" ] && [ -f trivy.sarif ]; then
            curl -sS -X POST "$RIKUGAN_API_URL/api/ingest/__TARGET_ID__?tool=trivy&branch=${{ github.ref_name }}" \\
              -H "X-API-Key: $RIKUGAN_API_KEY" -H "Content-Type: application/json" \\
              --data-binary @trivy.sarif \\
              || echo "Rikugan ingest push failed -- RIKUGAN_API_URL must be a publicly reachable Rikugan deployment, not localhost"
          else
            echo "Skipping Rikugan push: set the RIKUGAN_API_URL/RIKUGAN_API_KEY repo secrets to enable it."
          fi
"""

_GOSEC_JOB = """
  gosec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "stable"
      - name: Install gosec
        run: go install github.com/securego/gosec/v2/cmd/gosec@latest
      - name: Run gosec
        run: ~/go/bin/gosec -fmt=sarif -out=gosec.sarif -no-fail ./... || true
      - name: Summarize
        run: |
          echo "## gosec" >> "$GITHUB_STEP_SUMMARY"
          python3 -c "
          import json
          d = json.load(open('gosec.sarif'))
          results = d.get('runs', [{}])[0].get('results', [])
          with open('$GITHUB_STEP_SUMMARY', 'a') as f:
              f.write(f'{len(results)} findings\\n')
          " || true
      - uses: actions/upload-artifact@v4
        with:
          name: gosec-results
          path: gosec.sarif
      - name: Push results to Rikugan
        if: always()
        env:
          RIKUGAN_API_URL: ${{ secrets.RIKUGAN_API_URL }}
          RIKUGAN_API_KEY: ${{ secrets.RIKUGAN_API_KEY }}
        run: |
          if [ -n "$RIKUGAN_API_URL" ] && [ -f gosec.sarif ]; then
            curl -sS -X POST "$RIKUGAN_API_URL/api/ingest/__TARGET_ID__?tool=gosec&branch=${{ github.ref_name }}" \\
              -H "X-API-Key: $RIKUGAN_API_KEY" -H "Content-Type: application/json" \\
              --data-binary @gosec.sarif \\
              || echo "Rikugan ingest push failed -- RIKUGAN_API_URL must be a publicly reachable Rikugan deployment, not localhost"
          else
            echo "Skipping Rikugan push: set the RIKUGAN_API_URL/RIKUGAN_API_KEY repo secrets to enable it."
          fi
"""

_TEMPLATE = """name: __WORKFLOW_NAME__

# Generated by Rikugan DevSecOps Platform (issue #66) for target "__TARGET_NAME__"
# (id __TARGET_ID__). Runs the same open-source scanners Rikugan wraps natively
# in this job -- mirrors this platform's own dogfooding workflow
# (.github/workflows/self-scan.yml) -- then pushes each tool's SARIF output
# back into Rikugan via POST /api/ingest/__TARGET_ID__.
#
# IMPORTANT: GitHub's cloud runners cannot reach a Rikugan backend running on
# localhost. For the "push results to Rikugan" steps below to actually succeed,
# configure these secrets in this repo's Settings > Secrets and variables >
# Actions:
#
#   RIKUGAN_API_URL  - a PUBLICLY REACHABLE deployment of the Rikugan platform
#                  (e.g. behind docker-compose.yml exposed via a real
#                  domain/tunnel). Do NOT set this to http://localhost:8000
#                  -- that only works from your own machine, not from
#                  GitHub's runners.
#   RIKUGAN_API_KEY  - this target's workspace API key
#                  (GET /api/targets/__TARGET_ID__/workspace-key in Rikugan).
#
# Scanning and the job summary/artifacts work regardless of whether these
# secrets are set -- only the "push results to Rikugan" step is skipped/fails
# without them, same degrade-gracefully behavior as self-scan.yml.

on:
  push:
    branches: [__DEFAULT_BRANCH__]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:__JOBS__
"""

# Ordered lookup from tool name -> job YAML block. Order here is only the
# fallback default order (matches #66's original fixed template); a custom
# PipelineWorkflowTemplate's own `steps` order (issue #35) is honored
# instead when one is supplied to generate_workflow_yaml.
_JOB_BLOCKS = {
    "semgrep": _SEMGREP_JOB,
    "gitleaks": _GITLEAKS_JOB,
    "trivy": _TRIVY_JOB,
    "gosec": _GOSEC_JOB,
}


def generate_workflow_yaml(session: Session, target: Target, steps: list[str] | None = None) -> dict:
    """Returns {"yaml": str, "includes_gosec": bool, "languages": [...],
    "detection_source": "scan_history"|"github_languages"|"default"}.

    `steps`, added for issue #35's Custom Workflow Builder, is an optional
    ordered list of tool names (a PipelineWorkflowTemplate's enabled steps,
    already filtered/ordered by the caller -- see
    app.api.pipeline_templates) to include instead of #66's original fixed
    default set. Unknown tool names are dropped rather than raising, since
    validation already happens at template-write time
    (app.api.pipeline_templates); duplicates are collapsed keeping first
    occurrence so a malformed/edited-by-hand template can't double up a job
    name and produce invalid YAML.

    When `steps` is None (every existing #66/#68 call site), behavior is
    byte-for-byte unchanged from before #35: semgrep + gitleaks + trivy
    always, gosec only when `detect_tool_set` finds real evidence of Go."""
    detection = detect_tool_set(session, target)
    if steps is not None:
        seen: set[str] = set()
        tools = []
        for tool in steps:
            if tool in _JOB_BLOCKS and tool not in seen:
                tools.append(tool)
                seen.add(tool)
        includes_gosec = "gosec" in tools
    else:
        # (#232) Was a hardcoded ["semgrep", "gitleaks", "trivy"] regardless
        # of the workspace's ci_pipeline assignment -- a ticked/unticked box
        # on the Tool Marketplace card had no effect on what a *newly
        # generated* workflow actually contained. Only tools with a real job
        # template (_JOB_BLOCKS) can appear here regardless of assignment;
        # within that set, the assignment now decides which are offered.
        #
        # This is a generation-time default, not a live control: it decides
        # what goes into a workflow file the moment it is written, and has
        # no effect on a workflow already committed to a target's repo (see
        # generate_workflow_yaml's docstring and the pipeline-integration UI
        # note -- a durable file on disk in someone else's repo cannot be
        # retroactively rewritten by a later assignment change).
        enabled = set(tools_for_surface(session, target.workspace_id, "ci_pipeline")) & set(_JOB_BLOCKS)
        tools = [t for t in ("semgrep", "gitleaks", "trivy") if t in enabled]
        if detection["include_gosec"] and "gosec" in enabled:
            tools.append("gosec")
        includes_gosec = "gosec" in tools

    jobs_yaml = "".join(_JOB_BLOCKS[t] for t in tools)

    # YAML double-quoted scalar: escape backslashes then quotes so a target
    # name containing `"` or `\` still produces valid YAML.
    safe_name = target.name.replace("\\", "\\\\").replace('"', '\\"')
    yaml_text = _TEMPLATE.replace("__JOBS__", jobs_yaml)
    yaml_text = (
        yaml_text.replace("__WORKFLOW_NAME__", f'"Rikugan Scan ({safe_name})"')
        .replace("__TARGET_ID__", str(target.id))
        .replace("__TARGET_NAME__", target.name)
        .replace("__DEFAULT_BRANCH__", target.default_branch)
    )
    return {
        "yaml": yaml_text,
        "path": WORKFLOW_PATH,
        "includes_gosec": includes_gosec,
        "languages": detection["languages"],
        "detection_source": detection["source"],
    }
