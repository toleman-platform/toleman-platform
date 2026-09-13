# Handoff: custom Semgrep rule pack + registry integration

Branch: `scan-engine/multi-language-rule-pack`. Read this file first if
you're picking this up cold — it tells you what exists, what's proven,
what's not, and exactly what to do next. Don't re-derive any of this from
the diff alone; the *why* behind several non-obvious decisions below isn't
visible in the code.

## What this branch is

Toleman already had a `semgrep-llm` custom ruleset (`backend/app/scanners/
rules/llm/`) wired into `runner.py`. This branch adds a second one,
`backend/app/scanners/rules/core/`, aimed at general vulnerability classes
(not LLM-specific), plus a not-yet-wired-in design for combining it with
the public [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)
registry instead of duplicating what that registry already covers well.

**Everything in this pack was validated by cloning a real vulnerable app
and manually reading the matched line before trusting a rule — never
shipped on "the pattern looks right."** That discipline is why this took
as long as it did, and it's the thing to preserve if you keep extending it.
Read `backend/app/scanners/rules/core/README.md` for the full validation
methodology and the per-rule status table — this file is about *status and
next steps*, that one is about *what was checked and how*.

## Current state — 94 rules, 6 languages, validated against 9 real repos

| Language | Fixture(s) used | Notes |
|---|---|---|
| Python | this repo, [PyGoat](https://github.com/adeyosemanputra/pygoat), [DVPWA](https://github.com/anxolerd/dvpwa) | Core of the pack. PyGoat is the richest ground truth (labeled OWASP labs). |
| TypeScript/JS | this repo's own frontend | `xss-js/` — DOM-XSS, Web Storage, postMessage, prototype pollution |
| Java | [OWASP WebGoat](https://github.com/WebGoat/WebGoat) | 13 rules, most with real hits |
| PHP | [DVWA](https://github.com/digininja/DVWA) | 8 rules |
| Ruby | [RailsGoat](https://github.com/OWASP/railsgoat) | 12 rules, 8 with real hits |
| Go | [govwa](https://github.com/0c34/govwa), [go-dvwa](https://github.com/sqreen/go-dvwa), [go-test-bench](https://github.com/Contrast-Security-OSS/go-test-bench) | 10 rules; 3 validated only against hand-written synthetic files (no real repo had the shape) — disclosed, not hidden |

All of these repos were cloned locally to validate against, not committed
to this repo. If you're continuing this work, re-clone them (URLs above)
rather than assuming they're anywhere in this checkout.

**Retired, 2026-09-13**: 5 files / 10 rule ids (SQLi ×4, insecure
deserialization ×2, eval/exec + shell=True, CSRF-exempt, weak-hash) were
deleted after confirming the public registry already has an equivalent,
proven on real code this session (see README's "Registry integration"
section for exactly which registry rule covers which). Don't
re-add these without re-checking the registry first — that's the entire
point of the exercise below.

## The registry-integration design — what's built, what's not

**Built and tested**: `backend/app/scanners/rule_selector.py`. Three
functions, each independently benchmarked before being written as real
code:

- `detect_languages()` / `detect_technologies()` — the latter checks the
  root manifest AND greps actual import statements repo-wide. The
  import-grep half exists because manifest-only detection missed a Flask
  sub-app embedded inside PyGoat (mostly Django) during benchmarking —
  cost real coverage until fixed.
- `build_registry_config()` — prunes a vendored `semgrep-rules` clone down
  to `category: security` rules for the detected technologies, merged into
  **one file per language**. The one-file requirement isn't style: the
  registry's native layout (hundreds of small per-topic files) took ~2x as
  long to load as the identical rules in one file, for zero coverage
  difference. Measured, not assumed.
- `run_layered_scan()` — runs this repo's own pack and the pruned registry
  config as **two separate Semgrep invocations, in parallel**, with
  different `--disable-nosem` policies (on for our pack, off for the
  registry layer), then merges with a marker-only nosemgrep post-filter.

**Why two invocations and a custom post-filter, not one `--config` list**:
`--disable-nosem` is all-or-nothing per Semgrep invocation. This pack
wants it on for its own narrow rules (matches the existing `semgrep-llm`
posture: a compromised dependency shouldn't blind the scanner via a
comment) but *off* for the registry layer, so a developer's prior,
legitimate triage of a generic finding isn't defeated. Measured on this
repo: running the registry layer with `--disable-nosem` produced 15
findings, **all 15 false positives**, 14 of which already carried a human
`# nosemgrep: <exact-id>` comment. Respecting nosemgrep should have
dropped those 14 automatically — it didn't, because consolidating rules
into a new file changes their effective check_id prefix (from e.g.
`python.lang.security.audit.dangerous-subprocess-use-audit` to whatever
this repo's local config path resolves to), which breaks Semgrep's
id-based nosemgrep matching against a comment written for the *original*
path. The fix implemented in `_line_has_nosemgrep_marker()`: check the
flagged line for *any* nosemgrep marker, not an exact id match. Confirmed
this brings 15 → 1 (the one remaining finding — `use-defusedcsv` on a
class literally named `SafeCsvWriter` — had never been reviewed/suppressed
by anyone before, so no marker-based filter could know it's safe; that's
an honest residual, not a filter bug).

**Smoke-tested end to end**, not just unit-level:
```
custom findings: 50
registry findings before filter: 15
registry findings after nosemgrep filter: 1
```
matches the manual benchmark run exactly.

**Not built yet**:
1. **Caching.** `build_registry_config()` rebuilds its pruned/consolidated
   file from scratch every call — fine for a benchmark, wrong for
   production (parsing ~2000 YAML files per scan defeats the whole point).
   Needs a freshness check against `cache_dir` before rebuilding, and
   probably a scheduled job that refreshes the vendored `semgrep-rules`
   clone itself (weekly cron is plenty — this isn't fast-moving content).
2. **`runner.py`/`tool_registry.py` wiring.** Deliberately not done — see
   "Wiring in" in the README, same reasoning as `semgrep-core` before it:
   tool naming, default on/off per surface, and whether the registry layer
   should ever be allowed to block a PR (its findings are lower-precision
   by construction — they're generic, not app-specific) are real product
   decisions, not something to default silently.
3. **Multi-language repos in one scan.** `run_layered_scan()` picks the
   *first* detected language with a non-empty pruned config and stops —
   see the `TODO` inline. A repo with both a Python backend and a
   TypeScript frontend (like this one) needs both languages' registry
   configs merged into the run, not just one.
4. **A `--confidence` filter was tried and explicitly rejected.** Don't
   re-add one without re-reading this: only 19/266 Python security rules
   in the registry are tagged `confidence: HIGH`; `eval-detected` (the
   exact rule that caught PyGoat's live-fired RCE) is tagged `LOW`. A
   HIGH-only filter would have silently dropped it. Confidence tagging in
   this registry does not correlate with "is this rule worth keeping" —
   verified, not assumed.
5. **Non-Python languages' registry folders** haven't been surveyed the
   same way (which Java/Go/PHP/Ruby/JS rules are duplicates of our own —
   only spot-checked a few: CSRF-exempt, pickle, yaml.load, subprocess
   shell=True, mass-assignment, SSRF). A full per-language dedup pass like
   the Python one is real, bounded, valuable follow-up work.

## Immediate next steps, roughly in order

1. Add the freshness-check/caching to `build_registry_config()` — this is
   the one thing that makes the whole design production-viable instead of
   a nice benchmark.
2. Decide and implement the `runner.py` wiring (see README's "Wiring in").
   Suggested shape, not gospel: a `semgrep-core` tool entry for the custom
   pack (as already sketched), plus a separate `semgrep-registry` tool
   entry for the pruned layer, both surfaced independently in Tool
   Marketplace/per-tool coverage so an operator can turn the (lower-
   precision, broader-recall) registry layer off without losing the
   custom pack.
3. Run the same registry-duplicate-check done for Python against the other
   5 languages' rule files, and retire what's genuinely redundant there
   too.
4. Fix `run_layered_scan()`'s single-language limitation for polyglot
   repos.
5. The pack itself still has real gaps, not registry-integration gaps —
   see `backend/app/scanners/rules/core`'s companion tracker artifact from
   this session (ask the user for the link if you need the full taxonomy
   view; not checked into this repo) for what's validated vs. written-but-
   unproven vs. genuinely not started. CSS injection/exfiltration is the
   one class with literally no rule yet, in any language.

## A meta-lesson worth internalizing before you write more rules

**A benchmark run only proves what it actually ran against — always
`ls`/`git status` your rule directory after "finishing" a batch, don't
trust a green benchmark alone.** The XXE/CORS/TLS/hardcoded-secret/
insecure-random/eval-exec/shell-true rules were validated multiple times in
the session that produced this branch — including a live-fired
unauthenticated RCE proof — and the files were *never actually written to
disk in this repo*. Every "whole pack" benchmark that session ran against
a silently incomplete copy. It was caught only because a later benchmark's
rule count (96) didn't match a manual recount, and someone thought to
`grep` for the missing rule ids across the whole tree instead of trusting
the number. If a rule you wrote isn't showing up in `git status`, it isn't
real yet, no matter what a scratch-file test run said.
