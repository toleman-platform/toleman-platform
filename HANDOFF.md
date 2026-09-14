# Handoff: custom Semgrep rule pack + registry integration

Branch: `scan-engine/multi-language-rule-pack`. Read this file first if
you're picking this up cold — it tells you what exists, what's proven,
what's not, and exactly what to do next. Don't re-derive any of this from
the diff alone; the *why* behind several non-obvious decisions below isn't
visible in the code.

## Goal

Toleman needs to find real vulnerabilities in whatever language a target
repo is written in, cheaply and without duplicating detection the public
Semgrep registry already does well. Concretely, in order:

1. Ship a custom Semgrep rule pack covering vulnerability classes the
   public registry misses or gets wrong for common frameworks (proven
   gaps, not assumed ones — e.g. the registry's only Python SSRF rule is
   hardcoded to Flask and has zero coverage for FastAPI+httpx).
2. Never write a rule for a class the registry already covers well —
   check first, retire on overlap.
3. Combine the two (custom pack + a pruned slice of the registry) in one
   scan that is faster than either `semgrep --config=auto` alone or a
   naive "run everything" combination, with fewer false positives than
   running the registry blind (`--disable-nosem` on rules a human already
   triaged is pure noise).
4. Do all of the above for every language Toleman might need to scan — not
   just the two languages Toleman itself happens to be written in.

Status against that goal: (1) and (2) are done for Python, spot-checked
for the other 5 languages. (3) is designed, implemented, and benchmarked,
but not wired into the product's actual scan path yet. (4) has rules for
6 languages; per-language registry-overlap checking (item 2) has only
actually been done for Python so far — see "Status: done vs. pending"
below for the precise line.

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
- `run_layered_scan()` — runs this repo's own pack and every detected
  language's pruned registry config as **one Semgrep invocation** with
  `--disable-nosem`, reporting the two layers separately.

**Inline suppression is never honoured — and that is why this is one
invocation.** Toleman does not acknowledge a `# nosemgrep` comment. An
ignore is requested and approved in the Toleman dashboard, where it
carries an approval trail and can be revoked; honouring an inline marker
would open a second, invisible suppression channel usable by anyone with
commit access, or by a compromised dependency.

This reverses an earlier design on this branch, so the history is worth
knowing before someone reinstates it. The original split the scan into two
parallel invocations for exactly one reason: `--disable-nosem` is global to
an invocation, and the plan at the time was to disable it for our own rules
while respecting it for the registry layer, on the theory that a
developer's prior triage of a generic rule was worth preserving. That
required a marker-based post-filter as well, because consolidating registry
rules into one file changes their effective `check_id` prefix and silently
breaks Semgrep's own id-based nosemgrep matching. With the policy settled,
all of that came out: the post-filter and its path-resolution helper are
deleted, and one invocation parses each file **once** instead of twice.

Expect raw counts to rise on any repository that already contains
suppression comments. On this repo the registry layer reports 18 where the
old filtered design reported 1; the 17 difference is findings that were
suppressed outside the approval workflow and now have to go through it.
Those are not regressions.

**Smoke-tested end to end**, not just unit-level, against this repo:
```
custom findings:   50
registry findings: 18
```

**Built 2026-09-14** (this section previously listed items 1 and 3 as not
built; both are now done, with tests in `backend/tests/test_rule_selector.py`):

- **Caching.** `build_registry_config()` now writes a sidecar
  `<language>-registry-pruned.meta.json` recording a registry
  fingerprint, the technology folder set, and
  `REGISTRY_CONFIG_SCHEMA_VERSION`, and reuses the built config when all
  three still match. The fingerprint is the clone's git HEAD when
  `registry_root/.git` exists (one subprocess), otherwise a hash of
  `(path, size, mtime)` over just the folders the build would read —
  stat'ing files is cheap, parsing them as YAML is the cost being
  avoided, so the fallback deliberately does not hash contents. Measured
  on this repo against a real clone: Python layer cold 2.55s → warm
  0.33s, TypeScript cold 0.81s → warm 0.06s. Bump the schema constant
  whenever the pruning logic changes, or stale configs get reused.
  `force_rebuild=True` bypasses the check.
- **Polyglot repos.** `run_layered_scan()` no longer stops at the first
  language. Every detected language gets its own pruned config and all of
  them are passed to a single registry invocation (`--config` repeated) —
  still one subprocess, since the parallelism that matters is
  custom-vs-registry, not language-vs-language. A language whose pruned
  config comes out empty is skipped rather than given a `--config` slot.
  `LayeredScanResult.registry_config_path` is accordingly replaced by
  `registry_configs: list[PrunedRegistryConfig]`, with a
  `registry_config_paths` convenience property.
- **TypeScript reads the `javascript/` registry folder too**
  (`REGISTRY_LANGUAGE_ALIASES`). Found while verifying the polyglot path:
  the registry keeps 169 security rules under `javascript/` and only 25
  files under `typescript/`, and 153 of those javascript rules explicitly
  declare `languages: [javascript, typescript]`. Pruning a TypeScript
  repo against `typescript/` alone yielded **1 rule**. Rule ids are
  deduped across the two folders.
- **JavaScript/TypeScript technology signatures.** `TECHNOLOGY_SIGNATURES`
  had entries for Python only, so every other language read its `lang/`
  folder and skipped every framework folder. Added a `_js_sig()` builder
  (package.json dependency keys + `import`/`require` syntax, subpath
  imports included, prefix matches excluded) and a table covering the
  JS/TS registry folders with ≥3 security rules that are real npm
  packages. On this repo that takes the TypeScript layer from 1 rule to
  **39**, correctly detecting `react` and not `express`/`angular`/`nestjs`.
- **A real bug in `_line_has_nosemgrep_marker()`.** It joined Semgrep's
  reported path onto `repo_path`, but Semgrep echoes back the target
  argument it was given — scanning `..` reports `../backend/app/foo.py`,
  and the join produced `../../backend/app/foo.py`, which does not exist.
  The filter then failed open. With a relative `repo_path`, **every**
  suppression silently failed: 18 registry findings, 0 suppressed, 17 of
  them already carrying a human `# nosemgrep:` comment. It hid because
  the original benchmark used an absolute `repo_path`, where
  `os.path.join` discards its first argument and the bug cannot fire.
  `_resolve_reported_path()` now tries the path as reported before
  falling back to the join, and still fails open (surfacing an
  unsuppressed finding beats silently dropping a real one) when neither
  candidate exists.

**Still not built**:
1. **A scheduled job to refresh the vendored `semgrep-rules` clone.**
   The cache above is keyed on that clone's state, but nothing populates
   or updates `SEMGREP_RULES_REGISTRY_ROOT` today. Weekly is plenty —
   this isn't fast-moving content.
2. ~~**`runner.py`/`tool_registry.py` wiring.**~~ **Done 2026-09-15.** Two
   tools, not one: `semgrep-core` (this pack) and `semgrep-registry` (the
   pruned layer), so a Finding carries which layer produced it and per-tool
   coverage can tell them apart. The surface defaults encode the one
   product decision this was waiting on — CI and PR Guardrail gate a
   developer, so they are latency-bound, while on-demand and scheduled
   scans are not and should go as deep as they can. `semgrep-registry`
   therefore defaults **on** for on-demand/scheduled and **off** for
   `ci_pipeline` and `pr_guardrail` (`tool_registry.DEEP_SCAN_ONLY_TOOLS`);
   it is a default, not a prohibition, and an operator can switch it on per
   workspace. An unprovisioned registry clone raises `ToolNotApplicable`
   rather than running semgrep with no `--config`, which would scan nothing,
   exit 0, and ingest as a clean sweep that mitigates every open finding.
   Original reasoning for deferring it is below — see
   "Wiring in" in the README, same reasoning as `semgrep-core` before it:
   tool naming, default on/off per surface, and whether the registry layer
   should ever be allowed to block a PR (its findings are lower-precision
   by construction — they're generic, not app-specific) are real product
   decisions, not something to default silently.
3. **Technology signatures for Go, Java, PHP and Ruby.** Same gap the
   JS/TS table above closed: with no entries, these four read their
   `lang/` folder alone and skip every framework folder in the registry.
   Bounded, measurable work — count each folder's security rules first,
   the way the JS/TS table records its counts, and note that `_sig()`'s
   patterns are Python syntax, so each language needs its own builder
   like `_js_sig()`.
4. **`javascript/browser` (10 security rules) is not selected by
   anything.** It isn't an npm package, so there is nothing to key a
   signature on. The alternative is always-on for every JS/TS repo,
   which would aim DOM rules at pure Node services — decide it against a
   fixture and measure the false positives, don't just default it in.
5. **A `--confidence` filter was tried and explicitly rejected.** Don't
   re-add one without re-reading this: only 19/266 Python security rules
   in the registry are tagged `confidence: HIGH`; `eval-detected` (the
   exact rule that caught PyGoat's live-fired RCE) is tagged `LOW`. A
   HIGH-only filter would have silently dropped it. Confidence tagging in
   this registry does not correlate with "is this rule worth keeping" —
   verified, not assumed.
6. **Non-Python languages' registry folders** haven't been surveyed the
   same way (which Java/Go/PHP/Ruby/JS rules are duplicates of our own —
   only spot-checked a few: CSRF-exempt, pickle, yaml.load, subprocess
   shell=True, mass-assignment, SSRF). A full per-language dedup pass like
   the Python one is real, bounded, valuable follow-up work.

## Status: done vs. pending

**Done, verified:**
- [x] 94-rule custom pack, 6 languages, each rule checked by hand against a real vulnerable-app fixture (or disclosed as synthetic-only where no fixture existed — see the Go section of the README).
- [x] Python rules cross-checked against the actual registry source; 10 duplicate rule ids retired with the specific registry rule that replaces each one named in the README.
- [x] `rule_selector.py` written and smoke-tested end to end against this repo (see "Test plan" below for the exact command and expected numbers).
- [x] The nosemgrep-respecting merge behavior specifically verified (15 raw registry findings → 1 after the marker-based post-filter, on this repo's own source).

- [x] Pruned-registry caching with fingerprint + schema-version invalidation, benchmarked cold vs. warm against a real clone (2026-09-14).
- [x] `run_layered_scan()` handles every detected language, not just the first (2026-09-14).
- [x] TypeScript pulls the `javascript/` registry folder; JS/TS technology signatures added — took this repo's TypeScript layer from 1 rule to 39 (2026-09-14).
- [x] `_line_has_nosemgrep_marker()` path-resolution bug fixed — it had been failing open on every suppression whenever `repo_path` was relative (2026-09-14).
- [x] 22 tests in `backend/tests/test_rule_selector.py`, hermetic (they build a miniature fake registry rather than depending on a network clone).

- [x] Inline suppression never honoured, and the scan collapsed to one invocation now that nothing needs a per-layer nosem policy (2026-09-15).
- [x] `runner.py`/`tool_registry.py` wiring, as `semgrep-core` and `semgrep-registry`, with CI/PR-vs-scheduled surface defaults (2026-09-15).

**Designed and prototyped, not yet in the product's actual scan path:**
- [ ] A scheduled job to fetch/refresh the vendored `semgrep-rules` clone itself — nothing populates `SEMGREP_RULES_REGISTRY_ROOT` today. The cache is keyed on that clone's state, so it is correct but never refreshed until this exists.

**Not started / explicitly out of scope for this branch:**
- [ ] Registry-overlap check for Java/PHP/Ruby/Go/JS rules (only Python's was done — see item 6 under "Still not built" above).
- [ ] Technology signatures for Go/Java/PHP/Ruby (item 3 above) — those four still read `lang/` alone.
- [ ] Whether `javascript/browser`'s 10 rules should be always-on for JS/TS repos (item 4 above).
- [ ] CSS injection/exfiltration rule (the one class in the taxonomy with zero coverage in any language).
- [ ] Anything DAST-side (the "Confirmation Loop" design from earlier in this work — route resolution, live-request confirmation) — a related but separate effort, not touched on this branch.

## Test plan

Everything below is meant to be runnable cold, with nothing but this repo
and a `pip install semgrep pyyaml` (or the versions already pinned in
`backend/requirements.txt`). No network calls except the one-time registry
clone.

**1. The rule pack is syntactically valid and has the expected rule count:**
```bash
semgrep scan --config=backend/app/scanners/rules/core --validate
# expect: "Configuration is valid - found 0 configuration error(s), and 94 rule(s)."
```
If the count is off, something was added/removed since this doc was
written — check `git log` on that directory before assuming this doc is
wrong.

**2. The pack still finds what it's supposed to.** Clone the fixtures (URLs
in the "Current state" table above) and run:
```bash
semgrep scan --config=backend/app/scanners/rules/core --disable-nosem --json <fixture-path>
```
Known-good reference points to check the output against (all re-confirmed
the same day this branch was pushed):
- Against **this repo**: the SSRF rule fires on `backend/app/core/slack_integration.py:28`; the exception-info-exposure rules fire on `backend/app/api/pr_guardrail.py` and `backend/app/api/config.py` (3 spots); `hardcoded-secret-assignment` and `hardcoded-encryption-key-or-iv-assignment` both find **zero** hits (confirmed true negative, not a broken rule).
- Against **PyGoat**: `toleman-code-injection-eval-exec` fires on `introduction/mitre.py:218`; `toleman-xxe-external-entities-explicitly-enabled` fires on `introduction/views.py:259`; `toleman-django-debug-true` fires on `pygoat/settings.py:30`.
- Against **DVPWA**: `toleman-sql-injection-fstring-var-then-execute` fires on `sqli/dao/student.py:45`.

If any of these go silent, that's a regression — bisect from there, don't
assume the fixture changed.

**3. The unit tests** — hermetic, no clone and no semgrep binary needed,
so run these before anything slower:
```bash
cd backend && python3 -m pytest tests/test_rule_selector.py -q
# expect: 22 passed
```
They cover cache hit/miss, every invalidation path (registry content,
technology set, schema version, corrupt metadata, git HEAD), the
`javascript/` alias, JS/TS framework detection, polyglot layering, and
the nosemgrep path resolution described above.

**4. `rule_selector.py` end to end** (this is the one that catches "the
rule pack passes but the file was never actually written" — see the meta-
lesson below). Needs a `semgrep/semgrep-rules` clone and takes ~50s:
```bash
cd backend && python3 -c "
from app.scanners import rule_selector as rs
result = rs.run_layered_scan(
    '..',
    custom_config_path='app/scanners/rules/core',
    registry_root='<path to a semgrep/semgrep-rules clone>',
)
print('custom findings:', len(result.custom_findings))                    # expect 50
print('registry before filter:', result.registry_findings_before_filter)  # expect 18
print('registry after filter:', len(result.registry_findings))            # expect 1
print([(c.language, c.rule_count) for c in result.registry_configs])      # expect python 112, typescript 39
"
```
These were the exact numbers on 2026-09-14 against a clone of that date.
Read them as follows:

- A different `custom findings` count most likely means a rule file
  changed — 50 has held since the branch was first pushed.
- `registry before filter` was 15 before the TypeScript layer existed;
  the extra 3 are `unsafe-dynamic-method` in
  `frontend/src/hooks/use-tool-install.ts`, all three already carrying a
  developer's `// nosemgrep:` comment, so they filter out.
- `registry after filter` climbing back toward `before filter` means the
  nosemgrep post-filter broke — check `_resolve_reported_path()` first,
  then `_line_has_nosemgrep_marker()`. That is exactly how the path bug
  fixed on 2026-09-14 presented (18 in, 18 out).
- The one surviving finding should be `use-defusedcsv` on
  `backend/app/core/csv_export.py:28`. That is the honest residual
  documented above — a class named `SafeCsvWriter` that nobody had
  reviewed or suppressed — not a filter failure.
- Registry rule counts depend on the clone's date; treat a modest drift
  as the registry moving, a collapse to single digits as a pruning or
  alias regression.

**5. Manual spot-check, not just automated**: pick at least one finding
from step 2 or 3 and open the actual file at that line yourself before
trusting any of the above. That's the standard this whole pack was held
to — a green test run is necessary, not sufficient.

## Immediate next steps, roughly in order

1. Decide and implement the `runner.py` wiring (see README's "Wiring in").
   Suggested shape, not gospel: a `semgrep-core` tool entry for the custom
   pack (as already sketched), plus a separate `semgrep-registry` tool
   entry for the pruned layer, both surfaced independently in Tool
   Marketplace/per-tool coverage so an operator can turn the (lower-
   precision, broader-recall) registry layer off without losing the
   custom pack.
2. Add the scheduled refresh for the vendored `semgrep-rules` clone. The
   cache is keyed on that clone, so until this exists the pruned configs
   are correct and permanently stale.
3. Add technology signatures for Go/Java/PHP/Ruby, the way the JS/TS ones
   were added — each needs its own `_sig`-style builder, since `_sig()`'s
   patterns are Python import syntax.
4. Run the same registry-duplicate-check done for Python against the other
   5 languages' rule files, and retire what's genuinely redundant there
   too.
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
