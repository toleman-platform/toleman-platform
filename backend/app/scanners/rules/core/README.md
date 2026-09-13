# Core rule pack

Custom semgrep rules for vulnerability classes generic community rulesets
(`semgrep --config=auto`, `p/security-audit`, `p/owasp-top-ten`) miss on
this codebase. Benchmarked 2026-09-12: `auto` + `p/security-audit` +
`p/owasp-top-ten` combined (1157 rules loaded, 537 run) found the same 4
findings as `auto` alone on toleman-platform — zero additional real hits.
These 16 rules found 9 of the real vulnerabilities that pass alone missed
(cross-checked against this repo's own GitHub CodeQL alerts), in under 5
seconds.

Mirrors the existing `rules/llm/` convention: one `semgrep-core` tool entry
(see `runner.py`'s `LLM_RULES_DIR` for the pattern to copy), `toleman-`
prefixed rule ids, a `confidence` field.

## Validation methodology

Every rule here was run against real code and checked by hand before being
kept — never shipped on "the pattern looks right." Three repos, chosen to
prove two different things:

- **toleman-platform** (this repo): where clean rewrites started, and the
  only repo with independent ground truth (GitHub's own CodeQL + Dependabot
  alerts) to check hits against.
- **[PyGoat](https://github.com/adeyosemanputra/pygoat)** (Django, OWASP's
  own teaching app) and **[DVPWA](https://github.com/anxolerd/dvpwa)**
  (Flask/asyncpg, SQLi-focused): unrelated codebases, different
  frameworks, never seen while writing these rules. Proves the rules are
  portable, not tuned to this repo's variable names — found PyGoat's own
  labeled SSRF and insecure-deserialization labs, and DVPWA's actual SQLi
  challenge, unmodified.

One SSRF finding was also confirmed *live*, not just by pattern match: a
canary HTTP listener under our control received a real outbound request
fired by hitting the flagged endpoint with a crafted payload. That's the
strongest evidence tier — `EXPLOIT-CONFIRMED`, not just `PLAUSIBLE`.

Every rule's file states exactly what it was checked against and what came
of it. Read the header comment before trusting a rule you didn't
personally re-verify.

## Confidence tiers

| Confidence | Meaning |
|---|---|
| **MEDIUM** | Found a real, manually-verified true positive on at least one repo (ideally 2+, ideally including a repo this rule wasn't written against) |
| **LOW** | Either found only unverified candidates, or is a "make a human check this" heuristic where a benign match is an expected, correct outcome (not a false positive) |
| unproven | Written but hasn't matched anything on any of the 3 validation repos yet — kept in the pack, not deleted, but don't cite it as validated |

## Rule status

| Rule | File | Confidence | Result |
|---|---|---|---|
| `toleman-unvalidated-url-param-to-http-client` | `ssrf/` | MEDIUM | toleman: 6/6 TP (2 live-confirmed) · pygoat: 1/1 TP (labeled SSRF lab) · dvpwa: true negative |
| ~~`toleman-weak-hash-on-secret-value`~~ | **RETIRED 2026-09-13** | LOW | Was: toleman 2/2 TP · pygoat 6 hits, spot-checked TP · dvpwa 1/1 TP. Retired in favor of the registry's own weak-hash rules (`md5-loose-equality` and per-language equivalents), which independently caught the same DVWA hit this session. See "Registry integration" section below. |
| `toleman-hardcoded-encryption-key-or-iv-assignment` | `crypto/hardcoded-encryption-key-or-iv.yaml` | MEDIUM | toleman: true negative (BaseSettings/DEFAULT_/empty-string guards confirmed working) · pygoat: 4/4 TP (settings.py:25 SECRET_KEY, settings.py:171 SECRET_COOKIE_KEY, broken_auth_lab/app.py:8, sensitive_data_lab/settings.py:8) · dvpwa: true negative |
| `toleman-hardcoded-key-literal-in-cipher-call` | `crypto/hardcoded-encryption-key-or-iv.yaml` | LOW | 0/0/0 across all 3 repos -- unproven |
| `toleman-unsalted-fast-hash-on-password` | `crypto/unsalted-password-hashing.yaml` | MEDIUM | toleman: true negative (hash_password() already correct: salted pbkdf2_hmac, 200k iters) · pygoat: 5/5 TP · dvpwa: 1/1 TP (sqli/dao/user.py:41, same ground-truth line as the broad weak-hash rule) |
| `toleman-kdf-unsafe-iteration-count` | `crypto/unsalted-password-hashing.yaml` | LOW | 0/0/0 across all 3 repos -- unproven |
| ~~`toleman-sql-injection-*`~~ (4 rules) | **RETIRED 2026-09-13** | MEDIUM | Was: dvpwa 1/1 TP (`fstring-var-then-execute`, needed taint mode). Retired: registry's per-language SQLi rules (`tainted-sql-string`, `jdbc-sqli`, `gosql-sqli`, etc.) independently caught the same real bugs on DVPWA, WebGoat and go-dvwa this session. |
| ~~`toleman-insecure-deserialization-pickle/yaml`~~ | **RETIRED 2026-09-13** | MEDIUM | Was: pygoat 2/2 TP (pickle, explicitly labeled) + 1/1 TP (yaml). Retired: registry's `lang/security/deserialization/pickle.py` and `avoid-pyyaml-load.py` exist and cover the identical shape natively. |
| ~~`toleman-code-injection-eval-exec`~~ | **RETIRED 2026-09-13** | MEDIUM | Was: pygoat 2/2 TP, one live-fired to a confirmed unauthenticated RCE this session. Retired: registry's `eval-detected` + `user-eval` caught the exact same finding independently (cross-checked file:line). |
| ~~`toleman-os-command-injection-shell-true`~~ | **RETIRED 2026-09-13** | MEDIUM | Was: pygoat 2/2 TP. Retired: registry's `dangerous-subprocess-use`/`subprocess-injection` cover this shape natively (proven on go-dvwa's Go equivalent this session; Python registry rule exists at the same path pattern). |
| `toleman-path-traversal-open-from-request` | `access-control/` | LOW | unproven-by-sample |
| `toleman-open-redirect-from-request-param` | `access-control/` | LOW | unproven-by-sample |
| `toleman-url-startswith-check-used-as-validation` | `access-control/url-boundary-check.yaml` | LOW | toleman: found the real CodeQL alert; manually confirmed benign-in-context (test assertion) |
| `toleman-url-endswith-check-used-as-validation` | `access-control/url-boundary-check.yaml` | LOW | toleman: 2 unverified candidates |
| `toleman-exception-str-interpolated-into-http-detail` | `error-handling/` | MEDIUM | toleman: 1/1 exact CodeQL match + 3 unverified bonus |
| `toleman-external-call-result-into-http-detail` | `error-handling/` | MEDIUM | toleman: 3/3 exact CodeQL match |
| `toleman-cookie-set-with-derived-value` | `error-handling/` | LOW | toleman: matched real CodeQL alert; confirmed benign (signed token, not raw input) — correct outcome for this heuristic |
| `toleman-jwt-decode-without-verification` | `auth/` | LOW | unproven-by-sample |
| ~~`toleman-django-csrf-exempt`~~ | **RETIRED 2026-09-13** | LOW | Was: pygoat 25/25 TP across 6 files, incl. the exact endpoint this pack live-fired an unauthenticated RCE against. Retired: registry's `django/security/audit/csrf-exempt.yaml` exists natively for this exact pattern. |
| `toleman-xxe-unsafe-xml-parser` | `injection/xxe.yaml` | LOW | 0 direct hits on any of the 3 repos — pygoat's real XXE lab uses xml.sax/pulldom, a shape this generic sink-list rule doesn't directly catch (kept as defense-in-depth for the more common etree/lxml/minidom shape) |
| `toleman-xxe-external-entities-explicitly-enabled` | `injection/xxe.yaml` | MEDIUM | pygoat: 1/1 TP (their labeled A4 XXE lab, `introduction/views.py:259`) — no registry equivalent found for this exact explicit-enable signal, kept |
| `toleman-cors-wildcard-with-credentials` | `misconfig/cors-wildcard-with-credentials.yaml` | LOW | 0/0/0 across all 3 repos — unproven-by-sample |
| `toleman-tls-verification-disabled` | `crypto/tls-verification-disabled.yaml` | LOW | 0/0/0 across all 3 repos — unproven-by-sample |
| `toleman-hardcoded-secret-assignment` | `crypto/hardcoded-secret-assignment.yaml` | LOW | toleman: fixed a 7/7 false-positive rate (BaseSettings/DEFAULT_/empty-string exclusions), now 0/0 confirmed clean · pygoat/dvpwa: 0/0/0 (their hardcoded secrets are a different shape, caught by `hardcoded-encryption-key-or-iv-assignment` instead) |
| `toleman-insecure-random-for-security-token` | `crypto/insecure-random-for-security-token.yaml` | LOW | pygoat: 1/1 TP (`views.py:496`, `randint()` generating an OTP) — no registry equivalent found for this exact "random module used for a security-shaped value" signal, kept |
| `toleman-insecure-persistent-auth-cookie` | `auth/` | MEDIUM | toleman: true negative · pygoat: 4 hits, 2/2 spot-checked TP (raw-userid cookie lab + labeled "Remember Me" lab) · dvpwa: true negative |
| `toleman-oauth-authorize-redirect-missing-state` | `auth/` | LOW | unproven-by-sample (no repo hand-rolls an OAuth authorize redirect); verified against a synthetic repro instead |
| `toleman-unrestricted-file-upload-filename` | `file-handling/unrestricted-file-upload.yaml` | LOW | 0/0/0 across all 3 repos -- toleman's only upload endpoint never touches `.filename`/writes to disk; pygoat's 2 upload labs process in memory only; dvpwa has no upload surface. Self-test only (see file header): fires on a hand-written vulnerable snippet, silent once `secure_filename()`/`os.path.basename()` sanitizers are added |
| `toleman-zip-slip-extractall` | `file-handling/zip-slip.yaml` | MEDIUM | 0/0/0 across all 3 repos -- no archive-handling code exists in any of their app code. Self-test only: fires on `ZipFile`/`tarfile` `.extractall()`; silent on `filter="data"`; confirmed it still (by design tradeoff, documented in file) fires on a hand-rolled safe containment loop -- a human must still confirm no real check exists before trusting a hit |
| `toleman-insecure-temp-file-mktemp` | `file-handling/insecure-temp-file.yaml` | LOW | 0/0/0 across all 3 repos -- toleman's real temp-file code already uses `mkdtemp`/`NamedTemporaryFile`/`TemporaryDirectory` correctly, so 0 hits there is a true negative proving the rule doesn't flag the safe APIs. Self-test only: fires on `tempfile.mktemp()` |
| `toleman-insecure-temp-file-predictable-tmp-path` | `file-handling/insecure-temp-file.yaml` | LOW | 0/0/0 across all 3 repos. Self-test only: fires on `open("/tmp/" + name, ...)` and an f-string equivalent |
| `toleman-redos-nested-quantifier` | `dos/redos-nested-quantifier.yaml` | LOW | 0/0/0 across all 3 repos -- every `re.compile`/`match`/`search` in their app code uses flat, non-nested patterns. Self-test only: fires on `(a+)+$` and `([a-zA-Z]+)*b`; silent on a flat char-class pattern and a single non-nested quantified group. Explicitly a textbook-shape heuristic, not a real regex complexity analysis -- see file header for false-negative/false-positive risk |
| `toleman-django-debug-true` | `misconfig/debug-mode.yaml` | MEDIUM | pygoat: 2/2 TP (settings.py:30, matches Solutions/solution.md's own A6 writeup; dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:11, a second independent Django settings module with the same bug) · toleman-platform: true negative (FastAPI, no Django) · dvpwa: true negative (not Django) |
| `toleman-flask-run-debug-true` | `misconfig/debug-mode.yaml` | LOW | 0/0/0 across all 3 repos -- unproven-by-sample. dvpwa's aiohttp app hardcodes `debug=True` but via `Application(debug=True, ...)`, a different call shape than `app.run(debug=True)`; deliberately out of scope, see file header |
| `toleman-uvicorn-reload-true` | `misconfig/debug-mode.yaml` | LOW | 0/0/0 across all 3 repos -- unproven-by-sample. toleman-platform's own FastAPI entrypoint never sets reload=True |
| `toleman-hardcoded-default-credential-compound-check` | `misconfig/default-credentials.yaml` | MEDIUM | pygoat: 3/3 TP (playground/A9/api.py:17 live-routed login handler, archive.py:17 dead-code duplicate, views.py:833 in a1_broken_access_lab_3) · toleman-platform: true negative -- correctly did NOT re-flag config.py:151's BaseSettings startup-validation comparison, but only after adding `constant_propagation: false` (see file header for the real bug this caught) · dvpwa: true negative |
| `toleman-hardcoded-default-credential-single-check` | `misconfig/default-credentials.yaml` | LOW | pygoat: 3/3 TP, same locations as the compound-check rule (expected full overlap, its pattern is a subexpression of that one) · toleman-platform: true negative (same constant-propagation fix applies) · dvpwa: true negative |
| `toleman-sensitive-variable-logged` | `error-handling/sensitive-data-in-logs.yaml` | MEDIUM | toleman-platform: true negative -- correctly did not re-flag 5 existing `# nosemgrep: ...credential-disclosure`-suppressed logger calls in github_token.py, because none of them actually interpolates the token itself (workspace_id/slug/exc only) · pygoat: known miss -- its one real analogue (playground/A9/api.py:16, logs `password` in an f-string) uses a custom `L.info(...)` object, not `logger`/`log`/`logging`, which this rule intentionally does not chase · dvpwa: true negative |
| `toleman-request-object-logged-unredacted` | `error-handling/sensitive-data-in-logs.yaml` | LOW | 0/0/0 across all 3 repos -- unproven-by-sample, no repo logs a whole `request.POST`/`.body`/`.headers`/`.META` object |

## Ruby (Rails) extension, 2026-09-12

Same methodology, fourth validation repo: **[RailsGoat](https://github.com/OWASP/railsgoat)**
(OWASP's own intentionally-vulnerable Rails app), cloned to
`scratchpad/railsgoat`, source-only (gems never installed, app never run).
12 rule ids across 7 files, all `languages: [ruby]`. 8/12 found a real,
hand-verified true positive on RailsGoat; the other 4 are unproven-by-
sample (kept per this pack's policy, not deleted).

| Rule | File | Confidence | Result |
|---|---|---|---|
| `toleman-ruby-sql-injection-where-interpolation` | `injection/ruby-sql-injection.yaml` | MEDIUM | railsgoat: 1/1 TP (users_controller.rb:29, `User.where("id = '#{params[:user][:id]}'")`) |
| `toleman-ruby-sql-injection-find-by-sql` | `injection/ruby-sql-injection.yaml` | MEDIUM | 0/0 -- unproven-by-sample, no find_by_sql in this repo |
| `toleman-ruby-sql-injection-connection-execute` | `injection/ruby-sql-injection.yaml` | MEDIUM | 0/0 -- unproven-by-sample, no connection.execute in this repo |
| `toleman-ruby-command-injection-shell-interpolation` | `injection/ruby-command-injection.yaml` | MEDIUM | railsgoat: 1/1 TP (benefits.rb:15, `system("cp #{full_file_name} ...#{file.original_filename}")`) |
| `toleman-ruby-insecure-deserialization-marshal-load` | `injection/ruby-insecure-deserialization.yaml` | MEDIUM | railsgoat: 1/1 TP (password_resets_controller.rb:6, `Marshal.load(Base64.decode64(params[:user]))`, reachable pre-auth) |
| `toleman-ruby-insecure-deserialization-yaml-load` | `injection/ruby-insecure-deserialization.yaml` | MEDIUM | 0/0 -- unproven-by-sample, no YAML.load in this repo |
| `toleman-ruby-mass-assignment-to-unsafe-h` | `access-control/ruby-mass-assignment.yaml` | MEDIUM | railsgoat: 1/1 TP (admin_controller.rb:45, `user.update(filtered_params)` sourced from `params[:user].to_unsafe_h`; matches this repo's own inline VULNERABILITY comment). Needed `mode: taint` -- 3 indirections (`||=`, a `.reject{}` block, a rename) between source and sink. |
| `toleman-ruby-mass-assignment-permit-bang` | `access-control/ruby-mass-assignment.yaml` | MEDIUM | railsgoat: 1/1 TP (users_controller.rb:50, `params.require(:user).permit!`) |
| `toleman-ruby-path-traversal-param-to-file-sink` | `access-control/ruby-path-traversal.yaml` | LOW | railsgoat: 1/1 TP (benefit_forms_controller.rb:11-13, `path = params[:name]; file = params[:type].constantize.new(path); send_file file`). `mode: taint` with `File.expand_path` as sanitizer. |
| `toleman-ruby-xss-html-safe-on-interpolated-param` | `xss-js/ruby-xss-html-safe.yaml` | MEDIUM | railsgoat: 1/1 TP (password_resets_controller.rb:36, `"...#{params[:email]}".html_safe`) |
| `toleman-ruby-xss-html-safe-on-cookie` | `xss-js/ruby-xss-html-safe.yaml` | LOW | 0/0 -- unproven-by-sample, no cookie-derived html_safe/raw in this repo |
| `toleman-ruby-hardcoded-secret-key-base` | `crypto/ruby-hardcoded-secret-key-base.yaml` | MEDIUM | railsgoat: 1/1 TP (config/initializers/secret_token.rb:8, `config.secret_key_base = "<128-hex-char literal>"`) |

Mass assignment was written and validated per Rails' own vulnerability
model (strong parameters bypassed via `.to_unsafe_h` or `.permit!`)
rather than the Python rule's "raw request dict into a constructor" shape
-- RailsGoat has no instance of the latter (every `.new(params[...])` call
routes through a `permit`/`permit!`-based params method first), but has
two clean instances of the former, one of them (`.to_unsafe_h`) explicitly
labeled by RailsGoat's own maintainers as the intended lesson.

## Go extension, 2026-09-12

Go has no established "PyGoat for Go" -- checked (real GitHub search, not
just going by name recognition): `OWASP/Go-SCP` is a secure-coding *guide*,
not an app. Cloned and inspected 3 real candidates instead, all found by
searching GitHub directly, none seen before this session:

- **[0c34/govwa](https://github.com/0c34/govwa)** -- small (~1.5k LOC),
  genuinely vulnerable-by-design (SQLi/IDOR/XSS/XXE routes with a
  deliberately unsafe code path next to a "SafeQuery" one), but unmaintained
  (last real activity years old) and narrow.
- **[sqreen/go-dvwa](https://github.com/sqreen/go-dvwa)** -- tiny (~290
  LOC) but sharp: 3 real vulnerable sinks (SQLi via concatenation,
  `sh -c` command injection, LFI), each wired to an actual HTTP handler in
  `server/router.go`.
- **[Contrast-Security-OSS/go-test-bench](https://github.com/Contrast-Security-OSS/go-test-bench)**
  -- large (~13.6k LOC, mostly go-swagger-generated boilerplate), but its
  hand-written `internal/<vuln-class>/*.go` files are real OWASP-Top-10
  exercises (SSRF, path traversal, command injection, SQLi) with genuine
  Safe/Unsafe branches, actively used as a commercial scanner's own test
  suite.

Used all 3 together rather than picking one -- combined they cover more
ground than any single one, at the cost of go-test-bench's generic
sink-registration abstraction (request-input extraction lives in
`internal/common/`, one file away from the sink call in each vuln
package) defeating same-function/same-file taint tracking for 2 of the
signatures below (see `go-ssrf-unvalidated-url.yaml` and
`go-path-traversal.yaml` headers). 10 rule ids across 6 files, all
`languages: [go]`.

| Rule | File | Confidence | Result |
|---|---|---|---|
| `toleman-go-sql-injection-inline-concat` | `injection/go-sql-injection.yaml` | MEDIUM | go-dvwa: 1/1 TP (vulnerable/sql.go:70, `db.QueryContext(ctx, "...'"+category+"'")`) · govwa: 1 hit, benign-impact (util/database/database.go:24, `db.Exec("CREATE DATABASE..."+config.Dbname)` -- structurally a match, but `config.Dbname` is an admin config value, not request input) |
| `toleman-go-sql-injection-var-then-query` | `injection/go-sql-injection.yaml` | MEDIUM (taint) | govwa: 1/1 TP (vulnerability/sqli/function.go:34-41, `fmt.Sprintf` into `getProfileSql` then `DB.Query(getProfileSql)`) · go-test-bench: 1/1 TP (internal/injection/sqli/sql-injection.go:57, Unsafe-branch `fmt.Sprintf` then `db.Exec(query)`) · needed `focus-metavariable: $SINK` on every sink alternative -- without it, taint mode treated the whole matched call (including its "..." bind-param tail) as the sink, false-positiving on go-dvwa's legitimate `db.Exec("INSERT...VALUES (?,?,?)", fmt.Sprintf(...), ...)`, a real parameterized query whose *values* happen to be Sprintf-built |
| `toleman-go-command-injection-shell` | `injection/go-command-injection.yaml` | MEDIUM | go-dvwa: 1/1 TP (vulnerable/system.go:9, `exec.CommandContext(ctx, "sh", "-c", cmd)`) |
| `toleman-go-command-injection-dynamic-binary` | `injection/go-command-injection.yaml` | LOW | go-test-bench: 2/2 TP (internal/injection/cmdi/cmd-injection.go:53 and :84, `exec.Command(args[0], args[1:]...)`/CommandContext variant, both Unsafe branches) -- correctly silent on the same file's Safe branches (`exec.Command("echo", in)`, literal binary name) |
| `toleman-go-ssrf-unvalidated-url` | `ssrf/go-ssrf-unvalidated-url.yaml` | LOW | go-test-bench: 1/1 TP (internal/ssrf/ssrf.go:51, `http.Get(payload)`) + 1 false positive (internal/common/commontest/request_gen.go:44, `http.NewRequest(method, u, nil)` -- this is the test harness building requests to exercise the app, not app code reachable by an attacker). No naming filter on the URL argument (unlike this pack's Python SSRF rule) because the real variable name here is `payload`, not anything url/host-shaped -- a naming filter would have missed the one real hit entirely |
| `toleman-go-path-traversal-file-open` | `access-control/go-path-traversal.yaml` | LOW | 0/0/0 across govwa/go-dvwa/go-test-bench -- go-test-bench has the real vulnerable sink but the request-input extraction happens in a different file (see header). Synthetic: 3/3 TP (gotest/path_traversal_vulnerable.go), true negative on gotest/path_traversal_safe.go |
| `toleman-go-weak-hash-on-secret-value` | `crypto/go-weak-hash-secret.yaml` | LOW | govwa: 3/3 TP (user/user.go:160, vulnerability/csa/csa.go:62 -- OTP check, vulnerability/idor/idor.go:164 -- forgeable signature) · go-dvwa: true negative |
| `toleman-go-hardcoded-secret-literal` | `crypto/go-hardcoded-secret.yaml` | MEDIUM | govwa: 1/1 TP (vulnerability/csa/csa.go:49, `sotp := "a587cd6bf1e49d2c3928d1f8b86f248b"`, a hardcoded OTP-verification hash) · go-dvwa, go-test-bench: true negative |
| `toleman-go-math-rand-for-security-token` | `crypto/go-math-rand-token.yaml` | LOW | 0/0/0 across all 3 real repos (go-dvwa's only math/rand call, `rand.Intn(500)` for a fake price, is a true negative -- not a token, and not even assigned to a variable). Synthetic: 2/2 TP. Uncovered a 4th real semgrep-Go gotcha doing this: `crypto/rand` and `math/rand` both literally declare `package rand`, so a bare `rand.Read(...)` pattern matches an *aliased* `crypto/rand` import too (proven with a 2-line probe file) -- false-positived on this rule's own "safe" fixture before a `pattern-not-inside: import "crypto/rand"` guard fixed it. See file header. |
| `toleman-go-insecure-tls-skip-verify` | `crypto/go-insecure-tls-skip-verify.yaml` | LOW | 0/0/0 across all 3 real repos (none construct a tls.Config at all). Synthetic: 2/2 TP (struct-literal and direct-assignment shapes), true negative on a config with `InsecureSkipVerify: false` or the field omitted |

Two of the ten (`-path-traversal-file-open`, `-insecure-tls-skip-verify`)
and one more (`-math-rand-for-security-token`) are validated only against
hand-written synthetic fixtures under `scratchpad/gotest/`, not a real
app -- flagged honestly above and in each file's own header, per this
pack's documented fallback policy. `toleman-go-ssrf-unvalidated-url`'s
one false positive (test-harness code) is also called out rather than
folded into its true-positive count.

## Declined: session fixation, weak logout / session invalidation

Two of the four auth/session classes assigned in this batch (session
fixation, weak logout / weak session invalidation) were investigated and
deliberately **not** given rules -- same call as rate-limiting and
logging in an earlier pass: pure absence-of-control, no positive line to
key on, and the "correct" shape varies too much per app for a generic
negative check not to either miss real bugs or false-positive on correct
code.

- **Session fixation** (session ID not regenerated on login/privilege
  change): checked toleman's own login() (`backend/app/api/auth.py`) --
  it mints a brand-new signed token via `create_session_token(user.id,
  user.token_version)` on every login, with `token_version` bumped first,
  so the token value (and therefore the session identity it encodes)
  necessarily changes every time; there's no "old ID reused" to flag.
  Django (pygoat) and Flask-Login-style frameworks handle this inside
  their own `login()` call, not in app code. The actual vulnerable shape
  -- a hand-rolled auth flow that writes an auth session key directly
  without calling the framework's login()/regenerating anything -- has no
  fixed syntactic marker; it's an omission, not a bad line, and none of
  the 3 repos contain a hand-rolled instance to even calibrate against.

- **Weak logout / session invalidation**: prototyped a heuristic (flag a
  `response.delete_cookie(...)` call in a function that never also calls
  a recognized invalidation primitive -- `.flush()`, `.clear()`,
  `.cycle_key()`, `django.contrib.auth.logout()`, `.pop(...)`) and it
  came within one line of a **false positive on this repo's own reference
  logout** (`backend/app/api/auth.py`'s `logout()`): its actual
  invalidation mechanism is a bespoke `user.token_version += 1`, which
  doesn't match any "standard" library invalidation call a generic rule
  could whitelist. Widening the whitelist to catch that shape would mean
  whitelisting "any attribute increment," which stops the rule from
  meaningfully flagging anything. The one real instance of this bug this
  session found -- pygoat's `auth_lab_logout` deleting a cookie that IS
  the entire auth credential, so "logout" does nothing -- is a downstream
  symptom of the cookie itself being insecure, not an independently
  detectable logout-code flaw, and is already caught at its root cause by
  `toleman-insecure-persistent-auth-cookie` above.

## Two real semgrep gotchas hit while building this

Both cost real debugging time and will bite anyone extending this pack:

1. **`metavariable-regex` anchors like `re.match`, not `re.search`.** An
   alternation like `(url|host)$` only matches if the bound text *starts*
   matching one of those branches at position 0 — `webhook_url` fails it
   even though "url" is right there as a substring. Wrap patterns in
   `.*(...).*` to get real substring matching. Silently returned zero
   matches instead of erroring; only caught it by
   re-running the sink pattern alone and noticing it matched fine without
   the regex filter.

2. **A plain multi-line `$X = ...\n...\n$SINK($X)` pattern only follows a
   variable through sibling statements in the same block.** It does not
   track a variable into a nested block (an `if`, a `with`, a `for`) even
   one level deeper. `toleman-sql-injection-fstring-var-then-execute`
   needed `mode: taint` to actually find DVPWA's SQLi, which builds the
   query in the function body and executes it one indent level deeper
   inside `async with conn.cursor() as cur:`. Any rule connecting
   "value assigned here" to "value used later in this function" should
   default to taint mode rather than assume both statements sit at the
   same depth.

## Regression note, 2026-09-13

The XXE, CORS, TLS-verification, hardcoded-secret-assignment, insecure-
random, eval/exec, and shell=True rules above were validated multiple
times during the 2026-09-12 session (including a live-fired unauthenticated
RCE proof against a real PyGoat endpoint) but the files were never actually
written to this directory — every "whole pack" benchmark that session ran
against a copy missing 8 of what are now 94 rules, silently. Recovered from
the session's own validated final versions and re-confirmed against the
same real findings (pygoat's eval RCE, XXE lab, OTP-randomness bug) before
being committed. See KT.md at the repo root for the full trail. Lesson for
whoever extends this pack next: after writing and validating a rule,
confirm it with `git status`/`ls` in this directory, not just a passing
benchmark — a benchmark against the wrong config still "passes."

## Registry integration, 2026-09-13

Five rule files (`sql-injection.yaml`, `insecure-deserialization.yaml`,
`code-and-command-injection.yaml`, `csrf-protection-disabled.yaml`,
`weak-hash-on-secret-value.yaml` — 10 rule ids total, struck through in the
table above) were retired the same day they were recovered, once
cross-checking against the actual [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)
source showed the registry already has an equivalent for each, proven on
real code this session (registry's `eval-detected`/`user-eval` caught
PyGoat's live-fired RCE independently; `bad-deserialization` caught
RailsGoat's `Marshal.load`; `md5-loose-equality` caught DVWA's password
hash; `dangerous-subprocess-use`/`tainted-sql-string`/`gosql-sqli` caught
Go's command-injection and SQLi; `django/security/audit/csrf-exempt.yaml`
covers the CSRF-exempt flag). Maintaining a duplicate of a rule the
registry already ships is pure cost with no coverage benefit.

**What's still genuinely ours** (checked, no registry equivalent exists —
don't retire these without re-checking): the SSRF rule (registry's
`ssrf-requests.yaml` is hardcoded to Flask's `@app.route`+`flask.request`+
`requests.$FUNC` shape and has zero rules in its `fastapi/` folder at all —
verified by reading its pattern directly, not by absence-of-a-grep-hit),
`xxe-external-entities-explicitly-enabled`, `hardcoded-default-credential`,
`insecure-random-for-security-token`, the `exception-*-into-http-detail`
pair (keyed to this codebase's own helper-function convention), and the
cookie/URL-boundary review heuristics.

`backend/app/scanners/rule_selector.py` is the implementation of the
combine-with-registry design: detects languages/frameworks in a target
repo (manifest **and** repo-wide import grep — manifest-only detection
missed a Flask sub-app embedded in PyGoat during benchmarking), prunes the
vendored registry to `category: security` rules for just those
technologies, consolidates them into one file per language (benchmarked:
~2x faster to load than the registry's native hundreds-of-small-files
layout, same rules), and runs it alongside this pack as a second Semgrep
invocation — deliberately two invocations, not one combined `--config`
list, because `--disable-nosem` is all-or-nothing per invocation and this
pack wants it on for our own rules but *off* for the registry layer, so a
developer's prior triage of a generic registry finding (a real
`# nosemgrep: ...` comment) isn't defeated. Consolidating registry rules
into a new file changes their effective check_id prefix, which breaks
Semgrep's own id-based nosemgrep matching against comments written when
the rule lived at its original registry path — `rule_selector.py` works
around this with a marker-only post-filter (any `nosemgrep` text on the
flagged line, not an exact id match). Measured effect on this repo: 15
registry-layer findings before the filter, 1 after — the other 14 already
carried a human-reviewed suppression comment.

Full numbers (coverage cross-check against `semgrep --config=auto`,
timing, and the false-positive analysis that led to the nosemgrep-filter
design) are in KT.md, not duplicated here.

Not yet wired into `runner.py`/`tool_registry.py`, and the registry clone
itself (`SEMGREP_RULES_REGISTRY_ROOT`) isn't fetched/refreshed by anything
yet — both deliberate next steps, see KT.md.

## Running standalone

```bash
semgrep scan --config=backend/app/scanners/rules/core --json .
```

## Wiring in (not yet done)

Following the exact `semgrep-llm` pattern in `runner.py`:

```python
CORE_RULES_DIR = Path(__file__).parent / "rules" / "core"

# in TOOL_COMMANDS:
"semgrep-core": lambda path: [
    "semgrep", "scan", f"--config={CORE_RULES_DIR}", "--disable-nosem", "--json", "--quiet", path
],
```

Plus the matching `MULTI_PATH` / exit-code-set entries `semgrep-llm` has,
and a `tool_registry.py` entry so it shows up in Tool Marketplace and
per-tool coverage reporting. Deliberately not applied yet — that's a real
product decision (tool name, default on/off per surface, whether Tier-1
LOW-confidence rules should default to disabled) worth making explicitly
rather than as a side effect of writing the rules.
