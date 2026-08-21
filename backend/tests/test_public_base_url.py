"""Tests for finding GH-02/BLD-03: the deployment's public addresses must
come from configuration, not from five hardcoded "localhost" literals.

What the external evaluation hit:
  * every link Rikugan posted to GitHub -- the PR comment's "review in
    Rikugan", the "request ignore" link, the commit status target_url --
    pointed at http://localhost:3000, so no teammate on a shared repository
    could follow any of them;
  * CORS was pinned to that same single origin, so running the frontend on
    any other port failed the preflight, and the login form reported that
    transport failure as "Invalid email or password".
"""


from app.core.config import Settings, settings


def _settings(**kwargs) -> Settings:
    # _env_file=None so a developer's real .env can't leak into these
    # assertions and make the suite pass/fail depending on the machine.
    return Settings(_env_file=None, **kwargs)


def test_defaults_preserve_the_localhost_dev_experience():
    s = _settings()
    assert s.public_base_url == "http://localhost:3000"
    assert s.public_api_url == "http://localhost:8000"
    assert s.cors_allow_origins == ["http://localhost:3000"]


def test_public_base_url_becomes_the_allowed_cors_origin():
    s = _settings(public_base_url="https://rikugan.example.com")
    assert s.cors_allow_origins == ["https://rikugan.example.com"]


def test_trailing_slash_is_normalised_away():
    # "https://x.example.com/" would never match a browser Origin header,
    # which sends no trailing slash -- a silent, confusing CORS failure.
    s = _settings(public_base_url="https://rikugan.example.com/")
    assert s.cors_allow_origins == ["https://rikugan.example.com"]


def test_extra_origins_are_appended():
    s = _settings(
        public_base_url="https://rikugan.example.com",
        extra_cors_origins="https://staging.example.com, http://localhost:3001",
    )
    assert s.cors_allow_origins == [
        "https://rikugan.example.com",
        "https://staging.example.com",
        "http://localhost:3001",
    ]


def test_extra_origins_ignores_blanks_and_duplicates():
    s = _settings(
        public_base_url="https://rikugan.example.com",
        extra_cors_origins=" , https://rikugan.example.com/ ,, https://other.example.com ",
    )
    assert s.cors_allow_origins == ["https://rikugan.example.com", "https://other.example.com"]


def test_wildcard_is_never_produced():
    # These endpoints are session-cookie authenticated and the app sets
    # allow_credentials=True; "*" there is rejected by browsers and would be
    # a real CSRF surface if it weren't.
    s = _settings(public_base_url="https://rikugan.example.com", extra_cors_origins="https://a.example.com")
    assert "*" not in s.cors_allow_origins


def test_pr_guardrail_links_are_derived_from_settings():
    """The commit-status target_url and every PR-comment link must be built
    from public_base_url, not a module constant.

    Asserted by derivation rather than by reloading the module under a patched
    env: `importlib.reload(app.core.config)` rebinds `settings` to a *new*
    object while every module that did `from app.core.config import settings`
    keeps the old one, so a later test monkeypatching the new object silently
    has no effect on them. That leaked across files and broke
    test_security.py's default-secret check in CI -- a real cost, for a
    weaker assertion than this one.
    """
    from app.core import pr_guardrail_executor as executor

    assert executor.FRONTEND_URL == settings.public_base_url.rstrip("/")


def test_github_app_manifest_urls_are_derived_from_settings():
    """GitHub's servers call these back, so a localhost value produces an App
    that can never reach this deployment."""
    from app.api import github_app

    assert github_app.FRONTEND_URL == settings.public_base_url.rstrip("/")
    assert github_app.BACKEND_URL == settings.public_api_url.rstrip("/")


def test_no_hardcoded_localhost_remains_in_backend_source():
    """Regression guard for GH-02: a new hardcoded localhost literal in an
    outbound-URL position is exactly the bug that shipped, and it is
    invisible in review.

    AST-based rather than a grep so it flags real string *values* and ignores
    prose -- both this codebase's comments and its docstrings legitimately
    discuss the localhost problem (see core/pipeline_workflow.py, which warns
    an operator not to point RIKUGAN_API_URL at localhost). A line-based
    check would either flag that documentation or have to be loosened until
    it stopped catching the actual bug.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "app"
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "config.py":
            continue  # the one legitimate home for the defaults
        tree = ast.parse(path.read_text())

        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc is not None:
                    docstrings.add(id(node.body[0].value))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in docstrings:
                continue
            for line in node.value.splitlines():
                # A generated-file template can legitimately *warn about*
                # localhost in its own comment lines -- pipeline_workflow.py's
                # workflow template tells the operator not to set
                # RIKUGAN_API_URL to localhost. That is the guidance working,
                # not the bug.
                if line.lstrip().startswith("#"):
                    continue
                if "localhost:3000" in line or "localhost:8000" in line:
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}: {line.strip()!r}")

    assert not offenders, (
        "hardcoded localhost URL(s) reintroduced -- use settings.public_base_url / "
        "settings.public_api_url instead:\n" + "\n".join(offenders)
    )
