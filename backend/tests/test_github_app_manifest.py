"""Tests for findings GH-03 and GH-05 in the generated GitHub App manifest.

GH-03: the manifest declared `"default_events": []` with no `hook_attributes`,
so the App subscribed to nothing. Nothing ran when a PR opened; a human had
to open PR History and press "Scan This PR". As the review put it, "blocking
mode" that depends on someone remembering to press a button is advisory in
practice, and a required check nobody triggers blocks every PR forever.

Nothing new had to be built to fix it: app/api/webhooks.py already verifies
the signature, filters to pull_request and dispatches the scan, and the
manifest-conversion handler already persists the webhook secret GitHub
generates. Only the subscription was missing.

GH-05: the App was named "OSP DevSecOps <suffix>" (the pre-rename product
name) so GitHub derived a bot login of `osp-devsecops-*[bot]`, which signed
every PR comment in every adopting org.
"""

from app.core.github_app import build_manifest


def _manifest(app_url="https://toleman.example.com", backend_url="https://api.toleman.example.com"):
    return build_manifest(app_url, backend_url, "abc123", setup_token="tok")


def test_app_subscribes_to_pull_request_events():
    assert _manifest()["default_events"] == ["pull_request"]


def test_hook_attributes_point_at_the_real_webhook_route():
    hook = _manifest()["hook_attributes"]
    # Must match app/api/webhooks.py's router prefix + route, or GitHub
    # delivers to a 404 and automatic scanning silently never fires.
    assert hook["url"] == "https://api.toleman.example.com/api/webhooks/github"
    assert hook["active"] is True


def test_webhook_url_is_built_from_the_backend_url_not_the_frontend_url():
    """GitHub's servers POST here. Pointing it at the frontend would deliver
    webhooks to a Next.js app that has no handler for them."""
    m = _manifest(app_url="https://ui.example.com", backend_url="https://api.example.com")
    assert m["hook_attributes"]["url"].startswith("https://api.example.com")


def test_app_is_named_toleman_not_the_pre_rename_product():
    """GH-05: this string is what GitHub derives the bot login from, so it is
    the product's signature on every PR comment in an adopting org."""
    name = _manifest()["name"]
    assert name.startswith("Toleman")
    # Both superseded product names, "OSP DevSecOps" (GH-05) and "Rikugan",
    # which this one replaced in turn.
    assert "OSP" not in name
    assert "Rikugan" not in name


def test_permissions_still_cover_what_pr_guardrail_needs():
    # Regression guard: subscribing to events is useless if the App cannot
    # post the status or the comment it exists to produce.
    perms = _manifest()["default_permissions"]
    assert perms["pull_requests"] == "write"
    assert perms["statuses"] == "write"
    assert perms["contents"] == "write"
    # Required separately by GitHub for any write under .github/workflows/.
    assert perms["workflows"] == "write"


def test_manifest_data_flags_an_unreachable_webhook_host(monkeypatch):
    """A localhost PUBLIC_API_URL produces an App whose deliveries can never
    arrive, indistinguishable, from the operator's side, from a scanner
    that finds nothing."""
    import app.api.github_app as github_app

    monkeypatch.setattr(github_app, "BACKEND_URL", "http://localhost:8000")
    assert github_app.manifest_data()["webhook_reachable"] is False

    monkeypatch.setattr(github_app, "BACKEND_URL", "http://127.0.0.1:8000")
    assert github_app.manifest_data()["webhook_reachable"] is False


def test_manifest_data_accepts_a_real_public_host(monkeypatch):
    import app.api.github_app as github_app

    monkeypatch.setattr(github_app, "BACKEND_URL", "https://api.toleman.example.com")
    result = github_app.manifest_data()

    assert result["webhook_reachable"] is True
    assert result["webhook_url"] == "https://api.toleman.example.com/api/webhooks/github"


def test_manifest_data_still_returns_a_usable_manifest_when_unreachable(monkeypatch):
    """Advisory, not blocking: creating the App is still worth doing while a
    tunnel is being set up, because on-demand scanning works regardless."""
    import app.api.github_app as github_app

    monkeypatch.setattr(github_app, "BACKEND_URL", "http://localhost:8000")
    result = github_app.manifest_data()

    assert result["manifest"]["default_events"] == ["pull_request"]
    assert result["post_url"].startswith("https://github.com/")
