from pathlib import Path

from app.scanners.discovery import discover_endpoints


def test_discovers_fastapi_route(tmp_path: Path):
    (tmp_path / "main.py").write_text('@app.get("/health")\ndef health():\n    return {"ok": True}\n')
    out = discover_endpoints(tmp_path)
    assert any(e["method"] == "GET" and e["route"] == "/health" for e in out)


def test_discovers_flask_route_with_methods(tmp_path: Path):
    (tmp_path / "views.py").write_text("@app.route('/login', methods=['POST'])\ndef login():\n    pass\n")
    out = discover_endpoints(tmp_path)
    assert any(e["framework"] == "flask" and e["route"] == "/login" for e in out)


def test_discovers_gin_route_not_duplicated_by_express_pattern(tmp_path: Path):
    (tmp_path / "app.go").write_text('router.GET("/index", handler)\n')
    out = discover_endpoints(tmp_path)
    gin_matches = [e for e in out if e["route"] == "/index"]
    assert len(gin_matches) == 1
    assert gin_matches[0]["framework"] == "gin"


def test_discovers_express_route_lowercase_only(tmp_path: Path):
    (tmp_path / "server.js").write_text("app.get('/users', handler)\n")
    out = discover_endpoints(tmp_path)
    assert any(e["framework"] == "express" and e["route"] == "/users" for e in out)


def test_router_get_line_not_double_matched_by_fastapi_and_express(tmp_path: Path):
    # `router.get("/x")` satisfies both the case-insensitive FastAPI pattern
    # and the express pattern, regression test for the API Discovery UI
    # bug where the same line was reported twice under different frameworks.
    (tmp_path / "routes.py").write_text('router.get("/{finding_id}", handler)\n')
    out = discover_endpoints(tmp_path)
    matches = [e for e in out if e["route"] == "/{finding_id}"]
    assert len(matches) == 1


def test_skips_vendored_and_hidden_dirs(tmp_path: Path):
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "index.js").write_text("app.get('/should-not-appear', h)\n")
    out = discover_endpoints(tmp_path)
    assert out == []


def test_records_file_and_line_number(tmp_path: Path):
    (tmp_path / "main.py").write_text('x = 1\n@app.post("/create")\ndef create():\n    pass\n')
    out = discover_endpoints(tmp_path)
    entry = next(e for e in out if e["route"] == "/create")
    assert entry["file"] == "main.py"
    assert entry["line"] == 2
