"""Tool marketplace / health page (issue #75).

Split into one module per concern (senior-review pass, #223). This used to
be a single ~320-line file covering four independent responsibilities --
live health checks, the marketplace registry, per-workspace usage
assignment, and one-click install -- that had grown by accretion, one issue
at a time, with no natural seam ever forcing them apart. None of the four
share meaningful logic beyond a single small helper (`_check_one`, defined
in health.py and reused by registry.py, since both do the same "does this
binary answer to --version" probe over different tool sets), so keeping
them in one file was expressing convenience-at-the-time, not real coupling.

  - health.py: `GET /health`, the original Sprint 1 check against exactly
    the four originally-integrated scanners. Kept for backwards
    compatibility with the frontend's existing ToolsHealth component.
  - registry.py: `GET /registry`, the full marketplace listing (every
    registered tool, live health, `integrated`/`installable` flags),
    cached per #221.
  - assignments.py: `GET`/`PUT /assignments`, per-workspace per-tool usage
    assignment backed by WorkspaceToolConfig.
  - install.py: `POST /{tool}/install` + `GET /installs/{id}`, admin-only
    one-click install (#216) -- see app.core.tool_install for the
    allowlist argument.

This file only aggregates: it builds the shared `/api/tools`-prefixed
router and mounts each submodule's routes onto it, with `tags=["tools"]`
applied once here rather than once per submodule so there is a single
place that declares how these routes appear in the OpenAPI docs.

Route paths, HTTP methods, response shapes, and status codes are
byte-identical to the single-file version -- see
tests/test_tool_marketplace.py, test_tool_install.py,
test_tool_health_cache.py, and test_tool_registry_contract.py, none of
which needed a behavior change. A few tests that reached into a module
internal via `unittest.mock.patch` were updated to the symbol's new home
(e.g. `app.api.tools._check_one` -> `app.api.tools.registry._check_one`,
since that is the module whose own global namespace registry.py's function
body actually resolves the bare name `_check_one` through at call time --
patching the old path would silently patch nothing). No compatibility
re-export was added for the old paths: per this project's own convention
against re-exporting things purely to avoid updating a call site, tests
now point at where the code actually lives.
"""
from fastapi import APIRouter

from . import assignments, health, install, registry

router = APIRouter(prefix="/api/tools")
router.include_router(health.router, tags=["tools"])
router.include_router(registry.router, tags=["tools"])
router.include_router(assignments.router, tags=["tools"])
router.include_router(install.router, tags=["tools"])
