"""The one line of real duplication in the create-row-then-dispatch pattern
(senior-review pass, #222).

Five endpoints (POST /api/scans/run, /api/discovery/{id}, /api/sbom/{id},
/api/api-scan/{id}, /api/tools/{tool}/install) each build a tracking row
with status="running", then persist it with the same three-line sequence:
`session.add(row); session.commit(); session.refresh(row)`. That much is
genuinely identical across all five and is extracted here.

What is deliberately *not* unified: the `.delay()` call (different task,
different kwargs per endpoint) and the 202 response body (different field
names; scan_id vs run_id, different extra fields like endpoint_count).
Forcing those into one generic function would trade five short, readable,
type-checked blocks for one function taking a task reference, a kwargs
dict, and a response-shape config; more indirection than the three lines
of duplication it would remove. That is the shape of premature abstraction
this codebase avoids elsewhere (see CLAUDE.md's "three similar lines is
better than a premature abstraction").

The actual failure mode this class of duplication produced (#219, where
a new async job type's Celery route was silently omitted) is not fixed by
unifying this three-line block. It is caught generically, for any future
async task regardless of how its dispatch code is written, by
tests/test_celery_task_routing.py, which checks every registered task
module against `task_routes` directly.
"""
from typing import TypeVar

from sqlmodel import Session, SQLModel

RowT = TypeVar("RowT", bound=SQLModel)


def create_running_row(session: Session, row: RowT) -> RowT:
    """Persist a freshly constructed tracking row (Scan/DiscoveryRun/SbomRun/
    ToolInstallRun, already built with status="running") and return it
    refreshed with its assigned id, ready to be passed to `.delay()`.
    """
    session.add(row)
    session.commit()
    session.refresh(row)
    return row
