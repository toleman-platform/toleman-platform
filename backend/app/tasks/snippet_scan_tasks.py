"""Ephemeral pre-commit vulnerability check (issue #108 follow-up), backing
POST /api/public/v1/scan-snippet: an MCP client (e.g. Claude Code) hands
over a code snippet it's about to write, before it ever lands in a real
file/commit, so it can be caught and fixed *while being written* instead of
only after a real scan of the finished repo finds it.

Runs against a plain temp dir, not a real clone: no Target, no Scan, no
Finding rows. app.scanners.runner.run_tool already knows how to run any
registered tool against an arbitrary directory (that's exactly what it does
for a real repo checkout too), so this reuses it unmodified rather than
inventing a second code path.
"""
import json
import logging
import shutil
import tempfile
from pathlib import Path

from sqlmodel import Session

from app.core.db import engine
from app.core.time import utcnow
from app.models.models import SnippetScanRun
from app.scanners import parsers, runner
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

PARSER_MAP = parsers.PARSER_MAP


@celery_app.task(name="app.tasks.snippet_scan_tasks.run_snippet_scan")
def run_snippet_scan(run_id: int, filename: str, content: str, tools: list[str]) -> dict:
    with Session(engine) as session:
        run = session.get(SnippetScanRun, run_id)
        if not run:
            return {"error": "snippet scan run not found"}

        tmp_dir = Path(tempfile.mkdtemp(prefix="toleman-snippet-"))
        try:
            # The public API endpoint already rejects an absolute/`..`
            # filename before dispatching; re-checked here too (defense in
            # depth -- `Path(tmp_dir) / "/etc/passwd"` would silently
            # discard tmp_dir and resolve to the absolute path instead of
            # raising) so this task can never be tricked into writing
            # outside its own temp dir regardless of caller.
            relative = filename.lstrip("/")
            if not relative or ".." in Path(relative).parts:
                raise ValueError(f"unsafe filename: {filename!r}")
            target_path = tmp_dir / relative
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content)

            findings = []
            for tool in tools:
                try:
                    raw = runner.run_tool(tool, tmp_dir)
                except runner.ToolNotApplicable:
                    # e.g. gosec requested against a non-Go snippet -- a
                    # real "nothing here for this tool" result, not a
                    # failure; simply contributes no findings.
                    continue
                for item in PARSER_MAP[tool](raw):
                    item["tool"] = tool
                    item["severity"] = item["severity"].value
                    item["file_path"] = filename
                    findings.append(item)

            run.status = "completed"
            run.findings_json = json.dumps(findings)
            run.completed_at = utcnow()
        except Exception as exc:
            logger.exception("snippet scan run %s failed", run_id)
            run.status = "failed"
            run.error = str(exc)[:500]
            run.completed_at = utcnow()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        session.add(run)
        session.commit()
        return {"run_id": run.id, "status": run.status}
