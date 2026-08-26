"""Tests for AI/ML repo detection (issue #185), the gate every AI-specific
scanner in epic #192 runs behind.

Two halves: the pure detection functions (app.core.ai_repo_detection, no DB)
and the persistence/override layer (app.core.ai_repo_status).
"""
import itertools

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.ai_repo_detection import (
    detect_ai_packages,
    detect_ai_repo,
    detect_model_files,
)
from app.core.ai_repo_status import effective_is_ai_repo, refresh_ai_repo_status
from app.models.models import Organization, SbomComponent, Target, Workspace

_names = itertools.count()


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _make_target(engine, default_branch="main") -> int:
    with Session(engine) as session:
        org = Organization(name=f"org-{next(_names)}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=f"ws-{next(_names)}", api_key=f"key-{next(_names)}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(
            workspace_id=ws.id,
            name="t",
            repo_url="https://github.com/acme/repo",
            default_branch=default_branch,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _add_components(engine, target_id: int, components, branch="main"):
    with Session(engine) as session:
        for name, package_type in components:
            session.add(
                SbomComponent(
                    target_id=target_id,
                    branch=branch,
                    name=name,
                    version="1.0.0",
                    package_type=package_type,
                    purl=f"pkg:{package_type}/{name}@1.0.0",
                )
            )
        session.commit()


# ---------------------------------------------------------------------------
# Model-file signal
# ---------------------------------------------------------------------------


def test_model_file_is_detected(tmp_path):
    (tmp_path / "model.pkl").write_bytes(b"not really a pickle")
    assert detect_model_files(tmp_path) == ["model.pkl"]


def test_various_model_extensions_detected(tmp_path):
    for name in ("a.safetensors", "b.pt", "c.h5", "d.onnx", "e.gguf"):
        (tmp_path / name).write_bytes(b"x")
    assert len(detect_model_files(tmp_path)) == 5


def test_model_file_inside_node_modules_is_ignored(tmp_path):
    """A model vendored inside a dependency belongs to that dependency, not
    to this repo; otherwise any app with a transitive ML package looks
    like an AI repo."""
    vendored = tmp_path / "node_modules" / "some-pkg"
    vendored.mkdir(parents=True)
    (vendored / "model.pkl").write_bytes(b"x")
    assert detect_model_files(tmp_path) == []


def test_model_file_inside_venv_and_git_ignored(tmp_path):
    for skip_dir in (".venv", ".git", "dist"):
        d = tmp_path / skip_dir / "nested"
        d.mkdir(parents=True)
        (d / "weights.bin").write_bytes(b"x")
    assert detect_model_files(tmp_path) == []


def test_plain_repo_has_no_model_files(tmp_path):
    (tmp_path / "main.go").write_text("package main")
    (tmp_path / "README.md").write_text("# hi")
    assert detect_model_files(tmp_path) == []


def test_missing_directory_is_not_an_error(tmp_path):
    assert detect_model_files(tmp_path / "does-not-exist") == []


# ---------------------------------------------------------------------------
# Dependency signal
# ---------------------------------------------------------------------------


def test_python_ai_package_detected():
    assert detect_ai_packages([("torch", "pip")]) == ["torch"]


def test_npm_ai_package_detected():
    """npm is 1351 of 1396 components on a live instance; a Python-only
    list would miss most of the estate."""
    assert detect_ai_packages([("openai", "npm")]) == ["openai"]


def test_scoped_langchain_npm_package_detected():
    assert detect_ai_packages([("@langchain/core", "npm")]) == ["@langchain/core"]


def test_langchain_python_prefix_detected():
    assert detect_ai_packages([("langchain-anthropic", "pip")]) == ["langchain-anthropic"]


def test_go_ai_module_detected():
    assert detect_ai_packages([("github.com/sashabaranov/go-openai", "gomod")]) == [
        "github.com/sashabaranov/go-openai"
    ]


def test_ordinary_packages_not_flagged():
    ordinary = [("express", "npm"), ("requests", "pip"), ("github.com/gin-gonic/gin", "gomod")]
    assert detect_ai_packages(ordinary) == []


def test_package_named_ai_in_wrong_ecosystem_not_matched_by_substring():
    """Matching must be exact/prefix, not substring; a substring check on
    "ai" flags most of npm."""
    assert detect_ai_packages([("chair", "npm"), ("aiohttp", "pip")]) == []


def test_detection_is_case_insensitive():
    assert detect_ai_packages([("Torch", "pip")]) == ["Torch"]


def test_duplicate_packages_reported_once():
    assert detect_ai_packages([("torch", "pip"), ("torch", "pip")]) == ["torch"]


# ---------------------------------------------------------------------------
# Combined
# ---------------------------------------------------------------------------


def test_either_signal_alone_is_sufficient(tmp_path):
    (tmp_path / "model.pkl").write_bytes(b"x")
    assert detect_ai_repo(repo_path=tmp_path).detected is True
    assert detect_ai_repo(components=[("torch", "pip")]).detected is True


def test_neither_signal_means_not_detected(tmp_path):
    (tmp_path / "main.go").write_text("package main")
    result = detect_ai_repo(repo_path=tmp_path, components=[("express", "npm")])
    assert result.detected is False
    assert result.signals == []


def test_signals_explain_why_it_fired(tmp_path):
    """A bare boolean isn't contestable; a user who thinks the platform is
    wrong needs to see what it matched on."""
    (tmp_path / "model.pkl").write_bytes(b"x")
    result = detect_ai_repo(repo_path=tmp_path, components=[("torch", "pip")])
    joined = " ".join(result.signals)
    assert "model.pkl" in joined
    assert "torch" in joined


def test_detection_works_without_a_checkout():
    """Re-evaluating every target from persisted SBOM inventory must not
    require cloning 35 repos."""
    assert detect_ai_repo(repo_path=None, components=[("transformers", "pip")]).detected is True


# ---------------------------------------------------------------------------
# Persistence + override
# ---------------------------------------------------------------------------


def test_refresh_persists_flag_and_signals(engine):
    target_id = _make_target(engine)
    _add_components(engine, target_id, [("torch", "pip")])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        refresh_ai_repo_status(session, target)
        assert target.is_ai_repo is True
        assert "torch" in target.is_ai_repo_signals


def test_refresh_only_reads_default_branch_components(engine):
    target_id = _make_target(engine, default_branch="main")
    _add_components(engine, target_id, [("torch", "pip")], branch="feature/x")

    with Session(engine) as session:
        target = session.get(Target, target_id)
        refresh_ai_repo_status(session, target)
        assert target.is_ai_repo is False


def test_repo_flips_to_ai_when_a_dependency_is_added(engine):
    target_id = _make_target(engine)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        refresh_ai_repo_status(session, target)
        assert target.is_ai_repo is False

    _add_components(engine, target_id, [("@langchain/core", "npm")])
    with Session(engine) as session:
        target = session.get(Target, target_id)
        refresh_ai_repo_status(session, target)
        assert target.is_ai_repo is True


def test_refresh_does_not_clobber_a_human_override(engine):
    """Detection keeps updating underneath a human decision, so the UI can
    show "auto-detection says X, you forced Y"."""
    target_id = _make_target(engine)
    _add_components(engine, target_id, [("torch", "pip")])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        target.is_ai_repo_override = False
        session.add(target)
        session.commit()

        refresh_ai_repo_status(session, target)
        assert target.is_ai_repo is True  # detection still recorded
        assert target.is_ai_repo_override is False  # override untouched
        assert effective_is_ai_repo(target) is False  # override wins


def test_override_can_force_on_for_an_undetected_repo(engine):
    target_id = _make_target(engine)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        refresh_ai_repo_status(session, target)
        assert effective_is_ai_repo(target) is False

        target.is_ai_repo_override = True
        assert effective_is_ai_repo(target) is True


def test_null_override_follows_detection(engine):
    target_id = _make_target(engine)
    _add_components(engine, target_id, [("torch", "pip")])
    with Session(engine) as session:
        target = session.get(Target, target_id)
        refresh_ai_repo_status(session, target)
        assert target.is_ai_repo_override is None
        assert effective_is_ai_repo(target) is True
