"""Tests for AIBOM generation (issue #190).

The schema test validates against the real published CycloneDX 1.6 schema,
vendored into tests/fixtures rather than fetched at test time so CI doesn't
depend on network access. A malformed BOM offered as a compliance artifact is
worse than none, so "it looks right" is not good enough here.
"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from app.core.aibom import (
    UNKNOWN,
    AiComponent,
    aibom_summary,
    build_aibom,
    extract_ai_components,
)

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "cyclonedx-bom-1.6.schema.json"


def _validate(doc: dict) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text())
    return [f"{list(e.path)}: {e.message}" for e in Draft7Validator(schema).iter_errors(doc)]


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_huggingface_model_is_extracted(tmp_path):
    (tmp_path / "a.py").write_text(
        "from transformers import AutoModel\nm = AutoModel.from_pretrained('org/model-a')\n"
    )
    comps = extract_ai_components(tmp_path)
    assert [c.name for c in comps] == ["org/model-a"]
    assert comps[0].component_type == "machine-learning-model"
    assert comps[0].source == "huggingface"


def test_unpinned_model_records_unknown_version_rather_than_guessing(tmp_path):
    """The missing revision *is* the finding. Inventing a version, or leaving
    the field out so it reads as fine, would both be worse than saying so."""
    (tmp_path / "a.py").write_text(
        "from transformers import AutoModel\nm = AutoModel.from_pretrained('org/model-a')\n"
    )
    assert extract_ai_components(tmp_path)[0].version == UNKNOWN


def test_pinned_revision_is_captured(tmp_path):
    (tmp_path / "a.py").write_text(
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('org/model-a', revision='abc123def')\n"
    )
    assert extract_ai_components(tmp_path)[0].version == "abc123def"


def test_hosted_api_model_is_extracted(tmp_path):
    (tmp_path / "a.py").write_text(
        "import openai\n"
        "r = openai.OpenAI().chat.completions.create(model='gpt-5', messages=[])\n"
    )
    comps = extract_ai_components(tmp_path)
    assert comps[0].name == "gpt-5"
    assert comps[0].source == "hosted-api"


def test_dataset_is_extracted(tmp_path):
    (tmp_path / "a.py").write_text("from datasets import load_dataset\nd = load_dataset('org/squad')\n")
    comps = extract_ai_components(tmp_path)
    assert comps[0].component_type == "data"
    assert comps[0].name == "org/squad"


def test_unrelated_model_kwarg_is_not_treated_as_an_llm(tmp_path):
    """`model=` is a common kwarg. Without the name filter this sweeps up ORM
    and serializer config as AI dependencies."""
    (tmp_path / "a.py").write_text(
        "serializer = Serializer(model='User')\nform = Form(model='invoice_line_item')\n"
    )
    assert extract_ai_components(tmp_path) == []


def test_model_named_in_a_whole_line_comment_is_ignored(tmp_path):
    """Running the extractor over this codebase pulled model names out of its
    own comments, which would have claimed dependencies that don't exist."""
    (tmp_path / "a.py").write_text(
        "# we could switch to model='gpt-5' later\n"
        "// note: claude-sonnet-4-5 was considered\n"
        "x = 1\n"
    )
    assert extract_ai_components(tmp_path) == []


def test_evidence_records_which_file_a_component_came_from(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import openai\nr = openai.OpenAI().chat.completions.create(model='gpt-5')\n"
    )
    assert extract_ai_components(tmp_path)[0].evidence == ["svc.py"]


def test_same_model_in_two_files_is_one_component_with_both_as_evidence(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(
            "import openai\nr = openai.OpenAI().chat.completions.create(model='gpt-5')\n"
        )
    comps = extract_ai_components(tmp_path)
    assert len(comps) == 1
    assert sorted(comps[0].evidence) == ["a.py", "b.py"]


def test_node_modules_is_not_walked(tmp_path):
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "a.py").write_text("m = AutoModel.from_pretrained('org/model-a')\n")
    assert extract_ai_components(tmp_path) == []


def test_missing_directory_returns_empty(tmp_path):
    assert extract_ai_components(tmp_path / "nope") == []


# ---------------------------------------------------------------------------
# CycloneDX document
# ---------------------------------------------------------------------------


def test_empty_aibom_validates_against_the_real_schema():
    doc = build_aibom([], target_name="demo", timestamp="2026-08-16T00:00:00Z")
    assert _validate(doc) == []
    assert doc["specVersion"] == "1.6"
    assert doc["bomFormat"] == "CycloneDX"


def test_populated_aibom_validates_against_the_real_schema():
    comps = [
        AiComponent("org/model-a", "machine-learning-model", UNKNOWN, "huggingface", ["app.py"]),
        AiComponent("gpt-5", "machine-learning-model", UNKNOWN, "hosted-api", ["svc.py"]),
        AiComponent("org/dataset-x", "data", UNKNOWN, "huggingface", ["train.py"]),
    ]
    doc = build_aibom(
        comps,
        target_name="demo",
        repo_url="https://github.com/acme/demo",
        branch="main",
        timestamp="2026-08-16T00:00:00Z",
    )
    assert _validate(doc) == []


def test_model_components_use_the_machine_learning_model_type():
    comps = [AiComponent("org/m", "machine-learning-model", UNKNOWN, "huggingface", ["a.py"])]
    doc = build_aibom(comps, target_name="demo")
    assert doc["components"][0]["type"] == "machine-learning-model"


def test_unknown_provenance_is_stated_not_omitted():
    """The whole point of the module. A modelCard left out entirely reads as
    "not applicable"; an explicit unknown reads as "we looked and could not
    tell", which is the true and materially different claim."""
    comps = [AiComponent("org/m", "machine-learning-model", UNKNOWN, "huggingface", ["a.py"])]
    entry = build_aibom(comps, target_name="demo")["components"][0]

    assert entry["version"] == UNKNOWN
    card = entry["modelCard"]
    assert card["modelParameters"]["task"] == UNKNOWN
    assert card["modelParameters"]["datasets"][0]["name"] == UNKNOWN
    assert "not determinable from source" in card["considerations"]["technicalLimitations"][0]


def test_unpinned_components_are_flagged_as_such():
    comps = [AiComponent("org/m", "machine-learning-model", UNKNOWN, "huggingface", ["a.py"])]
    props = build_aibom(comps, target_name="demo")["components"][0]["properties"]
    assert {"name": "toleman:unpinned", "value": "true"} in props


def test_pinned_components_are_not_flagged_as_unpinned():
    comps = [AiComponent("org/m", "machine-learning-model", "abc123", "huggingface", ["a.py"])]
    props = build_aibom(comps, target_name="demo")["components"][0]["properties"]
    assert all(p["name"] != "toleman:unpinned" for p in props)


def test_datasets_do_not_get_a_model_card():
    comps = [AiComponent("org/d", "data", UNKNOWN, "huggingface", ["a.py"])]
    assert "modelCard" not in build_aibom(comps, target_name="demo")["components"][0]


def test_bom_refs_are_unique():
    comps = [
        AiComponent("org/m", "machine-learning-model", UNKNOWN, "huggingface", ["a.py"]),
        AiComponent("org/m", "data", UNKNOWN, "huggingface", ["a.py"]),
    ]
    refs = [c["bom-ref"] for c in build_aibom(comps, target_name="demo")["components"]]
    assert len(refs) == len(set(refs))


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_summary_counts():
    comps = [
        AiComponent("org/m", "machine-learning-model", UNKNOWN, "huggingface", ["a.py"]),
        AiComponent("gpt-5", "machine-learning-model", UNKNOWN, "hosted-api", ["a.py"]),
        AiComponent("org/m2", "machine-learning-model", "abc", "huggingface", ["a.py"]),
        AiComponent("org/d", "data", UNKNOWN, "huggingface", ["a.py"]),
    ]
    assert aibom_summary(comps) == {
        "models": 3,
        "datasets": 1,
        "unpinned": 3,
        "hosted_api_models": 1,
    }


def test_revision_does_not_bleed_from_the_next_call(tmp_path):
    """An earlier version scanned a fixed window forward from the match,
    which picked up the *next* statement's revision kwarg and reported an
    unpinned model as pinned; inventing provenance, the single worst thing
    this module could do."""
    (tmp_path / "a.py").write_text(
        "m   = AutoModel.from_pretrained('org/unpinned')\n"
        "pin = AutoModel.from_pretrained('org/pinned', revision='abc123')\n"
    )
    by_name = {c.name: c for c in extract_ai_components(tmp_path)}
    assert by_name["org/unpinned"].version == UNKNOWN
    assert by_name["org/pinned"].version == "abc123"


def test_multiline_call_still_finds_its_own_revision(tmp_path):
    (tmp_path / "a.py").write_text(
        "m = AutoModel.from_pretrained(\n"
        "    'org/model-a',\n"
        "    revision='deadbeef',\n"
        ")\n"
    )
    assert extract_ai_components(tmp_path)[0].version == "deadbeef"
