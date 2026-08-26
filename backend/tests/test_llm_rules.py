"""Tests for the curated LLM security ruleset (issue #189).

These run the real semgrep binary against real fixture files. Mocking would
defeat the purpose: what is being tested is whether the *rules* match
correctly, and a mocked semgrep tests nothing about a rule.

The negative cases matter more than the positive ones here. Two real
precision bugs were caught by exactly these assertions while the rules were
being written:

  1. Without `mode: taint`, semgrep silently ignores `pattern-sources` and
     matches the sink alone, so `os.system("ls -la")` with a literal
     argument was reported as an LLM-output-to-shell finding.
  2. With taint mode but a bare `$CHAIN.run(...)` source, `subprocess.run()`
     matched as both source and sink and tainted itself, producing six false
     positives against this repository's own backend.

A rule that fires on every subprocess call in a file that happens to import
an LLM SDK is worse than no rule at all, because it teaches people to ignore
the scanner.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from app.models.models import Severity
from app.scanners import parsers, runner

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)


def _scan(tmp_path: Path) -> list[dict]:
    raw = runner.run_tool("semgrep-llm", tmp_path)
    return parsers.PARSER_MAP["semgrep-llm"](raw)


def _rule_ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"].split(".")[-1] for f in findings}


# ---------------------------------------------------------------------------
# LLM output reaching a sink
# ---------------------------------------------------------------------------


def test_llm_output_into_eval_is_flagged(tmp_path):
    (tmp_path / "a.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def f(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[{'role':'user','content':q}])\n"
        "    eval(r.choices[0].message.content)\n"
    )
    assert "toleman-llm-output-to-code-execution" in _rule_ids(_scan(tmp_path))


def test_llm_output_into_shell_is_flagged(tmp_path):
    (tmp_path / "a.py").write_text(
        "import os, openai\n"
        "client = openai.OpenAI()\n"
        "def f(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[{'role':'user','content':q}])\n"
        "    os.system(r.choices[0].message.content)\n"
    )
    assert "toleman-llm-output-to-shell" in _rule_ids(_scan(tmp_path))


def test_literal_shell_command_is_not_flagged_even_beside_an_llm_call(tmp_path):
    """The bug that `mode: taint` fixes. A file calling an LLM *and*
    separately running a fixed command is not an injection."""
    (tmp_path / "a.py").write_text(
        "import os, openai\n"
        "client = openai.OpenAI()\n"
        "def f(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[{'role':'user','content':q}])\n"
        "    print(r.choices[0].message.content)\n"
        "    os.system('ls -la')\n"
        "    eval('1 + 1')\n"
    )
    assert _scan(tmp_path) == []


def test_subprocess_run_is_not_treated_as_an_llm_source(tmp_path):
    """The bug the metavariable-regex fixes: a bare `$CHAIN.run(...)` source
    matched subprocess.run(), making it both source and sink."""
    (tmp_path / "a.py").write_text(
        "import subprocess\n"
        "def f(cmd):\n"
        "    out = subprocess.run(cmd, capture_output=True)\n"
        "    subprocess.run(out.stdout, shell=True)\n"
    )
    assert _rule_ids(_scan(tmp_path)) == set()


def test_langchain_style_call_is_flagged_when_receiver_is_named_like_an_llm(tmp_path):
    (tmp_path / "a.py").write_text(
        "import os\n"
        "def f(chain, q):\n"
        "    llm_chain = chain\n"
        "    out = llm_chain.run(q)\n"
        "    os.system(out)\n"
    )
    assert "toleman-llm-output-to-shell" in _rule_ids(_scan(tmp_path))


# ---------------------------------------------------------------------------
# Unsafe model loading
# ---------------------------------------------------------------------------


def test_torch_load_without_weights_only_is_flagged(tmp_path):
    (tmp_path / "a.py").write_text("import torch\nm = torch.load('ckpt.pt')\n")
    assert "toleman-torch-load-without-weights-only" in _rule_ids(_scan(tmp_path))


def test_torch_load_with_weights_only_is_clean(tmp_path):
    (tmp_path / "a.py").write_text("import torch\nm = torch.load('ckpt.pt', weights_only=True)\n")
    assert "toleman-torch-load-without-weights-only" not in _rule_ids(_scan(tmp_path))


def test_pickle_load_is_flagged(tmp_path):
    (tmp_path / "a.py").write_text("import pickle\nm = pickle.load(open('m.pkl','rb'))\n")
    assert "toleman-pickle-load-of-model-artifact" in _rule_ids(_scan(tmp_path))


def test_unpinned_hub_model_is_flagged(tmp_path):
    (tmp_path / "a.py").write_text(
        "from transformers import AutoModel\nm = AutoModel.from_pretrained('bert-base-uncased')\n"
    )
    assert "toleman-unpinned-huggingface-model" in _rule_ids(_scan(tmp_path))


def test_pinned_hub_model_is_clean(tmp_path):
    (tmp_path / "a.py").write_text(
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('org/model', revision='abc123def456')\n"
    )
    assert "toleman-unpinned-huggingface-model" not in _rule_ids(_scan(tmp_path))


def test_local_model_directory_is_not_treated_as_a_hub_reference(tmp_path):
    (tmp_path / "a.py").write_text(
        "from transformers import AutoModel\nm = AutoModel.from_pretrained('./local-model-dir')\n"
    )
    assert "toleman-unpinned-huggingface-model" not in _rule_ids(_scan(tmp_path))


# ---------------------------------------------------------------------------
# Whole-ruleset guards
# ---------------------------------------------------------------------------


def test_ruleset_has_no_syntax_errors(tmp_path):
    """A malformed rule makes semgrep skip it silently, which would look
    exactly like "clean repo" from the outside."""
    (tmp_path / "a.py").write_text("x = 1\n")
    proc = subprocess.run(
        ["semgrep", "scan", f"--config={runner.LLM_RULES_DIR}", "--json", "--quiet", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    import json

    assert proc.returncode == 0, proc.stderr[:500]
    assert json.loads(proc.stdout).get("errors") == []


def test_ordinary_non_ai_python_produces_nothing(tmp_path):
    """The rules must be silent on code that has nothing to do with AI."""
    (tmp_path / "a.py").write_text(
        "import subprocess, sqlite3\n"
        "def backup(path):\n"
        "    subprocess.run(['tar', '-cf', 'out.tar', path])\n"
        "    con = sqlite3.connect('db')\n"
        "    con.cursor().execute('SELECT 1')\n"
    )
    assert _scan(tmp_path) == []


def test_severity_maps_through_the_shared_semgrep_parser(tmp_path):
    (tmp_path / "a.py").write_text("import torch\nm = torch.load('ckpt.pt')\n")
    findings = _scan(tmp_path)
    assert findings and findings[0]["severity"] in (Severity.HIGH, Severity.CRITICAL)
