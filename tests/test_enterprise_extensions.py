
import json
from pathlib import Path

from licenseseal.core import InjectionConfig, audit_project, inject_project
from licenseseal.ipynb_handler import audit_notebook, notebook_digest
from licenseseal.redteam import StressTestConfig, run_stress_test
from licenseseal.diff_viewer import ast_line_matches


def test_ipynb_injection_code_only_digest(tmp_path):
    nb = {
        "cells": [
            {"cell_type": "code", "metadata": {}, "execution_count": 1, "outputs": [{"text": "x"}], "source": ["x = 1\n"]},
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    path = tmp_path / "analysis.ipynb"
    path.write_text(json.dumps(nb), encoding="utf-8")

    cfg = InjectionConfig(root=tmp_path, license_id="MIT", owner="ACME", project="demo", update=True)
    results = inject_project(cfg)
    assert any(r.path == path and r.action in {"injected", "updated"} for r in results)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["cells"][0]["cell_type"] == "markdown"
    assert data["cells"][0]["metadata"]["licenseseal_marker"] is True
    assert "licenseseal" in data["metadata"]

    has_marker, fields = audit_notebook(path)
    assert has_marker
    assert fields["SPDX-License-Identifier"] == "MIT"

    # Output changes do not change code digest.
    stripped = dict(data)
    stripped["cells"] = stripped["cells"][1:]
    d1 = notebook_digest(stripped)
    stripped["cells"][0]["outputs"] = [{"text": "changed"}]
    stripped["cells"][0]["execution_count"] = 99
    assert notebook_digest(stripped) == d1


def test_audit_counts_ipynb_and_jsonl_sidecar(tmp_path):
    (tmp_path / "data.jsonl").write_text('{"x":1}\n', encoding="utf-8")
    nb = {"cells": [{"cell_type": "code", "metadata": {}, "source": ["print(1)\n"]}], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    (tmp_path / "n.ipynb").write_text(json.dumps(nb), encoding="utf-8")
    cfg = InjectionConfig(root=tmp_path, license_id="MIT", owner="ACME", project="demo", update=True)
    inject_project(cfg)
    total, marked, unmarked, verification = audit_project(tmp_path)
    assert marked >= 2
    assert not unmarked


def test_redteam_local_mode(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("""
def add(x, y):
    return x + y
""", encoding="utf-8")
    report = run_stress_test(StressTestConfig(root=tmp_path, sample_size=1, mode="local", output_dir=tmp_path / "out"))
    assert report.files
    assert 0 <= report.overall_survival_rate <= 1


def test_ast_line_matches_identifier_rename(tmp_path):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("def f(x):\n    y = x + 1\n    return y\n", encoding="utf-8")
    b.write_text("def g(z):\n    q = z + 1\n    return q\n", encoding="utf-8")
    matches = ast_line_matches(a, b, "a.py", "b.py")
    assert matches
