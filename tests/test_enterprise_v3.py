
from __future__ import annotations

import json
from pathlib import Path

from licenseseal.graph_fingerprint import compare_graph_fingerprints, fingerprint_source
from licenseseal.sca_check import check_project
from licenseseal.llm_interceptor import scan_text
from licenseseal.bot import autofix_project


def test_graph_fingerprint_survives_identifier_renames(tmp_path: Path):
    src_a = """
def total(xs):
    s = 0
    for x in xs:
        if x > 0:
            s += x
    return s
"""
    src_b = """
def renamed(items):
    acc = 0
    for item in items:
        if item > 0:
            acc += item
    return acc
"""
    a = fingerprint_source(src_a, "python").combined()
    b = fingerprint_source(src_b, "python").combined()
    assert a
    assert b
    shared = set(a) & set(b)
    assert shared


def test_graph_project_compare(tmp_path: Path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "m.py").write_text("def f(x):\n    y=x+1\n    return y\n", encoding="utf-8")
    (b / "m.py").write_text("def g(z):\n    q=z+1\n    return q\n", encoding="utf-8")
    report = compare_graph_fingerprints(a, b)
    assert report["graph_similarity"] > 0


def test_sca_detects_stronger_target_warning(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\nlicense={text="MIT"}\n', encoding="utf-8")
    report = check_project(tmp_path, "AGPL-3.0")
    assert report.findings
    assert any(c.severity == "warning" for c in report.conflicts)


def test_llm_interceptor_blocks_boundary():
    result = scan_text("# AI_LICENSE_BOUNDARY_BEGIN\n# SPDX-License-Identifier: MIT\n")
    assert not result.allowed
    assert any(f.kind == "licenseseal_boundary" for f in result.findings)


def test_bot_autofix_dry_run(tmp_path: Path):
    (tmp_path / "a.py").write_text("print('hello')\n", encoding="utf-8")
    result = autofix_project(tmp_path, license_id="MIT", owner="ACME", dry_run=True)
    assert result.before_missing == 1
    assert result.changed >= 1
