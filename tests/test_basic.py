from pathlib import Path

from licenseseal.core import (
    InjectionConfig,
    audit_project,
    compare_projects,
    inject_project,
    remove_project,
)


def test_inject_update_remove_and_audit(tmp_path: Path):
    p = tmp_path / "demo"
    p.mkdir()
    target = p / "x.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")

    cfg = InjectionConfig(root=p, license_id="MIT", owner="Tester", project="demo")
    results = inject_project(cfg)
    assert any(r.action == "injected" for r in results)

    total, marked, unmarked, verification = audit_project(p)
    assert total == 1
    assert marked == 1
    assert not unmarked
    assert verification == []

    cfg2 = InjectionConfig(root=p, license_id="AGPL-3.0-or-later", owner="New Owner", project="demo", update=True)
    results = inject_project(cfg2)
    assert any(r.action == "updated" for r in results)
    text = target.read_text(encoding="utf-8")
    assert "AGPL-3.0-or-later" in text
    assert "New Owner" in text
    assert text.count("AI_LICENSE_BOUNDARY_BEGIN") == 1

    results = remove_project(p)
    assert any(r.action == "removed" for r in results)
    assert "AI_LICENSE_BOUNDARY_BEGIN" not in target.read_text(encoding="utf-8")


def test_compare_detects_similarity(tmp_path: Path):
    original = tmp_path / "original"
    suspected = tmp_path / "suspected"
    original.mkdir()
    suspected.mkdir()

    (original / "x.py").write_text("def f(a):\n    return a + 1\n", encoding="utf-8")
    (suspected / "y.py").write_text("def g(b):\n    return b + 1\n", encoding="utf-8")

    cfg = InjectionConfig(root=original, license_id="AGPL-3.0-or-later", owner="Tester", project="demo")
    inject_project(cfg)

    report = compare_projects(original, suspected)
    assert report["structural_similarity"] > 0.5
