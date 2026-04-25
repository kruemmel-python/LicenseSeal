from pathlib import Path
import json

from licenseseal.honey_multilang import (
    build_honey_spec,
    inject_honey_logic_source,
    MultiLanguageHoneyLogicDetector,
)
from licenseseal.semantic_morph import embed_morph_watermark, verify_morph_watermark
from licenseseal.build_integration import (
    create_binary_provenance,
    append_provenance_blob,
    audit_binary,
)
from licenseseal.lsp import inbound_paste_check


def test_multilang_honey_js_detection():
    spec = build_honey_spec("project", "sig", "javascript")
    source, changed = inject_honey_logic_source("const ok = true;\n", spec)
    assert changed
    hits = MultiLanguageHoneyLogicDetector([spec]).extract(source, "javascript", "x.js")
    assert hits
    assert hits[0].fingerprint == spec.fingerprint


def test_semantic_morph_local_roundtrip():
    source = "def add(a, b):\n    return a + b\n"
    result = embed_morph_watermark(source, "secret-seed")
    assert result["verification"]["ok"]
    assert verify_morph_watermark(result["source"], "secret-seed")["ok"]


def test_binary_provenance_append_and_audit(tmp_path: Path):
    (tmp_path / "a.py").write_text("print('x')\n")
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"fake-binary")
    prov = create_binary_provenance(tmp_path, "demo", "demo-id")
    append_provenance_blob(binary, prov)
    audit = audit_binary(binary)
    assert audit["found"]
    assert audit["provenance"]["project_id"] == "demo-id"


def test_inbound_paste_protection_marker():
    diags = inbound_paste_check("AI_LICENSE_BOUNDARY_BEGIN\nSPDX-License-Identifier: AGPL-3.0\n")
    assert diags
    assert any(d.confidence >= 0.9 for d in diags)
