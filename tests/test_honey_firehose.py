
from pathlib import Path

from licenseseal.watermark import (
    HoneyLogicDetector,
    embed_honey_logic,
    embed_watermark,
    expected_honey_logic_fingerprints,
    WatermarkConfig,
)


def test_zero_width_watermark_roundtrip_regression():
    cfg = WatermarkConfig(project_id="project-x", use_ast=False, use_honey_logic=False)
    source = "def f():\n    return 1\n"
    watermarked = embed_watermark(source, "project-x", "sig-y", cfg)
    from licenseseal.watermark import extract_watermark
    extracted = extract_watermark(watermarked, cfg)
    assert extracted is not None
    assert extracted["project_id"] == "project-x"


def test_honey_logic_is_deterministic_and_detectable():
    source = "def f(n):\n    return n + 1\n"
    watermarked = embed_honey_logic(source, "project-x", "sig-y", density=2)
    detector = HoneyLogicDetector()
    observed = detector.extract_fingerprints(watermarked)
    expected = expected_honey_logic_fingerprints("project-x", "sig-y", density=2)

    assert len(expected) == 2
    assert {fp.fingerprint for fp in expected}.issubset({fp.fingerprint for fp in observed})
    assert "def _ls_fold_" in watermarked
