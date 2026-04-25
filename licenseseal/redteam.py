"""
LicenseSeal Red-Team Stress Testing
===================================

Defensive robustness testing for a user's own protected code. The module
simulates refactors and optional LLM rewrites, then measures whether LicenseSeal
watermarks and Honey-Logic survive.

It does not remove third-party provenance; it only evaluates resilience of code
under the caller's control.
"""

from __future__ import annotations

import ast
import json
import os
import random
import shutil
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .core import DEFAULT_EXCLUDE_DIRS, iter_candidate_files
from .watermark import HoneyLogicDetector, extract_watermark


@dataclass
class StressTestConfig:
    root: Path
    sample_size: int = 5
    mode: str = "local"  # local, ollama, lmstudio
    seed: int = 1337
    ollama_url: str = "http://localhost:11434/api/generate"
    ollama_model: str = "codellama"
    lmstudio_url: str = "http://localhost:1234/v1/chat/completions"
    lmstudio_model: str = "local-model"
    output_dir: Path | None = None
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))


@dataclass
class FileStressResult:
    original_path: str
    rewritten_path: str
    watermark_before: bool
    watermark_after: bool
    honey_before: int
    honey_after: int
    survival_score: float
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original_path": self.original_path,
            "rewritten_path": self.rewritten_path,
            "watermark_before": self.watermark_before,
            "watermark_after": self.watermark_after,
            "honey_before": self.honey_before,
            "honey_after": self.honey_after,
            "survival_score": self.survival_score,
            "notes": self.notes,
        }


@dataclass
class StressTestReport:
    root: str
    mode: str
    files: list[FileStressResult]
    output_dir: str
    watermark_survival_rate: float
    honey_survival_rate: float
    overall_survival_rate: float
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "mode": self.mode,
            "output_dir": self.output_dir,
            "watermark_survival_rate": self.watermark_survival_rate,
            "honey_survival_rate": self.honey_survival_rate,
            "overall_survival_rate": self.overall_survival_rate,
            "recommendation": self.recommendation,
            "files": [f.to_dict() for f in self.files],
        }


class _LocalRefactor(ast.NodeTransformer):
    """Behavior-preserving-ish local rewrite: rename local identifiers and normalize loops."""

    def __init__(self):
        self._map: dict[str, str] = {}
        self._counter = 0

    def _name(self, old: str) -> str:
        if old.startswith("__") and old.endswith("__"):
            return old
        if old not in self._map:
            self._counter += 1
            self._map[old] = f"ls_rt_{self._counter}"
        return self._map[old]

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, (ast.Store, ast.Load, ast.Del)) and not node.id.startswith("_ls_"):
            node.id = self._name(node.id)
        return node

    def visit_arg(self, node: ast.arg):
        if not node.arg.startswith("_ls_"):
            node.arg = self._name(node.arg)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Keep _ls_ honey helpers intact; rewrite ordinary names.
        if not node.name.startswith("_ls_"):
            node.name = self._name(node.name)
        self.generic_visit(node)
        return node


def local_rewrite_python(source: str) -> str:
    """Offline rewrite simulation that avoids external services."""
    try:
        tree = ast.parse(source)
        tree = _LocalRefactor().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree) + "\n"
    except Exception:
        # Fallback: strip comments/blank lines while keeping source runnable enough.
        lines = []
        for line in source.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if line.strip():
                lines.append(line)
        return "\n".join(lines) + "\n"


def ollama_rewrite_python(source: str, cfg: StressTestConfig) -> str:
    """Optional local Ollama rewrite adapter. Uses localhost only by default."""
    prompt = (
        "Rewrite this Python code as a normal refactor. Preserve exact behavior. "
        "Rename variables and restructure simple expressions where safe. "
        "Do not add explanations, only return code.\n\n"
        f"```python\n{source}\n```"
    )
    payload = json.dumps({"model": cfg.ollama_model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(cfg.ollama_url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = data.get("response", "")
    if "```" in text:
        parts = text.split("```")
        text = max(parts, key=len)
        if text.lstrip().startswith("python"):
            text = text.lstrip()[6:]
    return text.strip() + "\n"



def lmstudio_rewrite_python(source: str, cfg: StressTestConfig) -> str:
    """Optional LM Studio rewrite adapter using its OpenAI-compatible local API."""
    prompt = (
        "Rewrite this Python code as a normal defensive robustness refactor for code owned by the requester. "
        "Preserve exact behavior and public API. Rename local variables and restructure simple expressions where safe. "
        "Do not add explanations, only return code.\n\n"
        f"```python\n{source}\n```"
    )
    payload = json.dumps({
        "model": cfg.lmstudio_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }).encode("utf-8")
    req = urllib.request.Request(cfg.lmstudio_url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if "```" in text:
        parts = text.split("```")
        text = max(parts, key=len)
        if text.lstrip().startswith("python"):
            text = text.lstrip()[6:]
    return text.strip() + "\n"

def select_python_files(root: Path, sample_size: int, exclude_dirs: set[str], seed: int) -> list[Path]:
    files = [p for p in iter_candidate_files(root, exclude_dirs, include_configs=False) if p.suffix.lower() == ".py"]
    rnd = random.Random(seed)
    rnd.shuffle(files)
    return files[:sample_size]


def _survival(before_wm: bool, after_wm: bool, before_honey: int, after_honey: int) -> float:
    parts = []
    if before_wm:
        parts.append(1.0 if after_wm else 0.0)
    if before_honey:
        parts.append(min(1.0, after_honey / before_honey))
    if not parts:
        return 1.0
    return sum(parts) / len(parts)


def run_stress_test(cfg: StressTestConfig) -> StressTestReport:
    root = cfg.root.resolve()
    out = cfg.output_dir or Path(tempfile.mkdtemp(prefix="licenseseal-redteam-"))
    out.mkdir(parents=True, exist_ok=True)

    if cfg.mode == "ollama":
        rewriter = lambda s: ollama_rewrite_python(s, cfg)
    elif cfg.mode in {"lmstudio", "lm-studio", "lm_studio"}:
        rewriter = lambda s: lmstudio_rewrite_python(s, cfg)
    else:
        rewriter = local_rewrite_python

    detector = HoneyLogicDetector()
    results: list[FileStressResult] = []
    for path in select_python_files(root, cfg.sample_size, cfg.exclude_dirs, cfg.seed):
        rel = path.relative_to(root)
        source = path.read_text(encoding="utf-8", errors="replace")
        before_wm = extract_watermark(source) is not None
        before_honey = len(detector.extract_fingerprints(source))

        try:
            rewritten = rewriter(source)
            notes: list[str] = []
        except Exception as exc:
            rewritten = local_rewrite_python(source)
            notes = [f"{cfg.mode} rewrite failed; used local fallback: {exc}"]

        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rewritten, encoding="utf-8")

        after_wm = extract_watermark(rewritten) is not None
        after_honey = len(detector.extract_fingerprints(rewritten))
        score = _survival(before_wm, after_wm, before_honey, after_honey)

        results.append(FileStressResult(
            original_path=str(rel),
            rewritten_path=str(target),
            watermark_before=before_wm,
            watermark_after=after_wm,
            honey_before=before_honey,
            honey_after=after_honey,
            survival_score=round(score, 4),
            notes=notes,
        ))

    wm_relevant = [r for r in results if r.watermark_before]
    honey_relevant = [r for r in results if r.honey_before > 0]
    wm_rate = sum(1 for r in wm_relevant if r.watermark_after) / len(wm_relevant) if wm_relevant else 1.0
    honey_rate = sum((min(1.0, r.honey_after / r.honey_before) if r.honey_before else 1.0) for r in honey_relevant) / len(honey_relevant) if honey_relevant else 1.0
    overall = sum(r.survival_score for r in results) / len(results) if results else 1.0

    if overall < 0.5:
        rec = "Increase honey_density and combine Honey-Logic with semantic and boundary markers."
    elif overall < 0.8:
        rec = "Consider robust watermark mode and at least two Honey-Logic snippets per critical module."
    else:
        rec = "Current watermark configuration survived the tested rewrite scenarios well."

    return StressTestReport(
        root=str(root),
        mode=cfg.mode,
        files=results,
        output_dir=str(out),
        watermark_survival_rate=round(wm_rate, 4),
        honey_survival_rate=round(honey_rate, 4),
        overall_survival_rate=round(overall, 4),
        recommendation=rec,
    )
