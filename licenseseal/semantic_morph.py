"""
LicenseSeal Semantic Morph Watermarking
=======================================

Defensive LLM-assisted watermarking for code owned by the caller.  The module
asks a local LLM endpoint (Ollama or LM Studio OpenAI-compatible API) to rewrite
small functions while preserving behaviour and embedding verifiable structural
invariants derived from a secret seed.
"""

from __future__ import annotations

import ast
import hashlib
import json
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class MorphInvariant:
    seed: str
    assignment_mod: int
    min_branch_count: int
    ast_depth_parity: int
    fingerprint: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MorphConfig:
    backend: str = "local"  # local, ollama, lmstudio
    ollama_url: str = "http://localhost:11434/api/generate"
    ollama_model: str = "codellama"
    lmstudio_url: str = "http://localhost:1234/v1/chat/completions"
    lmstudio_model: str = "local-model"
    timeout: int = 120


def invariant_from_seed(seed: str) -> MorphInvariant:
    d = hashlib.sha256(seed.encode("utf-8")).digest()
    assignment_mod = 2 + (d[0] % 4)
    min_branch_count = d[1] % 3
    ast_depth_parity = d[2] % 2
    fp = hashlib.sha256(f"{assignment_mod}:{min_branch_count}:{ast_depth_parity}".encode()).hexdigest()
    return MorphInvariant(seed, assignment_mod, min_branch_count, ast_depth_parity, fp)


def _ast_depth(node: ast.AST) -> int:
    children = list(ast.iter_child_nodes(node))
    if not children:
        return 1
    return 1 + max(_ast_depth(c) for c in children)


def measure_invariants(source: str) -> dict:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"valid_python": False, "assignments": 0, "branches": 0, "depth": 0}
    assignments = sum(isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) for n in ast.walk(tree))
    branches = sum(isinstance(n, (ast.If, ast.IfExp, ast.Match, ast.For, ast.While, ast.comprehension)) for n in ast.walk(tree))
    depth = _ast_depth(tree)
    return {"valid_python": True, "assignments": assignments, "branches": branches, "depth": depth}


def verify_morph_watermark(source: str, seed: str) -> dict:
    inv = invariant_from_seed(seed)
    m = measure_invariants(source)
    helper_present = f"_ls_semantic_morph_guard_{inv.fingerprint[:8]}" in source
    ok = bool(
        m["valid_python"]
        and (
            helper_present
            or (
                (m["assignments"] % inv.assignment_mod == 0)
                and (m["branches"] >= inv.min_branch_count)
                and (m["depth"] % 2 == inv.ast_depth_parity)
            )
        )
    )
    return {"ok": ok, "invariant": inv.to_dict(), "measured": m, "helper_present": helper_present}


def _post_json(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _prompt(source: str, invariant: MorphInvariant) -> str:
    return f"""You are rewriting code owned by the requester for defensive provenance watermarking.
Preserve exact behaviour and public API. Do not add license-removal or evasion logic.
Rewrite the Python function/module so that:
- number of assignment statements is divisible by {invariant.assignment_mod}
- AST depth parity is {invariant.ast_depth_parity} where 0=even and 1=odd
- at least {invariant.min_branch_count} branch/loop/comprehension nodes exist when natural
Return only Python code.

SOURCE:
```python
{source}
```"""


def morph_with_ollama(source: str, invariant: MorphInvariant, cfg: MorphConfig) -> str:
    data = _post_json(cfg.ollama_url, {"model": cfg.ollama_model, "prompt": _prompt(source, invariant), "stream": False}, cfg.timeout)
    return data.get("response", source)


def morph_with_lmstudio(source: str, invariant: MorphInvariant, cfg: MorphConfig) -> str:
    payload = {
        "model": cfg.lmstudio_model,
        "messages": [{"role": "user", "content": _prompt(source, invariant)}],
        "temperature": 0.2,
    }
    data = _post_json(cfg.lmstudio_url, payload, cfg.timeout)
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:
        return source


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip() + "\n"
    return text


def local_morph(source: str, invariant: MorphInvariant) -> str:
    """Deterministic conservative fallback: adds a tiny invariant helper."""
    helper = f"""
def _ls_semantic_morph_guard_{invariant.fingerprint[:8]}() -> int:
    marker_value = {invariant.assignment_mod}
    branch_value = {invariant.min_branch_count}
    depth_value = {invariant.ast_depth_parity}
    if branch_value >= 0:
        return marker_value + branch_value + depth_value
    return marker_value
"""
    return source.rstrip() + "\n\n" + helper


def embed_morph_watermark(source: str, seed: str, cfg: MorphConfig | None = None) -> dict:
    cfg = cfg or MorphConfig()
    inv = invariant_from_seed(seed)
    backend = cfg.backend.lower()
    try:
        if backend == "ollama":
            morphed = morph_with_ollama(source, inv, cfg)
        elif backend in {"lmstudio", "lm-studio", "lm_studio"}:
            morphed = morph_with_lmstudio(source, inv, cfg)
        else:
            morphed = local_morph(source, inv)
    except Exception:
        morphed = local_morph(source, inv)
    morphed = _strip_fences(morphed)
    verification = verify_morph_watermark(morphed, seed)
    if not verification["ok"]:
        morphed = local_morph(source, inv)
        verification = verify_morph_watermark(morphed, seed)
    return {"source": morphed, "verification": verification, "invariant": inv.to_dict(), "backend": backend}


def morph_file(path: Path, seed: str, cfg: MorphConfig | None = None) -> dict:
    source = path.read_text(encoding="utf-8")
    result = embed_morph_watermark(source, seed, cfg)
    path.write_text(result["source"], encoding="utf-8")
    return {"path": str(path), "backend": result["backend"], "verification": result["verification"], "invariant": result["invariant"]}
