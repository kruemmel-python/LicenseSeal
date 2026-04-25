"""
LicenseSeal graph fingerprinting
================================
Control-flow and data-flow fingerprints for resilience against deep refactors.

This module intentionally keeps the core implementation dependency-light. Python
gets a real AST-derived CFG/DFG approximation. Other languages receive a robust
token/control-keyword heuristic that still captures execution and data movement
without requiring a full compiler frontend.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .core import iter_candidate_files, strip_license_boundary, cosine_similarity


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str = ""


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str = "control"


@dataclass
class GraphFingerprint:
    language: str
    path_hashes: Counter[str] = field(default_factory=Counter)
    data_hashes: Counter[str] = field(default_factory=Counter)
    features: dict = field(default_factory=dict)

    def combined(self) -> Counter[str]:
        out = Counter()
        out.update({f"cfg:{k}": v for k, v in self.path_hashes.items()})
        out.update({f"dfg:{k}": v for k, v in self.data_hashes.items()})
        return out


def _h(value: object, size: int = 10) -> str:
    raw = json.dumps(value, sort_keys=True, default=str).encode("utf-8", "surrogatepass")
    return hashlib.blake2b(raw, digest_size=size).hexdigest()


class PythonGraphExtractor(ast.NodeVisitor):
    """Builds normalized CFG/DFG-ish paths from Python AST."""

    CONTROL_TYPES = (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Match, ast.BoolOp, ast.IfExp)
    ASSIGN_TYPES = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)

    def __init__(self) -> None:
        self.nodes: list[str] = []
        self.control_edges: list[tuple[str, str, str]] = []
        self.data_edges: list[tuple[str, str, str]] = []
        self._stack: list[str] = []
        self._last_by_var: dict[str, str] = {}

    def visit(self, node: ast.AST):  # type: ignore[override]
        node_id = f"{type(node).__name__}:{len(self.nodes)}"
        kind = self._kind(node)
        self.nodes.append(kind)
        if self._stack:
            self.control_edges.append((self._stack[-1], node_id, "contains"))
        self._stack.append(node_id)
        self._capture_dataflow(node, node_id)
        super().visit(node)
        self._stack.pop()

    def _kind(self, node: ast.AST) -> str:
        if isinstance(node, ast.FunctionDef):
            return "FunctionDef"
        if isinstance(node, ast.AsyncFunctionDef):
            return "AsyncFunctionDef"
        if isinstance(node, ast.ClassDef):
            return "ClassDef"
        if isinstance(node, self.CONTROL_TYPES):
            return type(node).__name__
        if isinstance(node, self.ASSIGN_TYPES):
            return type(node).__name__
        if isinstance(node, ast.Call):
            return "Call"
        if isinstance(node, ast.Return):
            return "Return"
        if isinstance(node, ast.Raise):
            return "Raise"
        if isinstance(node, ast.BinOp):
            return f"BinOp:{type(node.op).__name__}"
        if isinstance(node, ast.Compare):
            return "Compare"
        return type(node).__name__

    def _names_read(self, node: ast.AST) -> set[str]:
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                names.add(child.id)
        return names

    def _names_written(self, node: ast.AST) -> set[str]:
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                names.add(child.id)
        return names

    def _capture_dataflow(self, node: ast.AST, node_id: str) -> None:
        reads = self._names_read(node)
        for name in sorted(reads):
            prev = self._last_by_var.get(name)
            if prev:
                self.data_edges.append((prev, node_id, "read_after_write"))

        writes = self._names_written(node)
        for name in sorted(writes):
            prev = self._last_by_var.get(name)
            if prev:
                self.data_edges.append((prev, node_id, "write_after_write"))
            self._last_by_var[name] = node_id

    def fingerprint(self) -> GraphFingerprint:
        cfg = Counter()
        dfg = Counter()
        for src, dst, kind in self.control_edges:
            src_i = int(src.rsplit(":", 1)[-1])
            dst_i = int(dst.rsplit(":", 1)[-1])
            cfg[_h((self.nodes[src_i], kind, self.nodes[dst_i]))] += 1
        for src, dst, kind in self.data_edges:
            src_i = int(src.rsplit(":", 1)[-1])
            dst_i = int(dst.rsplit(":", 1)[-1])
            dfg[_h((self.nodes[src_i], kind, self.nodes[dst_i]))] += 1
        return GraphFingerprint(
            language="python",
            path_hashes=cfg,
            data_hashes=dfg,
            features={
                "node_count": len(self.nodes),
                "cfg_edge_count": len(self.control_edges),
                "dfg_edge_count": len(self.data_edges),
            },
        )


CONTROL_KEYWORDS = {
    "if", "else", "elif", "for", "while", "switch", "case", "match", "try", "catch",
    "finally", "return", "throw", "raise", "yield", "await", "async", "defer", "go",
}
DATA_TOKENS = {"=", "+=", "-=", "*=", "/=", "%=", ":=", "=>", "->"}


def heuristic_graph_fingerprint(source: str, language: str = "text") -> GraphFingerprint:
    """Language-agnostic graph-ish fallback from normalized control/data tokens."""
    source = re.sub(r"//.*|/\*.*?\*/|#.*", " ", source, flags=re.S)
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|\+=|-=|\*=|/=|%=|:=|=>|->|[{}();,:=]", source)
    normalized = []
    for token in tokens:
        if token in CONTROL_KEYWORDS or token in DATA_TOKENS or token in "{}();,:":
            normalized.append(token)
        elif re.match(r"[A-Za-z_]", token):
            normalized.append("_")
        else:
            normalized.append(token)

    cfg = Counter()
    dfg = Counter()
    controls = [t for t in normalized if t in CONTROL_KEYWORDS or t in "{}"]
    for i in range(max(0, len(controls) - 2)):
        cfg[_h(tuple(controls[i:i + 3]))] += 1
    for i, t in enumerate(normalized):
        if t in DATA_TOKENS:
            window = tuple(normalized[max(0, i - 3): i + 4])
            dfg[_h(window)] += 1
    return GraphFingerprint(
        language=language,
        path_hashes=cfg,
        data_hashes=dfg,
        features={"token_count": len(tokens), "control_count": len(controls), "data_ops": sum(dfg.values())},
    )


def fingerprint_source(source: str, language: str = "python") -> GraphFingerprint:
    source = strip_license_boundary(source)
    if language == "python":
        try:
            tree = ast.parse(source)
            extractor = PythonGraphExtractor()
            extractor.visit(tree)
            return extractor.fingerprint()
        except SyntaxError:
            pass
    return heuristic_graph_fingerprint(source, language)


LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust",
    ".java": "java", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
}


def fingerprint_file(path: Path) -> GraphFingerprint:
    language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "text")
    try:
        source = path.read_text(encoding="utf-8")
    except Exception:
        return GraphFingerprint(language=language)
    return fingerprint_source(source, language)


def project_graph_signature(root: Path, include_configs: bool = False, exclude_dirs: set[str] | None = None) -> Counter[str]:
    sig = Counter()
    for path in iter_candidate_files(root, exclude_dirs=exclude_dirs, include_configs=include_configs):
        fp = fingerprint_file(path)
        sig.update(fp.combined())
    return sig


def compare_graph_fingerprints(original: Path, suspected: Path, include_configs: bool = False, exclude_dirs: set[str] | None = None) -> dict:
    a = project_graph_signature(original, include_configs, exclude_dirs)
    b = project_graph_signature(suspected, include_configs, exclude_dirs)
    sim = cosine_similarity(a, b)
    return {
        "schema": "licenseseal.graph_compare.v1",
        "original": str(original),
        "suspected": str(suspected),
        "graph_similarity": round(sim, 4),
        "graph_similarity_percent": round(sim * 100, 2),
        "original_hashes": sum(a.values()),
        "suspected_hashes": sum(b.values()),
        "assessment": (
            "very_high_graph_similarity" if sim >= 0.90 else
            "high_graph_similarity" if sim >= 0.75 else
            "moderate_graph_similarity" if sim >= 0.55 else
            "low_graph_similarity"
        ),
    }
