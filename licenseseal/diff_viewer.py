"""
LicenseSeal side-by-side code evidence mapping
==============================================

A lightweight AST-aware diff engine for legal reports and web dashboards.
It returns line-range mappings instead of only aggregate similarity scores.
"""

from __future__ import annotations

import ast
import html
import hashlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


@dataclass
class CodeRange:
    start: int
    end: int


@dataclass
class CodeMatch:
    original_file: str
    suspected_file: str
    original_range: CodeRange
    suspected_range: CodeRange
    node_type: str
    fingerprint: str
    similarity: float = 1.0

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["original_range"] = asdict(self.original_range)
        payload["suspected_range"] = asdict(self.suspected_range)
        return payload


def _normalize_ast_node(node: ast.AST) -> str:
    """Dump an AST node without variable names that are cheap to rename."""
    class Normalizer(ast.NodeTransformer):
        def visit_Name(self, n: ast.Name):
            return ast.copy_location(ast.Name(id="_VAR_", ctx=n.ctx), n)

        def visit_arg(self, n: ast.arg):
            n.arg = "_ARG_"
            return n

        def visit_Attribute(self, n: ast.Attribute):
            self.generic_visit(n)
            n.attr = "_ATTR_"
            return n

        def visit_FunctionDef(self, n: ast.FunctionDef):
            n.name = "_FUNC_"
            self.generic_visit(n)
            return n

        def visit_ClassDef(self, n: ast.ClassDef):
            n.name = "_CLASS_"
            self.generic_visit(n)
            return n

    cloned = ast.fix_missing_locations(Normalizer().visit(ast.parse(ast.unparse(node))) if hasattr(ast, "unparse") else node)
    return ast.dump(cloned, annotate_fields=True, include_attributes=False)


def _fingerprint_node(node: ast.AST) -> str:
    normalized = _normalize_ast_node(node)
    return hashlib.blake2b(normalized.encode("utf-8"), digest_size=12).hexdigest()


def _extract_python_ranges(path: Path) -> dict[str, tuple[CodeRange, str]]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return {}

    out: dict[str, tuple[CodeRange, str]] = {}
    for node in ast.walk(tree):
        if not hasattr(node, "lineno") or not hasattr(node, "end_lineno"):
            continue
        if isinstance(node, (ast.Module, ast.Load, ast.Store)):
            continue
        # Avoid very small fragments that create noisy matches.
        start = int(getattr(node, "lineno"))
        end = int(getattr(node, "end_lineno"))
        if end - start < 1 and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        fp = _fingerprint_node(node)
        out[fp] = (CodeRange(start, end), type(node).__name__)
    return out


def ast_line_matches(original_file: Path, suspected_file: Path, original_rel: str, suspected_rel: str, limit: int = 100) -> list[CodeMatch]:
    orig = _extract_python_ranges(original_file)
    susp = _extract_python_ranges(suspected_file)
    matches: list[CodeMatch] = []
    for fp in set(orig) & set(susp):
        o_range, node_type = orig[fp]
        s_range, _ = susp[fp]
        matches.append(CodeMatch(
            original_file=original_rel,
            suspected_file=suspected_rel,
            original_range=o_range,
            suspected_range=s_range,
            node_type=node_type,
            fingerprint=fp,
            similarity=1.0,
        ))
    matches.sort(key=lambda m: (-(m.original_range.end - m.original_range.start), m.original_file, m.suspected_file))
    return matches[:limit]


def collect_project_line_matches(original_root: Path, suspected_root: Path, pairs: Iterable[dict], limit_per_pair: int = 50) -> list[dict]:
    all_matches: list[dict] = []
    for pair in pairs:
        o_rel = pair.get("original_file")
        s_rel = pair.get("suspected_file")
        if not o_rel or not s_rel:
            continue
        o = original_root / o_rel
        s = suspected_root / s_rel
        if o.suffix.lower() != ".py" or s.suffix.lower() != ".py":
            continue
        all_matches.extend(m.to_dict() for m in ast_line_matches(o, s, o_rel, s_rel, limit=limit_per_pair))
    return all_matches


def render_side_by_side_html(original_text: str, suspected_text: str, original_ranges: list[dict], suspected_ranges: list[dict]) -> str:
    """Render a simple dependency-free two-column diff with highlighted ranges."""
    def marked_lines(text: str, ranges: list[dict]) -> str:
        lines = text.splitlines()
        highlighted = set()
        for r in ranges:
            for i in range(int(r["start"]), int(r["end"]) + 1):
                highlighted.add(i)
        rendered = []
        for idx, line in enumerate(lines, start=1):
            cls = " class='ls-hit'" if idx in highlighted else ""
            rendered.append(f"<tr{cls}><td class='ln'>{idx}</td><td><pre>{html.escape(line)}</pre></td></tr>")
        return "\n".join(rendered)

    return f"""
<div class="ls-diff">
  <div class="ls-pane"><table>{marked_lines(original_text, original_ranges)}</table></div>
  <div class="ls-pane"><table>{marked_lines(suspected_text, suspected_ranges)}</table></div>
</div>
"""
