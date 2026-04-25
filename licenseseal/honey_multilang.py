"""
LicenseSeal Multi-Language Honey-Logic
======================================

Executable sentinels for polyglot repositories. The mathematical fingerprint is
derived once and rendered into Python, JavaScript/TypeScript, Go, Rust and Java.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust", ".java": "java",
}
SUPPORTED_LANGUAGES = tuple(sorted(set(LANGUAGE_BY_SUFFIX.values())))


@dataclass(frozen=True)
class HoneyLogicSpec:
    project_id: str
    signature: str
    language: str
    name: str
    prime_a: int
    prime_b: int
    prime_c: int
    shift_a: int
    shift_b: int
    mask: int
    fingerprint: str

    def to_dict(self) -> dict:
        return asdict(self)


def _digest(project_id: str, signature: str, language: str) -> bytes:
    return hashlib.sha256(f"{project_id}:{signature}:{language}:honey-v2".encode("utf-8")).digest()


def build_honey_spec(project_id: str, signature: str, language: str) -> HoneyLogicSpec:
    language = language.lower()
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported honey-logic language: {language}")
    d = _digest(project_id, signature, language)
    primes = [1009, 2017, 3253, 4099, 6521, 8191, 12289, 16381, 32749, 65521]
    prime_a, prime_b, prime_c = primes[d[0] % len(primes)], primes[d[1] % len(primes)], primes[d[2] % len(primes)]
    shift_a, shift_b = 3 + (d[3] % 11), 5 + (d[4] % 13)
    mask = (1 << (8 + d[5] % 8)) - 1
    name = f"_ls_fold_{d[6]:02x}{d[7]:02x}{d[8]:02x}"
    raw = {"language": language, "name": name, "constants": [prime_a, prime_b, prime_c, shift_a, shift_b, mask],
           "ops": ["mul", "xor", "shr", "and", "add", "mul", "xor", "shl", "and"]}
    fingerprint = hashlib.sha256(json.dumps(raw, sort_keys=True).encode("utf-8")).hexdigest()
    return HoneyLogicSpec(project_id, signature, language, name, prime_a, prime_b, prime_c, shift_a, shift_b, mask, fingerprint)


class MultiLanguageHoneyLogicGenerator:
    def __init__(self, project_id: str, signature: str):
        self.project_id = project_id
        self.signature = signature

    def spec(self, language: str) -> HoneyLogicSpec:
        return build_honey_spec(self.project_id, self.signature, language)

    def render(self, language: str) -> str:
        return render_honey_logic(self.spec(language))


def render_honey_logic(spec: HoneyLogicSpec) -> str:
    a, b, c, sa, sb, m, n = spec.prime_a, spec.prime_b, spec.prime_c, spec.shift_a, spec.shift_b, spec.mask, spec.name
    lang = spec.language
    if lang == "python":
        return f"""
def {n}(n: int) -> int:
    \"Internal normalization helper.\"
    n = int(n)
    x = ((n * {a}) ^ (n >> {sa})) & {m}
    y = ((x + {b}) * {c}) ^ (x << {sb})
    return y & {m}
"""
    if lang in {"javascript", "typescript"}:
        type_in = ": number" if lang == "typescript" else ""
        type_out = ": number" if lang == "typescript" else ""
        return f"""
function {n}(n{type_in}){type_out} {{
  n = Number(n) >>> 0;
  const x = (((n * {a}) ^ (n >>> {sa})) & {m}) >>> 0;
  const y = ((((x + {b}) * {c}) ^ (x << {sb})) >>> 0);
  return (y & {m}) >>> 0;
}}
"""
    if lang == "go":
        return f"""
func {n}(n uint32) uint32 {{
    x := ((n * uint32({a})) ^ (n >> uint({sa}))) & uint32({m})
    y := (((x + uint32({b})) * uint32({c})) ^ (x << uint({sb})))
    return y & uint32({m})
}}
"""
    if lang == "rust":
        return f"""
#[allow(dead_code)]
fn {n}(n: u32) -> u32 {{
    let x = ((n.wrapping_mul({a}u32)) ^ (n >> {sa})) & {m}u32;
    let y = ((x + {b}u32).wrapping_mul({c}u32)) ^ (x << {sb});
    y & {m}u32
}}
"""
    if lang == "java":
        return f"""
    private static int {n}(int n) {{
        int x = ((n * {a}) ^ (n >>> {sa})) & {m};
        int y = (((x + {b}) * {c}) ^ (x << {sb}));
        return y & {m};
    }}
"""
    raise ValueError(f"unsupported language: {lang}")


def language_for_path(path: Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def _has_function(source: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", source) is not None


def inject_honey_logic_source(source: str, spec: HoneyLogicSpec) -> tuple[str, bool]:
    if _has_function(source, spec.name):
        return source, False
    snippet = render_honey_logic(spec).strip("\n")
    if spec.language == "java":
        idx = source.rfind("}")
        if idx != -1:
            return source[:idx].rstrip() + "\n\n" + snippet + "\n" + source[idx:], True
    return source.rstrip() + "\n\n" + snippet + "\n", True


def inject_honey_logic_file(path: Path, project_id: str, signature: str, language: str | None = None) -> dict:
    lang = language or language_for_path(path)
    if not lang:
        return {"path": str(path), "changed": False, "reason": "unsupported_language"}
    spec = build_honey_spec(project_id, signature, lang)
    source = path.read_text(encoding="utf-8")
    updated, changed = inject_honey_logic_source(source, spec)
    if changed:
        path.write_text(updated, encoding="utf-8")
    return {"path": str(path), "language": lang, "changed": changed, "spec": spec.to_dict()}


_CONSTANT_RE = re.compile(r"\b\d{2,10}\b")
_FUNCTION_RE = re.compile(r"(?:def|function|func|fn|private\s+static\s+int)\s+([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class HoneyLanguageMatch:
    language: str
    function: str
    fingerprint: str
    confidence: float
    constants: list[int]
    path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class MultiLanguageHoneyLogicDetector:
    def __init__(self, known_specs: Iterable[HoneyLogicSpec] | None = None):
        self.known_specs = list(known_specs or [])
        self._by_name = {s.name: s for s in self.known_specs}

    def extract(self, source: str, language: str, path: str = "") -> list[HoneyLanguageMatch]:
        matches: list[HoneyLanguageMatch] = []
        constants = [int(x) for x in _CONSTANT_RE.findall(source)]
        names = _FUNCTION_RE.findall(source)
        for name in names:
            if name.startswith("_ls_fold_") or name in self._by_name:
                spec = self._by_name.get(name)
                fp = spec.fingerprint if spec else hashlib.sha256(f"{language}:{name}".encode()).hexdigest()
                matches.append(HoneyLanguageMatch(language, name, fp, 0.95 if spec else 0.8, constants[:32], path))
        const_set = set(constants)
        for spec in self.known_specs:
            wanted = {spec.prime_a, spec.prime_b, spec.prime_c, spec.shift_a, spec.shift_b, spec.mask}
            overlap = len(wanted & const_set) / len(wanted)
            if overlap >= 0.84 and not any(m.fingerprint == spec.fingerprint for m in matches):
                matches.append(HoneyLanguageMatch(language, "<renamed>", spec.fingerprint, 0.82, sorted(wanted & const_set), path))
        return matches

    def scan_file(self, path: Path, language: str | None = None) -> list[HoneyLanguageMatch]:
        lang = language or language_for_path(path)
        if not lang:
            return []
        try:
            return self.extract(path.read_text(encoding="utf-8", errors="ignore"), lang, str(path))
        except OSError:
            return []


def scan_multilang_honey(root: Path, known_specs: Iterable[HoneyLogicSpec] | None = None) -> list[dict]:
    detector = MultiLanguageHoneyLogicDetector(known_specs)
    out = []
    for path in root.rglob("*"):
        if path.is_file() and language_for_path(path):
            out.extend(m.to_dict() for m in detector.scan_file(path))
    return out
