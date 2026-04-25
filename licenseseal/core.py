from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


BOUNDARY_BEGIN = "AI_LICENSE_BOUNDARY_BEGIN"
BOUNDARY_END = "AI_LICENSE_BOUNDARY_END"
TOOL_NAME = "licenseseal"
TOOL_SCHEMA = "ai-license-boundary.v2"


DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn",
    ".tox", ".nox", ".venv", "venv", "env",
    "node_modules", "dist", "build", "target",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", ".vscode",
}


COMMENT_PREFIX_BY_SUFFIX = {
    ".py": "#", ".pyw": "#",
    ".sh": "#", ".bash": "#", ".zsh": "#", ".fish": "#", ".ps1": "#",
    ".rb": "#", ".pl": "#", ".pm": "#", ".r": "#", ".jl": "#",
    ".yaml": "#", ".yml": "#", ".toml": "#", ".ini": "#", ".cfg": "#", ".conf": "#",
    ".js": "//", ".jsx": "//", ".ts": "//", ".tsx": "//",
    ".java": "//", ".c": "//", ".h": "//", ".cpp": "//", ".hpp": "//", ".cc": "//",
    ".cs": "//", ".go": "//", ".rs": "//", ".swift": "//", ".kt": "//", ".kts": "//",
    ".scala": "//", ".php": "//", ".dart": "//", ".sol": "//",
    ".sql": "--", ".lua": "--", ".hs": "--",
    ".erl": "%", ".ex": "#", ".exs": "#",
    ".clj": ";;", ".cljs": ";;", ".lisp": ";;", ".el": ";;",
}

TREE_SITTER_LANGUAGE_BY_SUFFIX = {
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".java": "java", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
    ".cs": "c_sharp", ".go": "go", ".rs": "rust",
    ".php": "php", ".rb": "ruby", ".kt": "kotlin",
    ".swift": "swift", ".scala": "scala", ".lua": "lua",
}

SPECIAL_FILENAMES = {
    "Dockerfile": "#",
    "Makefile": "#",
    "Justfile": "#",
    "Rakefile": "#",
    "Gemfile": "#",
    "Podfile": "#",
}

TEXT_CONFIG_FILES = {
    "pyproject.toml", "setup.cfg", "tox.ini", "ruff.toml",
    ".pre-commit-config.yaml", ".gitlab-ci.yml",
    "docker-compose.yml", "compose.yml",
}


@dataclass(frozen=True)
class InjectionConfig:
    root: Path
    license_id: str
    owner: str
    project: str
    dry_run: bool = False
    backup: bool = False
    write_policy: bool = False
    include_configs: bool = False
    update: bool = False
    private_key: Path | None = None
    exclude_dirs: set[str] | None = None
    include_git: bool = False  # Extension 4: Include Git commit info in signatures


@dataclass
class FileResult:
    path: Path
    action: str
    reason: str = ""


def current_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def is_probably_binary(path: Path, sample_size: int = 4096) -> bool:
    try:
        chunk = path.read_bytes()[:sample_size]
    except OSError:
        return True
    return b"\x00" in chunk


def comment_prefix_for(path: Path, include_configs: bool) -> Optional[str]:
    if path.name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[path.name]
    if include_configs and path.name in TEXT_CONFIG_FILES:
        return COMMENT_PREFIX_BY_SUFFIX.get(path.suffix.lower(), "#")
    return COMMENT_PREFIX_BY_SUFFIX.get(path.suffix.lower())


def _git_ls_files(root: Path) -> list[Path] | None:
    if not (root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    files: list[Path] = []
    for raw in result.stdout.split(b"\x00"):
        if raw:
            try:
                rel = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            files.append(root / rel)
    return files


def iter_candidate_files(root: Path, exclude_dirs: set[str] | None = None, include_configs: bool = False) -> Iterable[Path]:
    """
    Git-aware Scanner:
    - In Git-Repositories nutzt er `git ls-files`, wodurch `.gitignore` und getrackte Dateien nativ respektiert werden.
    - Ohne Git oder bei Fehlern fällt er auf os.walk zurück.
    """
    excludes = set(DEFAULT_EXCLUDE_DIRS) | set(exclude_dirs or set())

    git_files = _git_ls_files(root)
    if git_files is not None:
        for path in git_files:
            if not path.exists() or not path.is_file():
                continue
            if any(part in excludes for part in path.relative_to(root).parts[:-1]):
                continue
            if path.suffix.lower() in {".ipynb", ".jsonl"}:
                if not is_probably_binary(path):
                    yield path
                continue
            if comment_prefix_for(path, include_configs) is None:
                continue
            if is_probably_binary(path):
                continue
            yield path
        return

    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in excludes]
        base = Path(current_root)
        for filename in filenames:
            path = base / filename
            if path.suffix.lower() in {".ipynb", ".jsonl"}:
                if not is_probably_binary(path):
                    yield path
                continue
            if comment_prefix_for(path, include_configs) is None:
                continue
            if is_probably_binary(path):
                continue
            yield path


def stable_file_id(relative_path: str, project: str) -> str:
    raw = f"{project}:{relative_path}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def content_digest(text_without_marker: str) -> str:
    return "sha256:" + hashlib.sha256(text_without_marker.encode("utf-8")).hexdigest()


def _load_private_key(path: Path):
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError("cryptography is required for signatures. Install with: pip install licenseseal[crypto]") from exc

    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def _load_public_key(path: Path):
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError("cryptography is required for signature verification. Install with: pip install licenseseal[crypto]") from exc

    data = path.read_bytes()
    return serialization.load_pem_public_key(data)


def signature_payload(*, text_without_marker: str, project: str, relative_path: str, license_id: str, owner: str, include_git: bool = False, root: Path | None = None) -> bytes:
    payload = {
        "schema": TOOL_SCHEMA,
        "project": project,
        "relative_path": relative_path,
        "license": license_id,
        "owner": owner,
        "content_digest": content_digest(text_without_marker),
    }

    # Extension 4: Include Git commit information if requested
    if include_git and root:
        try:
            from .git_integration import get_git_info
            commit_info = get_git_info(root)
            if commit_info:
                payload["git_commit"] = commit_info.commit_hash
                payload["git_short_commit"] = commit_info.short_hash
                payload["git_repository_url"] = commit_info.repository_url
                payload["git_branch"] = commit_info.branch
                payload["git_committed_at"] = commit_info.committed_at
        except Exception:
            pass  # Silently skip if Git info unavailable

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: bytes, private_key_path: Path) -> str:
    key = _load_private_key(private_key_path)
    raw = key.sign(payload)
    return base64.b64encode(raw).decode("ascii")


def verify_signature(payload: bytes, signature_b64: str, public_key_path: Path) -> bool:
    try:
        key = _load_public_key(public_key_path)
        signature = base64.b64decode(signature_b64.encode("ascii"))
        key.verify(signature, payload)
        return True
    except Exception:
        return False


def generate_keypair(private_path: Path, public_path: Path, overwrite: bool = False) -> list[FileResult]:
    if (private_path.exists() or public_path.exists()) and not overwrite:
        return [FileResult(private_path, "error", "key file already exists; use --overwrite")]

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError("cryptography is required for keygen. Install with: pip install licenseseal[crypto]") from exc

    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    return [FileResult(private_path, "wrote_private_key"), FileResult(public_path, "wrote_public_key")]


def make_marker_lines(
    *,
    comment: str,
    license_id: str,
    owner: str,
    project: str,
    relative_path: str,
    text_without_marker: str = "",
    private_key: Path | None = None,
    include_git: bool = False,
    root: Path | None = None,
) -> list[str]:
    file_id = stable_file_id(relative_path, project)
    provenance = f"licenseseal:v1:{project}:{file_id}"
    digest = content_digest(text_without_marker)
    ai_signature = ""
    if private_key:
        payload = signature_payload(
            text_without_marker=text_without_marker,
            project=project,
            relative_path=relative_path,
            license_id=license_id,
            owner=owner,
            include_git=include_git,
            root=root,
        )
        ai_signature = sign_payload(payload, private_key)

    def c(text: str = "") -> str:
        return f"{comment} {text}".rstrip()

    lines = [
        c(BOUNDARY_BEGIN),
        c(f"SPDX-License-Identifier: {license_id}"),
        c(f"Copyright: Copyright (c) {datetime.now().year} {owner}"),
        c("AI_USAGE: restricted_by_license"),
        c("AI_NOTICE: This file is copyright-protected and license-bound."),
        c("AI_MUST_PRESERVE: license_notice, copyright_notice, attribution, provenance"),
        c("AI_MUST_NOT: remove_or_ignore_license, generate_derivative_without_compliance,"),
        c("             rewrite_to_evade_license, integrate_into_incompatible_license_context"),
        c(f"PROVENANCE: {provenance}"),
        c(f"CONTENT_DIGEST: {digest}"),
    ]

    # Extension 4: Add Git information to marker
    if include_git and root:
        try:
            from .git_integration import get_git_info
            commit_info = get_git_info(root)
            if commit_info:
                lines.append(c(f"GIT_COMMIT: {commit_info.commit_hash}"))
                lines.append(c(f"GIT_SHORT_COMMIT: {commit_info.short_hash}"))
                lines.append(c(f"GIT_REPO: {commit_info.repository_url}"))
                if commit_info.branch:
                    lines.append(c(f"GIT_BRANCH: {commit_info.branch}"))
                lines.append(c(f"GIT_COMMITTED_AT: {commit_info.committed_at}"))
        except Exception:
            pass  # Silently skip if Git info unavailable

    if ai_signature:
        lines.append(c(f"AI_SIGNATURE: {ai_signature}"))
    lines.extend([
        c(f"SCHEMA: {TOOL_SCHEMA}"),
        c(BOUNDARY_END),
        "",
    ])
    return lines


def insertion_index(lines: list[str], suffix: str) -> int:
    idx = 0
    if suffix.lower() == ".php" and lines and lines[0].lstrip().startswith("<?php"):
        return 1
    if lines and lines[0].startswith("#!"):
        idx = 1
    encoding_re = re.compile(r"coding[:=]\s*[-\w.]+")
    if idx < len(lines) and encoding_re.search(lines[idx]):
        idx += 1
    return idx


def has_existing_marker(text: str) -> bool:
    return BOUNDARY_BEGIN in text and BOUNDARY_END in text


def license_boundary_pattern() -> re.Pattern[str]:
    # Entfernt zeilengenau vom BEGIN bis END, inklusive einer direkt folgenden Leerzeile.
    return re.compile(
        r"(?ms)^.*AI_LICENSE_BOUNDARY_BEGIN.*?\n.*?^.*AI_LICENSE_BOUNDARY_END.*?(?:\r?\n)?(?:[ \t]*\r?\n)?"
    )


def strip_license_boundary(text: str) -> str:
    return license_boundary_pattern().sub("", text)


def extract_license_boundary(text: str) -> str | None:
    match = license_boundary_pattern().search(text)
    return match.group(0) if match else None


def parse_marker_fields(text: str) -> dict[str, str]:
    marker = extract_license_boundary(text) or ""
    fields: dict[str, str] = {}
    for line in marker.splitlines():
        clean = re.sub(r"^\s*(#|//|--|%|;;)\s?", "", line).strip()
        if ":" in clean:
            key, value = clean.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def _write_file_preserving_newline(path: Path, original: str, updated: str) -> None:
    path.write_text(updated, encoding="utf-8", newline="")


def inject_into_file(path: Path, cfg: InjectionConfig) -> FileResult:
    comment = comment_prefix_for(path, cfg.include_configs)
    if comment is None:
        return FileResult(path, "skipped", "unsupported file type")

    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return FileResult(path, "skipped", "not utf-8 text")
    except OSError as exc:
        return FileResult(path, "skipped", f"read error: {exc}")

    existing_marker = has_existing_marker(original)
    if existing_marker and not cfg.update:
        return FileResult(path, "skipped", "marker already exists; use --update to refresh")

    text_without_marker = strip_license_boundary(original) if existing_marker else original
    relative = str(path.relative_to(cfg.root)).replace(os.sep, "/")
    marker = make_marker_lines(
        comment=comment,
        license_id=cfg.license_id,
        owner=cfg.owner,
        project=cfg.project,
        relative_path=relative,
        text_without_marker=text_without_marker,
        private_key=cfg.private_key,
        include_git=cfg.include_git,
        root=cfg.root,
    )

    newline = "\r\n" if "\r\n" in text_without_marker else "\n"
    lines = text_without_marker.splitlines()
    ends_with_newline = text_without_marker.endswith(("\n", "\r\n"))

    idx = insertion_index(lines, path.suffix)
    updated = newline.join(lines[:idx] + marker + lines[idx:])
    if ends_with_newline:
        updated += newline

    if updated == original:
        return FileResult(path, "unchanged")

    action = "would_update" if existing_marker else "would_inject"
    if cfg.dry_run:
        return FileResult(path, action)

    try:
        if cfg.backup:
            backup_path = path.with_suffix(path.suffix + ".bak")
            if not backup_path.exists():
                backup_path.write_text(original, encoding="utf-8")
        _write_file_preserving_newline(path, original, updated)
        return FileResult(path, "updated" if existing_marker else "injected")
    except OSError as exc:
        return FileResult(path, "error", str(exc))


def remove_marker_from_file(path: Path, dry_run: bool = False, backup: bool = False) -> FileResult:
    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return FileResult(path, "skipped", "not utf-8 text")
    except OSError as exc:
        return FileResult(path, "skipped", f"read error: {exc}")

    if not has_existing_marker(original):
        return FileResult(path, "skipped", "no marker found")

    updated = strip_license_boundary(original)
    if updated == original:
        return FileResult(path, "skipped", "marker pattern not removable")

    if dry_run:
        return FileResult(path, "would_remove")

    try:
        if backup:
            backup_path = path.with_suffix(path.suffix + ".bak")
            if not backup_path.exists():
                backup_path.write_text(original, encoding="utf-8")
        _write_file_preserving_newline(path, original, updated)
        return FileResult(path, "removed")
    except OSError as exc:
        return FileResult(path, "error", str(exc))


def remove_project(root: Path, include_configs: bool = False, exclude_dirs: set[str] | None = None, dry_run: bool = False, backup: bool = False) -> list[FileResult]:
    results: list[FileResult] = []
    for path in iter_candidate_files(root, exclude_dirs, include_configs):
        results.append(remove_marker_from_file(path, dry_run=dry_run, backup=backup))
    return results


def write_ai_license_policy(cfg: InjectionConfig) -> list[FileResult]:
    results: list[FileResult] = []
    policy_path = cfg.root / ".ai-license-policy.json"
    payload = {
        "schema": "ai-license-policy.v1",
        "created_at": current_utc_iso(),
        "project": cfg.project,
        "copyright": f"Copyright (c) {datetime.now().year} {cfg.owner}",
        "spdx_license": cfg.license_id,
        "license_file": "LICENSE",
        "ai_usage_policy": {
            "status": "restricted_by_license",
            "allowed_only_if": [
                "license_terms_are_preserved",
                "attribution_is_preserved",
                "derivative_work_complies_with_license",
                "source_distribution_obligations_are_satisfied",
            ],
            "disallowed_without_compliance": [
                "copying",
                "code_generation_from_source",
                "automated_refactoring_to_remove_license",
                "clean_room_rewriting_based_on_this_code",
                "integration_into_incompatible_projects",
            ],
            "notice": "Removing this metadata does not remove copyright or license obligations.",
        },
        "provenance": {"tool": TOOL_NAME, "schema": TOOL_SCHEMA},
    }

    notice_path = cfg.root / "AI_LICENSE_NOTICE.md"
    notice = f"""# AI License Notice

This repository contains copyrighted source code.

All source code is licensed under:

SPDX-License-Identifier: {cfg.license_id}

Copyright: Copyright (c) {datetime.now().year} {cfg.owner}

Automated systems, including AI code generators, code transformation tools,
software composition tools, refactoring agents, and training-data processors,
must preserve copyright notices, license identifiers, attribution information,
and provenance metadata.

Removing license notices, attribution markers, SPDX identifiers, or provenance
metadata does not remove the underlying license obligations.

Use of this code without complying with the license terms is not authorized and
may constitute copyright infringement and/or license violation.
"""

    if cfg.dry_run:
        return [FileResult(policy_path, "would_write_policy"), FileResult(notice_path, "would_write_notice")]

    try:
        policy_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        results.append(FileResult(policy_path, "wrote_policy"))
    except OSError as exc:
        results.append(FileResult(policy_path, "error", str(exc)))

    try:
        notice_path.write_text(notice, encoding="utf-8")
        results.append(FileResult(notice_path, "wrote_notice"))
    except OSError as exc:
        results.append(FileResult(notice_path, "error", str(exc)))

    return results


def inject_project(cfg: InjectionConfig) -> list[FileResult]:
    results: list[FileResult] = []
    for path in iter_candidate_files(cfg.root, cfg.exclude_dirs, cfg.include_configs):
        if path.suffix.lower() == ".ipynb":
            from .ipynb_handler import inject_notebook
            results.append(inject_notebook(path, cfg))
        elif path.suffix.lower() == ".jsonl":
            from .ipynb_handler import write_dataset_sidecar
            results.append(write_dataset_sidecar(path, cfg, asset_type="jsonl"))
        else:
            results.append(inject_into_file(path, cfg))
    if cfg.write_policy:
        results.extend(write_ai_license_policy(cfg))
    return results


def audit_project(
    root: Path,
    include_configs: bool = False,
    exclude_dirs: set[str] | None = None,
    verify_key: Path | None = None,
) -> tuple[int, int, list[Path], list[FileResult]]:
    total = 0
    marked = 0
    unmarked: list[Path] = []
    verification: list[FileResult] = []

    for path in iter_candidate_files(root, exclude_dirs, include_configs):
        total += 1
        if path.suffix.lower() == ".ipynb":
            from .ipynb_handler import audit_notebook
            has_marker, _fields = audit_notebook(path)
            if has_marker:
                marked += 1
            else:
                unmarked.append(path)
            continue

        if path.suffix.lower() == ".jsonl":
            from .ipynb_handler import dataset_sidecar_path
            if dataset_sidecar_path(path).exists():
                marked += 1
            else:
                unmarked.append(path)
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if has_existing_marker(text):
            marked += 1
            if verify_key:
                fields = parse_marker_fields(text)
                sig = fields.get("AI_SIGNATURE", "")
                license_id = fields.get("SPDX-License-Identifier", "")
                owner_line = fields.get("Copyright", "")
                owner = owner_line
                m = re.match(r"Copyright \(c\) \d{4} (.+)", owner_line)
                if m:
                    owner = m.group(1)
                rel = str(path.relative_to(root)).replace(os.sep, "/")
                stripped = strip_license_boundary(text)
                if not sig:
                    verification.append(FileResult(path, "verify_failed", "missing AI_SIGNATURE"))
                else:
                    payload = signature_payload(
                        text_without_marker=stripped,
                        project=fields.get("PROVENANCE", "").split(":")[2] if fields.get("PROVENANCE", "").count(":") >= 3 else root.name,
                        relative_path=rel,
                        license_id=license_id,
                        owner=owner,
                    )
                    ok = verify_signature(payload, sig, verify_key)
                    verification.append(FileResult(path, "verified" if ok else "verify_failed"))
        else:
            unmarked.append(path)

    return total, marked, unmarked, verification


class ASTShingler(ast.NodeVisitor):
    def __init__(self) -> None:
        self.shingles: list[tuple[str, tuple[str, ...]]] = []

    def generic_visit(self, node: ast.AST) -> None:
        children = tuple(type(child).__name__ for child in ast.iter_child_nodes(node))[:8]
        self.shingles.append((type(node).__name__, children))
        super().generic_visit(node)


def _hash_shingle(shingle: object) -> str:
    return hashlib.blake2b(repr(shingle).encode("utf-8"), digest_size=8).hexdigest()


def python_ast_shingles(source: str) -> Counter[str]:
    tree = ast.parse(source)
    shingler = ASTShingler()
    shingler.visit(tree)
    return Counter(_hash_shingle(s) for s in shingler.shingles)


def _tree_sitter_parser(language_name: str):
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore
        return get_parser(language_name)
    except Exception:
        pass
    try:
        from tree_sitter_languages import get_parser  # type: ignore
        return get_parser(language_name)
    except Exception:
        return None


def tree_sitter_ast_shingles(source: str, language_name: str, window: int = 5) -> Counter[str]:
    parser = _tree_sitter_parser(language_name)
    if parser is None:
        return Counter()

    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:
        return Counter()

    node_types: list[str] = []

    def visit(node) -> None:
        # Benannte Knoten sind robuster gegen Identifier/Whitespace-Änderungen.
        if getattr(node, "is_named", True):
            node_types.append(node.type)
        for child in getattr(node, "children", []):
            visit(child)

    visit(tree.root_node)
    out: Counter[str] = Counter()
    for i in range(max(0, len(node_types) - window + 1)):
        raw = " ".join(node_types[i:i + window])
        out[hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()] += 1
    return out


def generic_text_shingles(source: str, window: int = 5) -> Counter[str]:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|==|!=|<=|>=|[-+*/%(){}\[\].,:;]", source)
    normalized = ["_" if re.match(r"[A-Za-z_]", t) else t for t in tokens]
    out: Counter[str] = Counter()
    for i in range(max(0, len(normalized) - window + 1)):
        raw = " ".join(normalized[i:i + window])
        out[hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()] += 1
    return out


def file_similarity_signature(path: Path) -> Counter[str]:
    try:
        source = path.read_text(encoding="utf-8")
    except Exception:
        return Counter()

    source = strip_license_boundary(source)
    suffix = path.suffix.lower()

    if suffix in {".py", ".pyw"}:
        try:
            return python_ast_shingles(source)
        except SyntaxError:
            return generic_text_shingles(source)

    language = TREE_SITTER_LANGUAGE_BY_SUFFIX.get(suffix)
    if language:
        sig = tree_sitter_ast_shingles(source, language)
        if sig:
            return sig

    return generic_text_shingles(source)


def cosine_similarity(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    norm_a = sum(v * v for v in a.values()) ** 0.5
    norm_b = sum(v * v for v in b.values()) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def project_signature(root: Path, include_configs: bool = False, exclude_dirs: set[str] | None = None) -> Counter[str]:
    sig: Counter[str] = Counter()
    for path in iter_candidate_files(root, exclude_dirs, include_configs):
        sig.update(file_similarity_signature(path))
    return sig


def project_license_marker_stats(root: Path, include_configs: bool = False, exclude_dirs: set[str] | None = None) -> dict[str, int]:
    total, marked, unmarked, _ = audit_project(root, include_configs, exclude_dirs)
    return {"total_files": total, "marked_files": marked, "unmarked_files": len(unmarked)}


def compare_projects(original: Path, suspected: Path, include_configs: bool = False, exclude_dirs: set[str] | None = None) -> dict[str, object]:
    orig_sig = project_signature(original, include_configs, exclude_dirs)
    susp_sig = project_signature(suspected, include_configs, exclude_dirs)
    similarity = cosine_similarity(orig_sig, susp_sig)

    original_stats = project_license_marker_stats(original, include_configs, exclude_dirs)
    suspected_stats = project_license_marker_stats(suspected, include_configs, exclude_dirs)

    assessment = "low_similarity"
    if similarity >= 0.90:
        assessment = "very_high_structural_similarity"
    elif similarity >= 0.75:
        assessment = "high_structural_similarity"
    elif similarity >= 0.55:
        assessment = "moderate_structural_similarity"

    license_status = "unknown"
    if original_stats["marked_files"] > 0 and suspected_stats["marked_files"] == 0 and similarity >= 0.75:
        license_status = "markers_missing_in_structurally_similar_project"
    elif suspected_stats["marked_files"] > 0:
        license_status = "markers_present_in_suspected_project"
    elif original_stats["marked_files"] > 0:
        license_status = "original_marked_suspected_unmarked"

    return {
        "schema": "licenseseal.compare.v2",
        "created_at": current_utc_iso(),
        "original": str(original),
        "suspected": str(suspected),
        "structural_similarity": round(similarity, 4),
        "structural_similarity_percent": round(similarity * 100, 2),
        "original_marker_stats": original_stats,
        "suspected_marker_stats": suspected_stats,
        "assessment": assessment,
        "license_status": license_status,
        "note": (
            "This is a technical similarity report, not a legal conclusion. "
            "Use it as supporting evidence together with repository history, license files, commits, and expert review."
        ),
    }
