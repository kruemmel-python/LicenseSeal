"""
LicenseSeal Jupyter Notebook and Dataset Handler
================================================
Native support for .ipynb provenance markers without corrupting notebook JSON.

Design:
- Adds an idempotent first Markdown cell carrying the LicenseSeal boundary.
- Stores machine-readable metadata under metadata.licenseseal.
- Computes CONTENT_DIGEST from code cells only, ignoring outputs, execution counts
  and other volatile notebook state.
- JSONL/dataset assets are handled by sidecar manifests to avoid changing
  training samples in-place.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .core import (
    BOUNDARY_BEGIN,
    BOUNDARY_END,
    FileResult,
    InjectionConfig,
    content_digest,
    current_utc_iso,
    has_existing_marker,
    make_marker_lines,
    parse_marker_fields,
    stable_file_id,
)


NOTEBOOK_METADATA_KEY = "licenseseal"
DATASET_SIDECAR_SUFFIX = ".licenseseal.json"


def _cell_source_to_text(source: str | list[str]) -> str:
    if isinstance(source, list):
        return "".join(source)
    return source or ""


def notebook_code_text(data: dict[str, Any]) -> str:
    """Return a stable code-only text representation for notebook signatures."""
    chunks: list[str] = []
    for cell in data.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        chunks.append(_cell_source_to_text(cell.get("source", "")))
    return "\n\n".join(chunks)


def notebook_digest(data: dict[str, Any]) -> str:
    """Digest only code cells; ignore outputs and execution counts."""
    return content_digest(notebook_code_text(data))


def is_licenseseal_cell(cell: dict[str, Any]) -> bool:
    metadata = cell.get("metadata", {}) or {}
    if metadata.get("licenseseal_marker") is True:
        return True
    source = _cell_source_to_text(cell.get("source", ""))
    return BOUNDARY_BEGIN in source and BOUNDARY_END in source


def strip_notebook_marker(data: dict[str, Any]) -> dict[str, Any]:
    """Remove existing LicenseSeal marker cells and notebook metadata."""
    copied = json.loads(json.dumps(data))
    copied["cells"] = [cell for cell in copied.get("cells", []) if not is_licenseseal_cell(cell)]
    metadata = copied.setdefault("metadata", {})
    metadata.pop(NOTEBOOK_METADATA_KEY, None)
    return copied


def make_notebook_marker_cell(
    *,
    path: Path,
    cfg: InjectionConfig,
    data_without_marker: dict[str, Any],
) -> dict[str, Any]:
    code_text = notebook_code_text(data_without_marker)
    relative = str(path.relative_to(cfg.root)).replace(os.sep, "/")
    marker_lines = make_marker_lines(
        comment="",
        license_id=cfg.license_id,
        owner=cfg.owner,
        project=cfg.project,
        relative_path=relative,
        text_without_marker=code_text,
        private_key=cfg.private_key,
        include_git=cfg.include_git,
        root=cfg.root,
    )
    source = ["<!-- LicenseSeal notebook provenance marker. Do not remove. -->\n"]
    source.extend(line.strip() + "\n" for line in marker_lines)
    return {
        "cell_type": "markdown",
        "metadata": {
            "licenseseal_marker": True,
            "licenseseal_schema": "notebook-boundary.v1",
            "created_at": current_utc_iso(),
        },
        "source": source,
    }


def inject_notebook(path: Path, cfg: InjectionConfig) -> FileResult:
    """Inject or update a notebook marker cell and metadata."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return FileResult(path, "skipped", f"invalid notebook json: {exc}")
    except OSError as exc:
        return FileResult(path, "skipped", f"read error: {exc}")

    if not isinstance(data, dict) or "cells" not in data:
        return FileResult(path, "skipped", "not a notebook document")

    existing = any(is_licenseseal_cell(cell) for cell in data.get("cells", [])) or NOTEBOOK_METADATA_KEY in data.get("metadata", {})
    if existing and not cfg.update:
        return FileResult(path, "skipped", "notebook marker already exists; use --update to refresh")

    data_without_marker = strip_notebook_marker(data) if existing else json.loads(json.dumps(data))
    relative = str(path.relative_to(cfg.root)).replace(os.sep, "/")
    file_id = stable_file_id(relative, cfg.project)
    digest = notebook_digest(data_without_marker)

    marker_cell = make_notebook_marker_cell(path=path, cfg=cfg, data_without_marker=data_without_marker)
    updated = json.loads(json.dumps(data_without_marker))
    updated.setdefault("cells", []).insert(0, marker_cell)
    updated.setdefault("metadata", {})[NOTEBOOK_METADATA_KEY] = {
        "schema": "notebook-boundary.v1",
        "tool": "licenseseal",
        "project": cfg.project,
        "relative_path": relative,
        "file_id": file_id,
        "spdx_license": cfg.license_id,
        "owner": cfg.owner,
        "content_digest_scope": "code_cells_only",
        "content_digest": digest,
        "created_at": current_utc_iso(),
    }

    if updated == data:
        return FileResult(path, "unchanged")

    action = "would_update" if existing else "would_inject"
    if cfg.dry_run:
        return FileResult(path, action)

    try:
        if cfg.backup:
            backup_path = path.with_suffix(path.suffix + ".bak")
            if not backup_path.exists():
                backup_path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        path.write_text(json.dumps(updated, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return FileResult(path, "updated" if existing else "injected")
    except OSError as exc:
        return FileResult(path, "error", str(exc))


def audit_notebook(path: Path) -> tuple[bool, dict[str, str]]:
    """Return (has_marker, fields) for a notebook."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False, {}

    metadata = data.get("metadata", {}).get(NOTEBOOK_METADATA_KEY, {})
    marker_text = ""
    for cell in data.get("cells", []):
        if is_licenseseal_cell(cell):
            marker_text += _cell_source_to_text(cell.get("source", "")) + "\n"

    has_marker = bool(metadata) or (BOUNDARY_BEGIN in marker_text and BOUNDARY_END in marker_text)
    fields = parse_marker_fields(marker_text)
    if metadata:
        fields.setdefault("SPDX-License-Identifier", str(metadata.get("spdx_license", "")))
        fields.setdefault("Copyright", f"Copyright (c) {datetime.now().year} {metadata.get('owner', '')}".strip())
        fields.setdefault("CONTENT_DIGEST", str(metadata.get("content_digest", "")))
        fields.setdefault("PROVENANCE", f"licenseseal:notebook:{metadata.get('project', '')}:{metadata.get('file_id', '')}")
    return has_marker, fields


def dataset_sidecar_path(path: Path) -> Path:
    return path.with_name(path.name + DATASET_SIDECAR_SUFFIX)


def dataset_digest(path: Path, max_bytes: int | None = None) -> str:
    h = hashlib.sha256()
    read = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            if max_bytes is not None and read + len(chunk) > max_bytes:
                chunk = chunk[: max_bytes - read]
            h.update(chunk)
            read += len(chunk)
            if max_bytes is not None and read >= max_bytes:
                break
    return h.hexdigest()


def write_dataset_sidecar(path: Path, cfg: InjectionConfig, asset_type: str = "jsonl") -> FileResult:
    """Create a provenance sidecar for dataset assets without mutating samples."""
    sidecar = dataset_sidecar_path(path)
    relative = str(path.relative_to(cfg.root)).replace(os.sep, "/")
    payload = {
        "schema": "licenseseal.dataset-sidecar.v1",
        "tool": "licenseseal",
        "asset_type": asset_type,
        "created_at": current_utc_iso(),
        "project": cfg.project,
        "relative_path": relative,
        "spdx_license": cfg.license_id,
        "owner": cfg.owner,
        "content_digest_sha256": dataset_digest(path),
        "policy": {
            "ai_usage": "restricted_by_license",
            "must_preserve": ["license_notice", "copyright_notice", "attribution", "provenance"],
        },
    }
    if cfg.dry_run:
        return FileResult(sidecar, "would_write_dataset_sidecar")
    try:
        sidecar.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return FileResult(sidecar, "wrote_dataset_sidecar")
    except OSError as exc:
        return FileResult(sidecar, "error", str(exc))
