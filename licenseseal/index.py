"""
LicenseSeal Index Module
========================
Provides persistent signature storage using SQLite for O(1) lookups.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .core import (
    BOUNDARY_BEGIN,
    BOUNDARY_END,
    current_utc_iso,
    file_similarity_signature,
    iter_candidate_files,
    parse_marker_fields,
    project_signature,
    strip_license_boundary,
)


@dataclass
class IndexConfig:
    db_path: Path
    project_name: str
    root: Path
    include_configs: bool = False
    exclude_dirs: set[str] | None = None


def _init_db(conn: sqlite3.Connection) -> None:
    """Initialize database schema."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            root_path TEXT NOT NULL,
            indexed_at TEXT NOT NULL,
            file_count INTEGER DEFAULT 0,
            shingle_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS file_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            UNIQUE(project_id, file_path)
        );

        CREATE TABLE IF NOT EXISTS shingles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_signature_id INTEGER NOT NULL,
            shingle_hash TEXT NOT NULL,
            frequency INTEGER DEFAULT 1,
            FOREIGN KEY (file_signature_id) REFERENCES file_signatures(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_shingles_hash ON shingles(shingle_hash);
        CREATE INDEX IF NOT EXISTS idx_shingles_file ON shingles(file_signature_id);
        CREATE INDEX IF NOT EXISTS idx_file_path ON file_signatures(file_path);
    """)


def _get_connection(db_path: Path) -> sqlite3.Connection:
    """Get or create database connection."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    return conn


def index_project(cfg: IndexConfig) -> dict:
    """
    Index a project's file signatures for fast similarity lookups.
    """
    conn = _get_connection(cfg.db_path)
    cursor = conn.cursor()

    now = current_utc_iso()
    project_sig = project_signature(
        cfg.root,
        cfg.include_configs,
        cfg.exclude_dirs,
    )

    # Insert or update project
    cursor.execute("""
        INSERT INTO projects (name, root_path, indexed_at, file_count, shingle_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            root_path = excluded.root_path,
            indexed_at = excluded.indexed_at,
            file_count = excluded.file_count,
            shingle_count = excluded.shingle_count
    """, (cfg.project_name, str(cfg.root), now, 0, len(project_sig)))

    project_id = cursor.execute(
        "SELECT id FROM projects WHERE name = ?", (cfg.project_name,)
    ).fetchone()["id"]

    # Clear existing signatures for this project
    cursor.execute("DELETE FROM shingles WHERE file_signature_id IN (SELECT id FROM file_signatures WHERE project_id = ?)", (project_id,))
    cursor.execute("DELETE FROM file_signatures WHERE project_id = ?", (project_id,))

    file_count = 0
    total_shingles = 0

    for path in iter_candidate_files(cfg.root, cfg.exclude_dirs, cfg.include_configs):
        file_count += 1
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue

        # Get content hash
        content = strip_license_boundary(text)
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:24]
        rel_path = str(path.relative_to(cfg.root)).replace(os.sep, "/")

        # Insert file signature
        cursor.execute("""
            INSERT INTO file_signatures (project_id, file_path, content_hash, created_at)
            VALUES (?, ?, ?, ?)
        """, (project_id, rel_path, content_hash, now))

        file_sig_id = cursor.lastrowid

        # Get shingles for this file
        file_sig = file_similarity_signature(path)
        for shingle_hash, freq in file_sig.items():
            cursor.execute("""
                INSERT INTO shingles (file_signature_id, shingle_hash, frequency)
                VALUES (?, ?, ?)
            """, (file_sig_id, shingle_hash, freq))
            total_shingles += 1

    # Update project stats
    cursor.execute("""
        UPDATE projects SET file_count = ?, shingle_count = ?
        WHERE id = ?
    """, (file_count, total_shingles, project_id))

    conn.commit()
    conn.close()

    return {
        "project": cfg.project_name,
        "root": str(cfg.root),
        "indexed_at": now,
        "file_count": file_count,
        "shingle_count": total_shingles,
    }


def compare_indexed(
    suspected_root: Path,
    db_path: Path,
    project_name: str,
    include_configs: bool = False,
    exclude_dirs: set[str] | None = None,
) -> dict:
    """
    Compare a suspected project against an indexed original.
    Uses SQL JOINs for efficient cosine similarity calculation.
    """
    conn = _get_connection(db_path)
    cursor = conn.cursor()

    # Get project ID
    project_row = cursor.execute(
        "SELECT id, file_count, shingle_count FROM projects WHERE name = ?",
        (project_name,)
    ).fetchone()

    if not project_row:
        conn.close()
        raise ValueError(f"Project '{project_name}' not found in index")

    project_id = project_row["id"]

    # Get shingles from indexed project
    cursor.execute("""
        SELECT shingle_hash, SUM(frequency) as freq
        FROM shingles
        WHERE file_signature_id IN (SELECT id FROM file_signatures WHERE project_id = ?)
        GROUP BY shingle_hash
    """, (project_id,))

    original_shingles: dict[str, int] = {row["shingle_hash"]: row["freq"] for row in cursor.fetchall()}

    # Calculate suspected project signature
    suspected_sig = project_signature(suspected_root, include_configs, exclude_dirs)

    # Calculate cosine similarity using SQL-like approach
    similarity = _cosine_from_dicts(original_shingles, suspected_sig)

    conn.close()

    return {
        "indexed_project": project_name,
        "suspected_project": str(suspected_root),
        "structural_similarity": round(similarity, 4),
        "structural_similarity_percent": round(similarity * 100, 2),
    }


def _cosine_from_dicts(a: dict[str, int], b: Counter[str]) -> float:
    """Calculate cosine similarity between two signature dictionaries."""
    if not a or not b:
        return 0.0

    common = set(a.keys()) & set(b.keys())
    dot = sum(a[k] * b[k] for k in common)

    norm_a = sum(v * v for v in a.values()) ** 0.5
    norm_b = sum(v * v for v in b.values()) ** 0.5

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


def list_indexed_projects(db_path: Path) -> list[dict]:
    """List all projects in the index."""
    conn = _get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT name, root_path, indexed_at, file_count, shingle_count
        FROM projects
        ORDER BY indexed_at DESC
    """)

    projects = []
    for row in cursor.fetchall():
        projects.append({
            "name": row["name"],
            "root_path": row["root_path"],
            "indexed_at": row["indexed_at"],
            "file_count": row["file_count"],
            "shingle_count": row["shingle_count"],
        })

    conn.close()
    return projects


def remove_from_index(db_path: Path, project_name: str) -> bool:
    """Remove a project from the index."""
    conn = _get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM projects WHERE name = ?", (project_name,))
    deleted = cursor.rowcount > 0

    conn.commit()
    conn.close()

    return deleted


def get_project_stats(db_path: Path, project_name: str) -> Optional[dict]:
    """Get statistics for an indexed project."""
    conn = _get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT name, root_path, indexed_at, file_count, shingle_count
        FROM projects WHERE name = ?
    """, (project_name,))

    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "name": row["name"],
            "root_path": row["root_path"],
            "indexed_at": row["indexed_at"],
            "file_count": row["file_count"],
            "shingle_count": row["shingle_count"],
        }
    return None


# Import hashlib at module level
import hashlib