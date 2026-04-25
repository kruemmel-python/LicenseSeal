"""
LicenseSeal Enterprise Registry Module
======================================
Centralized compliance database with FastAPI backend and PostgreSQL storage.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .core import current_utc_iso, project_signature


class RegistryMode(Enum):
    """Registry operation modes."""
    LOCAL = "local"
    REMOTE = "remote"


class ProjectStatus(Enum):
    """Project compliance status."""
    COMPLIANT = "compliant"
    PENDING = "pending"
    VIOLATION = "violation"
    UNKNOWN = "unknown"


@dataclass
class RegistryConfig:
    """Configuration for the enterprise registry."""
    mode: RegistryMode = RegistryMode.LOCAL
    database_url: str = "postgresql://localhost:5432/licenseseal"
    api_key: str = ""
    remote_url: str = ""
    pgvector_enabled: bool = True


@dataclass
class RegistryProject:
    """Project entry in the registry."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    owner: str = ""
    license_id: str = ""
    root_path: str = ""
    repository_url: str = ""
    signature: str = ""
    shingle_hash: str = ""
    embedding: list[float] = field(default_factory=list)
    status: ProjectStatus = ProjectStatus.UNKNOWN
    indexed_at: str = ""
    last_scanned_at: str = ""
    metadata: dict = field(default_factory=dict)


class EnterpriseRegistry:
    """
    Enterprise-grade signature registry with PostgreSQL backend.
    Supports both local and remote operation modes.
    """

    def __init__(self, config: RegistryConfig):
        self.config = config
        self._conn = None

    def _get_connection(self):
        """Get database connection."""
        if self._conn is not None:
            return self._conn

        try:
            import psycopg2
            self._conn = psycopg2.connect(self.config.database_url)
            return self._conn
        except ImportError:
            raise RuntimeError(
                "psycopg2 is required for enterprise registry. "
                'Install with: pip install "licenseseal[enterprise]"'
            )
        except Exception as e:
            raise RuntimeError(f"Failed to connect to database: {e}")

    def initialize_schema(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Projects table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registry_projects (
                id UUID PRIMARY KEY,
                name VARCHAR(512) NOT NULL,
                owner VARCHAR(256),
                license_id VARCHAR(128),
                root_path TEXT,
                repository_url TEXT,
                signature TEXT,
                shingle_hash TEXT,
                status VARCHAR(32) DEFAULT 'unknown',
                indexed_at TIMESTAMP DEFAULT NOW(),
                last_scanned_at TIMESTAMP,
                metadata JSONB DEFAULT '{}'
            )
        """)

        # Embeddings table (for pgvector)
        if self.config.pgvector_enabled:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS project_embeddings (
                    project_id UUID PRIMARY KEY REFERENCES registry_projects(id) ON DELETE CASCADE,
                    embedding vector(384),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """)

            # Create index for cosine similarity search
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_embeddings_cosine 
                ON project_embeddings USING ivfflat (embedding vector_cosine_ops)
            """)

        # Scan results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id UUID PRIMARY KEY,
                original_project_id UUID REFERENCES registry_projects(id),
                suspected_repo_url TEXT,
                similarity_score FLOAT,
                scan_type VARCHAR(32),
                scanned_at TIMESTAMP DEFAULT NOW(),
                details JSONB
            )
        """)

        # Honey-logic fingerprints generated from protected projects.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS honey_fingerprints (
                id UUID PRIMARY KEY,
                project_id UUID REFERENCES registry_projects(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                fingerprint_type VARCHAR(32) DEFAULT 'honey_logic',
                language VARCHAR(32) DEFAULT 'python',
                rarity_score FLOAT DEFAULT 1.0,
                features JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_honey_fingerprints_fingerprint
            ON honey_fingerprints(fingerprint)
        """)


        # CFG/DFG graph fingerprints for deep-refactor resilient matching.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS graph_fingerprints (
                id UUID PRIMARY KEY,
                project_id UUID REFERENCES registry_projects(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                fingerprint_type VARCHAR(32) DEFAULT 'cfg_dfg',
                language VARCHAR(32) DEFAULT 'mixed',
                weight FLOAT DEFAULT 1.0,
                features JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_graph_fingerprints_fingerprint
            ON graph_fingerprints(fingerprint)
        """)

        # Control-plane users, roles and webhook endpoints.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS control_plane_users (
                id UUID PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                role VARCHAR(32) NOT NULL DEFAULT 'viewer',
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS control_plane_webhooks (
                id UUID PRIMARY KEY,
                event_type VARCHAR(128) NOT NULL,
                url TEXT NOT NULL,
                secret_ref TEXT DEFAULT '',
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # Fine-grained evidence chain for firehose/registry alerts.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_items (
                id UUID PRIMARY KEY,
                scan_result_id UUID REFERENCES scan_results(id) ON DELETE CASCADE,
                evidence_type VARCHAR(64) NOT NULL,
                confidence FLOAT NOT NULL,
                source_path TEXT,
                matched_path TEXT,
                details JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)

        conn.commit()

    def register_project(
        self,
        name: str,
        owner: str,
        license_id: str,
        root_path: Path,
        signature: str,
        shingle_hash: str,
        embedding: list[float] | None = None,
        repository_url: str = "",
        metadata: dict | None = None,
    ) -> RegistryProject:
        """Register a new project in the enterprise registry."""
        project = RegistryProject(
            name=name,
            owner=owner,
            license_id=license_id,
            root_path=str(root_path),
            repository_url=repository_url,
            signature=signature,
            shingle_hash=shingle_hash,
            embedding=embedding or [],
            status=ProjectStatus.COMPLIANT,
            indexed_at=current_utc_iso(),
            metadata=metadata or {},
        )

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO registry_projects 
            (id, name, owner, license_id, root_path, repository_url, signature, 
             shingle_hash, status, indexed_at, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                owner = EXCLUDED.owner,
                license_id = EXCLUDED.license_id,
                signature = EXCLUDED.signature,
                shingle_hash = EXCLUDED.shingle_hash,
                indexed_at = EXCLUDED.indexed_at,
                metadata = EXCLUDED.metadata
        """, (
            project.id, project.name, project.owner, project.license_id,
            project.root_path, project.repository_url, project.signature,
            project.shingle_hash, project.status.value, project.indexed_at,
            json.dumps(project.metadata),
        ))

        # Store embedding if available
        if embedding and self.config.pgvector_enabled:
            cursor.execute("""
                INSERT INTO project_embeddings (project_id, embedding)
                VALUES (%s, %s)
                ON CONFLICT (project_id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    updated_at = NOW()
            """, (project.id, embedding))

        conn.commit()
        return project

    def find_similar_projects(
        self,
        embedding: list[float],
        threshold: float = 0.85,
        limit: int = 10,
    ) -> list[dict]:
        """Find similar projects using vector similarity."""
        if not self.config.pgvector_enabled:
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        # Use pgvector cosine similarity
        cursor.execute("""
            SELECT p.id, p.name, p.owner, p.license_id, p.repository_url,
                   1 - (e.embedding <=> %s::vector) as similarity
            FROM registry_projects p
            JOIN project_embeddings e ON p.id = e.project_id
            WHERE p.status = 'compliant'
            ORDER BY similarity DESC
            LIMIT %s
        """, (embedding, limit))

        results = []
        for row in cursor.fetchall():
            results.append({
                "project_id": str(row[0]),
                "name": row[1],
                "owner": row[2],
                "license_id": row[3],
                "repository_url": row[4],
                "similarity": row[5],
            })

        return [r for r in results if r["similarity"] >= threshold]

    def search_by_shingles(
        self,
        shingle_hash: str,
        threshold: float = 0.5,
    ) -> list[dict]:
        """Search projects by shingle hash similarity."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Simple hash-based search (can be enhanced with dedicated shingle table)
        cursor.execute("""
            SELECT id, name, owner, license_id, root_path, signature
            FROM registry_projects
            WHERE status = 'compliant'
            AND similarity(%s, shingle_hash) > %s
            LIMIT 20
        """, (shingle_hash, threshold))

        results = []
        for row in cursor.fetchall():
            results.append({
                "project_id": str(row[0]),
                "name": row[1],
                "owner": row[2],
                "license_id": row[3],
                "root_path": row[4],
                "signature": row[5],
            })

        return results

    def get_project(self, project_id: str) -> Optional[RegistryProject]:
        """Get a project by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, owner, license_id, root_path, repository_url,
                   signature, shingle_hash, status, indexed_at, last_scanned_at, metadata
            FROM registry_projects WHERE id = %s
        """, (project_id,))

        row = cursor.fetchone()
        if not row:
            return None

        return RegistryProject(
            id=str(row[0]),
            name=row[1],
            owner=row[2],
            license_id=row[3],
            root_path=row[4],
            repository_url=row[5],
            signature=row[6],
            shingle_hash=row[7],
            status=ProjectStatus(row[8]),
            indexed_at=row[9].isoformat() if row[9] else "",
            last_scanned_at=row[10].isoformat() if row[10] else "",
            metadata=row[11] or {},
        )

    def list_projects(
        self,
        status: ProjectStatus | None = None,
        limit: int = 100,
    ) -> list[RegistryProject]:
        """List projects in the registry."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT id, name, owner, license_id, root_path, repository_url, signature, shingle_hash, status, indexed_at, last_scanned_at, metadata FROM registry_projects"
        params = []

        if status:
            query += " WHERE status = %s"
            params.append(status.value)

        query += " ORDER BY indexed_at DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)

        projects = []
        for row in cursor.fetchall():
            projects.append(RegistryProject(
                id=str(row[0]),
                name=row[1],
                owner=row[2],
                license_id=row[3],
                root_path=row[4],
                repository_url=row[5],
                signature=row[6],
                shingle_hash=row[7],
                status=ProjectStatus(row[8]),
                indexed_at=row[9].isoformat() if row[9] else "",
                last_scanned_at=row[10].isoformat() if row[10] else "",
                metadata=row[11] or {},
            ))

        return projects


    def register_graph_fingerprint(
        self,
        project_id: str,
        fingerprint: str,
        fingerprint_type: str = "cfg_dfg",
        language: str = "mixed",
        weight: float = 1.0,
        features: dict | None = None,
    ) -> None:
        """Register a CFG/DFG graph fingerprint for a project."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO graph_fingerprints
            (id, project_id, fingerprint, fingerprint_type, language, weight, features)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            str(uuid.uuid4()),
            project_id,
            fingerprint,
            fingerprint_type,
            language,
            float(weight),
            json.dumps(features or {}),
        ))
        conn.commit()

    def find_graph_matches(self, fingerprints: list[str]) -> list[dict]:
        """Find registered CFG/DFG fingerprints."""
        if not fingerprints:
            return []
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT gf.project_id, rp.name, gf.fingerprint, gf.fingerprint_type,
                   gf.language, gf.weight, gf.features
            FROM graph_fingerprints gf
            JOIN registry_projects rp ON rp.id = gf.project_id
            WHERE gf.fingerprint = ANY(%s)
        """, (fingerprints,))
        rows = cursor.fetchall()
        return [
            {
                "project_id": str(r[0]),
                "project_name": r[1],
                "fingerprint": r[2],
                "fingerprint_type": r[3],
                "language": r[4],
                "weight": float(r[5] or 1.0),
                "features": r[6] or {},
            }
            for r in rows
        ]

    def record_scan_result(
        self,
        original_project_id: str,
        suspected_repo_url: str,
        similarity_score: float,
        scan_type: str = "structural",
        details: dict | None = None,
    ) -> str:
        """Record a scan result for audit trail and return its ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        scan_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO scan_results 
            (id, original_project_id, suspected_repo_url, similarity_score, scan_type, details)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            scan_id,
            original_project_id,
            suspected_repo_url,
            similarity_score,
            scan_type,
            json.dumps(details or {}),
        ))

        conn.commit()
        return scan_id

    def register_honey_fingerprint(
        self,
        project_id: str,
        fingerprint: str,
        language: str = "python",
        rarity_score: float = 1.0,
        features: dict | None = None,
        fingerprint_type: str = "honey_logic",
    ) -> str:
        """Register a honey-logic fingerprint for a protected project."""
        conn = self._get_connection()
        cursor = conn.cursor()
        item_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO honey_fingerprints
            (id, project_id, fingerprint, fingerprint_type, language, rarity_score, features)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            item_id,
            project_id,
            fingerprint,
            fingerprint_type,
            language,
            rarity_score,
            json.dumps(features or {}),
        ))

        conn.commit()
        return item_id

    def find_honey_matches(self, fingerprints: list[str]) -> list[dict]:
        """Find registered honey-logic matches for observed fingerprints."""
        if not fingerprints:
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT h.id, h.project_id, h.fingerprint, h.fingerprint_type,
                   h.language, h.rarity_score, h.features,
                   p.name, p.owner, p.repository_url
            FROM honey_fingerprints h
            JOIN registry_projects p ON p.id = h.project_id
            WHERE h.fingerprint = ANY(%s)
        """, (fingerprints,))

        results = []
        for row in cursor.fetchall():
            results.append({
                "id": str(row[0]),
                "project_id": str(row[1]),
                "fingerprint": row[2],
                "fingerprint_type": row[3],
                "language": row[4],
                "rarity_score": float(row[5] or 1.0),
                "features": row[6] or {},
                "project_name": row[7],
                "owner": row[8],
                "repository_url": row[9],
            })
        return results

    def record_evidence_item(
        self,
        scan_result_id: str,
        evidence_type: str,
        confidence: float,
        source_path: str = "",
        matched_path: str = "",
        details: dict | None = None,
    ) -> str:
        """Record one explainable evidence item under a scan result."""
        conn = self._get_connection()
        cursor = conn.cursor()
        evidence_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO evidence_items
            (id, scan_result_id, evidence_type, confidence, source_path, matched_path, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            evidence_id,
            scan_result_id,
            evidence_type,
            confidence,
            source_path,
            matched_path,
            json.dumps(details or {}),
        ))

        conn.commit()
        return evidence_id

    def get_scan_history(
        self,
        project_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Get scan history for a project."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, suspected_repo_url, similarity_score, scan_type, scanned_at, details
            FROM scan_results
            WHERE original_project_id = %s
            ORDER BY scanned_at DESC
            LIMIT %s
        """, (project_id, limit))

        results = []
        for row in cursor.fetchall():
            results.append({
                "scan_id": str(row[0]),
                "suspected_repo_url": row[1],
                "similarity_score": row[2],
                "scan_type": row[3],
                "scanned_at": row[4].isoformat() if row[4] else "",
                "details": row[5],
            })

        return results


# Remote registry client
class RemoteRegistryClient:
    """Client for remote registry operations."""

    def __init__(self, remote_url: str, api_key: str):
        self.remote_url = remote_url.rstrip("/")
        self.api_key = api_key
        self._session = None

    def _get_session(self):
        """Get HTTP session."""
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            })
        return self._session

    def push_signature(self, project_data: dict) -> bool:
        """Push project signature to remote registry."""
        session = self._get_session()

        try:
            response = session.post(
                f"{self.remote_url}/api/v1/projects",
                json=project_data,
                timeout=30,
            )
            return response.status_code in (200, 201)
        except Exception:
            return False

    def search_remote(self, query: dict) -> list[dict]:
        """Search remote registry."""
        session = self._get_session()

        try:
            response = session.post(
                f"{self.remote_url}/api/v1/search",
                json=query,
                timeout=30,
            )
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception:
            pass

        return []

    def check_compliance(self, project_name: str) -> dict:
        """Check compliance status of a project."""
        session = self._get_session()

        try:
            response = session.get(
                f"{self.remote_url}/api/v1/projects/{project_name}/compliance",
                timeout=10,
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return {"status": "unknown"}


def create_registry(config: RegistryConfig) -> EnterpriseRegistry:
    """Factory function to create a registry instance."""
    return EnterpriseRegistry(config)


def create_remote_client(remote_url: str, api_key: str) -> RemoteRegistryClient:
    """Factory function to create a remote registry client."""
    return RemoteRegistryClient(remote_url, api_key)


# Database URL parsing
def parse_database_url(url: str) -> dict:
    """Parse PostgreSQL connection URL."""
    import urllib.parse

    result = urllib.parse.urlparse(url)
    return {
        "host": result.hostname or "localhost",
        "port": result.port or 5432,
        "database": result.path.lstrip("/") or "licenseseal",
        "user": result.username or "",
        "password": result.password or "",
    }


# Health check
def check_registry_health(config: RegistryConfig) -> bool:
    """Check if registry database is accessible."""
    try:
        registry = EnterpriseRegistry(config)
        conn = registry._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        return cursor.fetchone() is not None
    except Exception:
        return False