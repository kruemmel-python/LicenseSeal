"""
Distributed Firehose Queue
==========================

Optional Celery/Redis integration for scaling LicenseSeal Firehose scans.
The module is import-safe: when Celery is unavailable, the local synchronous
fallback still works and tests can exercise the same public functions.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .enterprise import EnterpriseRegistry, RegistryConfig
from .firehose import CandidateRepo, FirehoseConfig, FirehoseScanner

try:
    from celery import Celery  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Celery = None  # type: ignore


@dataclass
class QueueConfig:
    broker_url: str = os.environ.get("LICENSESEAL_CELERY_BROKER", "redis://localhost:6379/0")
    result_backend: str = os.environ.get("LICENSESEAL_CELERY_BACKEND", "redis://localhost:6379/1")
    database_url: str = os.environ.get("LICENSESEAL_DATABASE_URL", "postgresql://localhost:5432/licenseseal")
    workdir: str = os.environ.get("LICENSESEAL_FIREHOSE_WORKDIR", ".licenseseal/firehose-workers")
    min_score: float = float(os.environ.get("LICENSESEAL_FIREHOSE_THRESHOLD", "0.72"))


def make_celery_app(config: QueueConfig | None = None):
    """Create a Celery app or return None when Celery is not installed."""
    config = config or QueueConfig()
    if Celery is None:
        return None
    app = Celery("licenseseal_firehose", broker=config.broker_url, backend=config.result_backend)
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        worker_prefetch_multiplier=1,
        task_acks_late=True,
    )
    return app


def scan_candidate_payload(payload: dict[str, Any], config: QueueConfig | None = None) -> dict:
    """Synchronous worker implementation used by Celery and local fallback."""
    config = config or QueueConfig()
    registry = EnterpriseRegistry(RegistryConfig(database_url=payload.get("database_url") or config.database_url))
    fh_config = FirehoseConfig(
        workdir=Path(payload.get("workdir") or config.workdir),
        min_score=float(payload.get("min_score", config.min_score)),
        clone_depth=int(payload.get("clone_depth", 1)),
        max_files_per_repo=int(payload.get("max_files_per_repo", 5000)),
        include_configs=bool(payload.get("include_configs", False)),
    )
    scanner = FirehoseScanner(registry, fh_config)
    candidate = CandidateRepo(
        url=payload["url"],
        name=payload.get("name", ""),
        owner=payload.get("owner", ""),
        default_branch=payload.get("default_branch", ""),
        metadata=payload.get("metadata", {}),
    )
    summary = scanner.scan_candidate(candidate, record=bool(payload.get("record", True)))
    return summary.to_dict()


celery_app = make_celery_app()

if celery_app is not None:  # pragma: no cover - requires Celery worker
    @celery_app.task(name="licenseseal.firehose.scan_candidate")
    def scan_candidate_task(payload: dict[str, Any]) -> dict:
        return scan_candidate_payload(payload)


def enqueue_candidate(payload: dict[str, Any], config: QueueConfig | None = None):
    """
    Enqueue a candidate for distributed scanning.

    Returns a Celery AsyncResult when Celery is available. If Celery is missing,
    raises a RuntimeError with an actionable message instead of failing at import.
    """
    app = make_celery_app(config)
    if app is None:
        raise RuntimeError('Celery is not installed. Install with: pip install "licenseseal[queue]"')
    return app.send_task("licenseseal.firehose.scan_candidate", args=[payload])


def run_local_queue_fallback(payloads: list[dict[str, Any]], config: QueueConfig | None = None) -> list[dict]:
    """Process payloads synchronously using the same worker logic."""
    return [scan_candidate_payload(payload, config=config) for payload in payloads]


def payload_from_candidate(url: str, **kwargs) -> dict[str, Any]:
    payload = {"url": url}
    payload.update(kwargs)
    return payload
