"""
LicenseSeal OSINT Crawler
=========================

Provider adapters for proactive discovery of possible code clones on public or
internal Git hosts.  The crawler only searches public APIs with caller-provided
tokens and enqueues candidates for the Firehose scanner; it does not bypass
access controls or scrape private content.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Iterable, Protocol

from .firehose_queue import enqueue_candidate, payload_from_candidate, QueueConfig


@dataclass
class SearchHit:
    provider: str
    repository_url: str
    file_url: str = ""
    path: str = ""
    score: float = 0.0
    metadata: dict | None = None

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["metadata"] = payload["metadata"] or {}
        return payload


@dataclass
class OSINTConfig:
    provider: str = "github"  # github, gitlab
    token: str = ""
    base_url: str = ""
    per_page: int = 20
    sleep_seconds: float = 0.0
    enqueue: bool = False
    database_url: str = ""
    workdir: str = ".licenseseal/firehose-osint"


class Provider(Protocol):
    def search_code(self, terms: Iterable[str]) -> list[SearchHit]: ...


def _request_json(url: str, headers: dict[str, str]) -> dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


class GitHubProvider:
    def __init__(self, token: str = "", base_url: str = "https://api.github.com", per_page: int = 20):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.base_url = base_url.rstrip("/")
        self.per_page = per_page

    def search_code(self, terms: Iterable[str]) -> list[SearchHit]:
        hits: list[SearchHit] = []
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "LicenseSeal-OSINT"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        for term in terms:
            q = urllib.parse.quote(f'"{term}"')
            url = f"{self.base_url}/search/code?q={q}&per_page={self.per_page}"
            data = _request_json(url, headers)
            for item in data.get("items", []):
                repo = item.get("repository", {})
                hits.append(SearchHit(
                    provider="github",
                    repository_url=repo.get("clone_url") or repo.get("html_url", ""),
                    file_url=item.get("html_url", ""),
                    path=item.get("path", ""),
                    score=float(item.get("score", 0.0) or 0.0),
                    metadata={"term": term, "repository": repo.get("full_name", "")},
                ))
        return hits


class GitLabProvider:
    def __init__(self, token: str = "", base_url: str = "https://gitlab.com/api/v4", per_page: int = 20):
        self.token = token or os.environ.get("GITLAB_TOKEN", "")
        self.base_url = base_url.rstrip("/")
        self.per_page = per_page

    def search_code(self, terms: Iterable[str]) -> list[SearchHit]:
        hits: list[SearchHit] = []
        headers = {"User-Agent": "LicenseSeal-OSINT"}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        for term in terms:
            search = urllib.parse.quote(term)
            url = f"{self.base_url}/search?scope=blobs&search={search}&per_page={self.per_page}"
            data = _request_json(url, headers)
            for item in data if isinstance(data, list) else []:
                project_id = item.get("project_id")
                repo_url = ""
                if project_id:
                    try:
                        project = _request_json(f"{self.base_url}/projects/{project_id}", headers)
                        repo_url = project.get("http_url_to_repo") or project.get("web_url", "")
                    except Exception:
                        repo_url = ""
                hits.append(SearchHit(
                    provider="gitlab",
                    repository_url=repo_url,
                    file_url=item.get("ref", ""),
                    path=item.get("path", ""),
                    score=1.0,
                    metadata={"term": term, "project_id": project_id},
                ))
        return hits


def make_provider(config: OSINTConfig) -> Provider:
    provider = config.provider.lower()
    if provider == "github":
        return GitHubProvider(config.token, config.base_url or "https://api.github.com", config.per_page)
    if provider == "gitlab":
        return GitLabProvider(config.token, config.base_url or "https://gitlab.com/api/v4", config.per_page)
    raise ValueError(f"unsupported OSINT provider: {config.provider}")


def terms_from_honey_specs(specs: Iterable[object]) -> list[str]:
    terms: list[str] = []
    for spec in specs:
        name = getattr(spec, "name", None)
        fingerprint = getattr(spec, "fingerprint", None)
        if name:
            terms.append(str(name))
        if fingerprint:
            terms.append(str(fingerprint)[:16])
    return sorted(set(terms))


def crawl_terms(terms: Iterable[str], config: OSINTConfig) -> list[SearchHit]:
    provider = make_provider(config)
    hits: list[SearchHit] = []
    for term in terms:
        hits.extend(provider.search_code([term]))
        if config.sleep_seconds:
            time.sleep(config.sleep_seconds)
    return hits


def enqueue_hits(hits: Iterable[SearchHit], config: OSINTConfig) -> list[dict]:
    results: list[dict] = []
    qcfg = QueueConfig(database_url=config.database_url) if config.database_url else None
    seen: set[str] = set()
    for hit in hits:
        if not hit.repository_url or hit.repository_url in seen:
            continue
        seen.add(hit.repository_url)
        payload = payload_from_candidate(
            hit.repository_url,
            workdir=config.workdir,
            metadata={"osint": hit.to_dict()},
        )
        try:
            result = enqueue_candidate(payload, config=qcfg)
            results.append({"repository_url": hit.repository_url, "queued": True, "task_id": getattr(result, "id", None)})
        except Exception as exc:
            results.append({"repository_url": hit.repository_url, "queued": False, "error": str(exc)})
    return results
