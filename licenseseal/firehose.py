"""
LicenseSeal Firehose Scanner
============================
Continuous candidate scanner that turns repository observations into registry
evidence items. It combines boundary markers, honey-logic fingerprints and
structural similarity into a noisy-OR evidence score.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .core import BOUNDARY_BEGIN, DEFAULT_EXCLUDE_DIRS, compare_projects, iter_candidate_files
from .enterprise import EnterpriseRegistry
from .watermark import HoneyLogicDetector, extract_honey_logic_fingerprints
from .honey_multilang import MultiLanguageHoneyLogicDetector, language_for_path


@dataclass
class FirehoseConfig:
    """Configuration for continuous repository scanning."""
    workdir: Path = Path(".licenseseal/firehose")
    min_score: float = 0.72
    clone_depth: int = 1
    include_configs: bool = False
    include_forks: bool = False
    max_files_per_repo: int = 5000
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))


@dataclass
class CandidateRepo:
    """A source candidate to be scanned."""
    url: str
    name: str = ""
    owner: str = ""
    local_path: Path | None = None
    default_branch: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class EvidenceHit:
    """One explainable match signal."""
    project_id: str
    candidate_url: str
    evidence_type: str
    confidence: float
    matched_path: str = ""
    source_path: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class FirehoseScanSummary:
    """Serializable result of one candidate scan."""
    candidate_url: str
    scores: dict[str, float]
    hits: list[EvidenceHit]
    recorded_scan_ids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "candidate_url": self.candidate_url,
            "scores": self.scores,
            "recorded_scan_ids": self.recorded_scan_ids,
            "hits": [
                {
                    "project_id": h.project_id,
                    "candidate_url": h.candidate_url,
                    "evidence_type": h.evidence_type,
                    "confidence": h.confidence,
                    "matched_path": h.matched_path,
                    "source_path": h.source_path,
                    "details": h.details,
                }
                for h in self.hits
            ],
        }


class LocalSourceAdapter:
    """Turns local paths or git URLs into materialized candidate directories."""

    def __init__(self, config: FirehoseConfig):
        self.config = config
        self.config.workdir.mkdir(parents=True, exist_ok=True)

    def materialize(self, candidate: CandidateRepo) -> Path:
        if candidate.local_path:
            path = candidate.local_path.resolve()
            if not path.is_dir():
                raise ValueError(f"candidate path is not a directory: {path}")
            return path

        raw = candidate.url
        maybe_path = Path(raw)
        if maybe_path.exists() and maybe_path.is_dir():
            candidate.local_path = maybe_path.resolve()
            return candidate.local_path

        # Git URL clone path. Kept intentionally shallow for firehose operation.
        repo_key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        target = self.config.workdir / repo_key
        if target.exists():
            shutil.rmtree(target)

        cmd = ["git", "clone", "--depth", str(self.config.clone_depth), raw, str(target)]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        candidate.local_path = target
        return target


class FirehoseScanner:
    """
    Candidate-to-evidence worker.

    The scanner does not declare infringement. It records independent evidence
    signals into the registry; policy and legal interpretation stay outside the
    crawler.
    """

    WEIGHTS = {
        "boundary_signature": 0.98,
        "watermark_zwc": 0.92,
        "watermark_semantic": 0.75,
        "honey_logic_exact": 0.95,
        "honey_logic_fuzzy": 0.82,
        "shingle_similarity": 0.65,
        "embedding_similarity": 0.45,
        "path_similarity": 0.25,
        "graph_similarity": 0.78,
    }

    def __init__(self, registry: EnterpriseRegistry, config: FirehoseConfig | None = None):
        self.registry = registry
        self.config = config or FirehoseConfig()
        self.adapter = LocalSourceAdapter(self.config)
        self.honey_detector = HoneyLogicDetector()

    def scan_candidate(self, candidate: CandidateRepo, record: bool = True) -> FirehoseScanSummary:
        local_path = self.adapter.materialize(candidate)
        candidate_url = candidate.url or str(local_path)
        hits: list[EvidenceHit] = []

        hits.extend(self._scan_honey_logic(candidate_url, local_path))
        hits.extend(self._scan_boundaries(candidate_url, local_path))
        hits.extend(self._scan_structural_similarity(candidate_url, local_path))
        hits.extend(self._scan_graph_similarity(candidate_url, local_path))

        scores = self.score_hits(hits)
        summary = FirehoseScanSummary(candidate_url=candidate_url, scores=scores, hits=hits)

        if record:
            summary.recorded_scan_ids = self.record_summary(summary)

        return summary

    def scan_many(self, candidates: Iterable[CandidateRepo], record: bool = True) -> list[FirehoseScanSummary]:
        return [self.scan_candidate(candidate, record=record) for candidate in candidates]

    def score_hits(self, hits: list[EvidenceHit]) -> dict[str, float]:
        """Combine independent evidence by project with noisy-OR scoring."""
        by_project: dict[str, float] = {}
        for hit in hits:
            weight = self.WEIGHTS.get(hit.evidence_type, 0.30)
            old = by_project.get(hit.project_id, 0.0)
            contribution = max(0.0, min(1.0, hit.confidence)) * weight
            by_project[hit.project_id] = 1 - ((1 - old) * (1 - contribution))
        return by_project

    def record_summary(self, summary: FirehoseScanSummary) -> dict[str, str]:
        """Persist scan results and evidence items into the registry."""
        scan_ids: dict[str, str] = {}
        for project_id, score in summary.scores.items():
            scan_id = self.registry.record_scan_result(
                original_project_id=project_id,
                suspected_repo_url=summary.candidate_url,
                similarity_score=score,
                scan_type="firehose",
                details={
                    "hit_count": sum(1 for h in summary.hits if h.project_id == project_id),
                    "threshold": self.config.min_score,
                },
            )
            scan_ids[project_id] = scan_id
            for hit in summary.hits:
                if hit.project_id != project_id:
                    continue
                self.registry.record_evidence_item(
                    scan_result_id=scan_id,
                    evidence_type=hit.evidence_type,
                    confidence=hit.confidence,
                    source_path=hit.source_path,
                    matched_path=hit.matched_path,
                    details=hit.details,
                )
        return scan_ids

    def _candidate_files(self, local_path: Path) -> list[Path]:
        files = list(iter_candidate_files(
            local_path,
            exclude_dirs=self.config.exclude_dirs,
            include_configs=self.config.include_configs,
        ))
        return files[: self.config.max_files_per_repo]

    def _scan_honey_logic(self, candidate_url: str, local_path: Path) -> list[EvidenceHit]:
        hits: list[EvidenceHit] = []
        files = self._candidate_files(local_path)
        observed_by_fp: dict[str, tuple[Path, object]] = {}

        # Python AST Honey-Logic.
        for path in [p for p in files if p.suffix == ".py"]:
            try:
                source = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for fp in extract_honey_logic_fingerprints(source):
                observed_by_fp[fp.fingerprint] = (path, fp)

        # Polyglot Honey-Logic: exact name and constant-set matches.
        multi_detector = MultiLanguageHoneyLogicDetector()
        for path in files:
            lang = language_for_path(path)
            if not lang:
                continue
            for match in multi_detector.scan_file(path, lang):
                observed_by_fp.setdefault(match.fingerprint, (path, match))

        if not observed_by_fp:
            return hits

        matches = self.registry.find_honey_matches(list(observed_by_fp.keys()))
        for match in matches:
            path, observed = observed_by_fp[match["fingerprint"]]
            try:
                rel = str(path.relative_to(local_path))
            except ValueError:
                rel = str(path)
            evidence_type = "honey_logic_exact"
            if getattr(observed, "language", "python") != "python":
                evidence_type = "honey_logic_multilang"
            hits.append(EvidenceHit(
                project_id=match["project_id"],
                candidate_url=candidate_url,
                evidence_type=evidence_type,
                confidence=float(match.get("rarity_score") or getattr(observed, "confidence", 1.0)),
                matched_path=rel,
                details={
                    "fingerprint": match["fingerprint"],
                    "function": getattr(observed, "function", ""),
                    "language": getattr(observed, "language", "python"),
                    "project_name": match.get("project_name", ""),
                    "features": match.get("features", {}),
                },
            ))
        return hits

    def _scan_boundaries(self, candidate_url: str, local_path: Path) -> list[EvidenceHit]:
        hits: list[EvidenceHit] = []
        projects = self.registry.list_projects()
        signatures = {
            p.signature: p
            for p in projects
            if p.signature
        }
        if not signatures:
            return hits

        for path in self._candidate_files(local_path):
            try:
                source = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if BOUNDARY_BEGIN not in source:
                continue
            for signature, project in signatures.items():
                if signature and signature in source:
                    try:
                        rel = str(path.relative_to(local_path))
                    except ValueError:
                        rel = str(path)
                    hits.append(EvidenceHit(
                        project_id=project.id,
                        candidate_url=candidate_url,
                        evidence_type="boundary_signature",
                        confidence=0.99,
                        matched_path=rel,
                        details={"signature": signature[:32]},
                    ))
        return hits

    def _scan_structural_similarity(self, candidate_url: str, local_path: Path) -> list[EvidenceHit]:
        hits: list[EvidenceHit] = []
        for project in self.registry.list_projects():
            if not project.root_path:
                continue
            original = Path(project.root_path)
            if not original.is_dir() or original.resolve() == local_path.resolve():
                continue
            try:
                report = compare_projects(
                    original,
                    local_path,
                    include_configs=self.config.include_configs,
                    exclude_dirs=self.config.exclude_dirs,
                )
            except Exception:
                continue
            score = float(report.get("structural_similarity", 0.0))
            if score >= 0.50:
                hits.append(EvidenceHit(
                    project_id=project.id,
                    candidate_url=candidate_url,
                    evidence_type="shingle_similarity",
                    confidence=score,
                    details={
                        "structural_similarity": score,
                        "license_status": report.get("license_status"),
                    },
                ))
        return hits


    def _scan_graph_similarity(self, candidate_url: str, local_path: Path) -> list[EvidenceHit]:
        """Scan CFG/DFG-style graph fingerprints against registered project roots."""
        hits: list[EvidenceHit] = []
        try:
            from .graph_fingerprint import compare_graph_fingerprints
        except Exception:
            return hits
        for project in self.registry.list_projects():
            if not project.root_path:
                continue
            original = Path(project.root_path)
            if not original.is_dir() or original.resolve() == local_path.resolve():
                continue
            try:
                report = compare_graph_fingerprints(
                    original,
                    local_path,
                    include_configs=self.config.include_configs,
                    exclude_dirs=self.config.exclude_dirs,
                )
            except Exception:
                continue
            score = float(report.get("graph_similarity", 0.0))
            if score >= 0.50:
                hits.append(EvidenceHit(
                    project_id=project.id,
                    candidate_url=candidate_url,
                    evidence_type="graph_similarity",
                    confidence=score,
                    details=report,
                ))
        return hits


def candidate_from_string(value: str) -> CandidateRepo:
    """Create a CandidateRepo from a local path or clone URL."""
    path = Path(value)
    if path.exists() and path.is_dir():
        return CandidateRepo(url=str(path.resolve()), name=path.name, local_path=path.resolve())
    return CandidateRepo(url=value, name=value.rstrip("/").split("/")[-1].replace(".git", ""))


def write_firehose_report(summary: FirehoseScanSummary, output: Path) -> None:
    """Write a JSON firehose summary to disk."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
