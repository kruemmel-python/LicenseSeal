"""
LicenseSeal Semantic Search Module
=================================
Provides LLM-based semantic similarity detection using embeddings.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import numpy as np

from .core import (
    current_utc_iso,
    iter_candidate_files,
    strip_license_boundary,
)


# Default embedding dimension for all-MiniLM-L6-v2
DEFAULT_EMBEDDING_DIM = 384

# Code-specialized embedding models
CODE_EMBEDDING_MODELS = {
    "jina-code": "jinaai/jina-embeddings-v2-base-code",
    "codebert": "microsoft/codebert-base",
    "starCoder": "bigcode/starencoder",
    "graphcodebert": "microsoft/graphcodebert-base",
    "minilm": "sentence-transformers/all-MiniLM-L6-v2",  # Default fallback
}

# Language mapping for code embeddings
CODE_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
}


@dataclass
class SemanticConfig:
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    model_type: str = "minilm"  # minilm, jina-code, codebert, starCoder
    device: str = "cpu"
    batch_size: int = 32
    cache_dir: Path | None = None
    cross_lingual: bool = True  # Enable cross-lingual detection
    trust_remote_code: bool = True  # Trust code from different languages


class EmbeddingModel:
    """Wrapper for sentence-transformers embedding model."""

    def __init__(self, config: SemanticConfig):
        self.config = config
        self._model = None
        self._tokenizer = None

    def _lazy_load(self) -> None:
        """Lazy load the model on first use."""
        if self._model is not None:
            return

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise RuntimeError(
                "semantic search requires sentence-transformers. "
                'Install with: pip install "licenseseal[ai]"'
            )

        self._model = SentenceTransformer(
            self.config.model_name,
            device=self.config.device,
            cache_folder=str(self.config.cache_dir) if self.config.cache_dir else None,
        )

    def encode(self, texts: list[str]) -> np.ndarray:
        """Encode texts to embedding vectors."""
        self._lazy_load()
        return self._model.encode(
            texts,
            batch_size=self.config.batch_size,
            convert_to_numpy=True,
            show_progress_bar=False,
        )

    def encode_file(self, path: Path) -> np.ndarray:
        """Encode a single file's content."""
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            return np.zeros(DEFAULT_EMBEDDING_DIM)

        text = strip_license_boundary(text)
        chunks = _chunk_by_function(text)

        if not chunks:
            return np.zeros(DEFAULT_EMBEDDING_DIM)

        embeddings = self.encode(chunks)
        return np.mean(embeddings, axis=0)


def _chunk_by_function(source: str, max_chars: int = 2000) -> list[str]:
    """
    Chunk source code by function/class boundaries.
    Falls back to character-based chunks if parsing fails.
    """
    chunks: list[str] = []

    # Try Python function detection
    if "def " in source or "class " in source:
        lines = source.splitlines()
        current_chunk: list[str] = []
        indent_stack = [0]

        for line in lines:
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            # New function or class
            if stripped.startswith(("def ", "class ", "async def ")):
                if current_chunk:
                    chunk_text = "\n".join(current_chunk)
                    if chunk_text.strip():
                        chunks.append(chunk_text)
                    current_chunk = []

            current_chunk.append(line)

        if current_chunk:
            chunk_text = "\n".join(current_chunk)
            if chunk_text.strip():
                chunks.append(chunk_text)

    # Fallback: character-based chunks
    if not chunks:
        for i in range(0, len(source), max_chars):
            chunk = source[i:i + max_chars]
            if chunk.strip():
                chunks.append(chunk)

    return chunks


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Calculate cosine similarity between two vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return float(np.dot(a, b) / (norm_a * norm_b))


def file_embedding(path: Path, model: EmbeddingModel) -> np.ndarray:
    """Get embedding vector for a file."""
    return model.encode_file(path)


def project_embeddings(
    root: Path,
    model: EmbeddingModel,
    include_configs: bool = False,
    exclude_dirs: set[str] | None = None,
) -> dict[Path, np.ndarray]:
    """Generate embeddings for all files in a project."""
    embeddings: dict[Path, np.ndarray] = {}

    for path in iter_candidate_files(root, exclude_dirs, include_configs):
        emb = model.encode_file(path)
        if np.any(emb):  # Only add non-zero embeddings
            embeddings[path] = emb

    return embeddings


def compare_semantic(
    original_root: Path,
    suspected_root: Path,
    model: EmbeddingModel,
    include_configs: bool = False,
    exclude_dirs: set[str] | None = None,
    threshold: float = 0.85,
) -> dict:
    """
    Compare two projects using semantic embeddings.
    Returns similarity score and detailed file-level analysis.
    """
    original_embeddings = project_embeddings(
        original_root, model, include_configs, exclude_dirs
    )
    suspected_embeddings = project_embeddings(
        suspected_root, model, include_configs, exclude_dirs
    )

    if not original_embeddings or not suspected_embeddings:
        return {
            "semantic_similarity": 0.0,
            "semantic_similarity_percent": 0.0,
            "assessment": "no_embeddings",
            "files_compared": 0,
        }

    # Calculate project-level similarity
    original_vecs = np.mean(list(original_embeddings.values()), axis=0)
    suspected_vecs = np.mean(list(suspected_embeddings.values()), axis=0)

    project_similarity = _cosine_similarity(original_vecs, suspected_vecs)

    # File-level analysis
    similar_files: list[dict] = []
    for orig_path, orig_emb in original_embeddings.items():
        for susp_path, susp_emb in suspected_embeddings.items():
            file_sim = _cosine_similarity(orig_emb, susp_emb)
            if file_sim >= threshold:
                similar_files.append({
                    "original_file": str(orig_path.relative_to(original_root)),
                    "suspected_file": str(susp_path.relative_to(suspected_root)),
                    "similarity": round(file_sim, 4),
                })

    # Sort by similarity
    similar_files.sort(key=lambda x: x["similarity"], reverse=True)

    assessment = "low_semantic_similarity"
    if project_similarity >= 0.95:
        assessment = "very_high_semantic_similarity"
    elif project_similarity >= 0.85:
        assessment = "high_semantic_similarity"
    elif project_similarity >= 0.70:
        assessment = "moderate_semantic_similarity"

    return {
        "schema": "licenseseal.semantic.v1",
        "created_at": current_utc_iso(),
        "original": str(original_root),
        "suspected": str(suspected_root),
        "semantic_similarity": round(project_similarity, 4),
        "semantic_similarity_percent": round(project_similarity * 100, 2),
        "model": model.config.model_name,
        "original_file_count": len(original_embeddings),
        "suspected_file_count": len(suspected_embeddings),
        "similar_files_above_threshold": len(similar_files),
        "threshold": threshold,
        "assessment": assessment,
        "top_similar_files": similar_files[:20],
    }


def find_semantic_matches(
    target_root: Path,
    indexed_embeddings: dict[Path, np.ndarray],
    model: EmbeddingModel,
    threshold: float = 0.85,
) -> list[dict]:
    """
    Find semantic matches between a target project and indexed embeddings.
    """
    matches: list[dict] = []

    target_embeddings = project_embeddings(target_root, model)

    for target_path, target_emb in target_embeddings.items():
        for indexed_path, indexed_emb in indexed_embeddings.items():
            sim = _cosine_similarity(target_emb, indexed_emb)
            if sim >= threshold:
                matches.append({
                    "target_file": str(target_path),
                    "indexed_file": str(indexed_path),
                    "similarity": round(sim, 4),
                })

    matches.sort(key=lambda x: x["similarity"], reverse=True)
    return matches


def embedding_hash(embedding: np.ndarray) -> str:
    """Generate a hash from an embedding vector for storage."""
    # Quantize to reduce precision before hashing
    quantized = (embedding * 1000).astype(np.int32).tobytes()
    return hashlib.sha256(quantized).hexdigest()[:16]


def store_embeddings(
    embeddings: dict[Path, np.ndarray],
    output_path: Path,
    metadata: dict | None = None,
) -> None:
    """Store embeddings to a file for later reuse."""
    import pickle

    data = {
        "metadata": metadata or {},
        "embeddings": {str(k): v.tolist() for k, v in embeddings.items()},
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(data, f)


def load_embeddings(input_path: Path) -> dict[Path, np.ndarray]:
    """Load embeddings from a file."""
    import pickle

    with open(input_path, "rb") as f:
        data = pickle.load(f)

    return {Path(k): np.array(v) for k, v in data["embeddings"].items()}


def get_embedding_model(
    model_name: str | None = None,
    device: str | None = None,
    cache_dir: Path | None = None,
) -> EmbeddingModel:
    """Factory function to create an embedding model."""
    config = SemanticConfig(
        model_name=model_name or "sentence-transformers/all-MiniLM-L6-v2",
        device=device or ("cuda" if _has_cuda() else "cpu"),
        cache_dir=cache_dir,
    )
    return EmbeddingModel(config)


def _has_cuda() -> bool:
    """Check if CUDA is available."""
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False


# =============================================================================
# Cross-Lingual Code Detection
# =============================================================================

def get_code_embedding_model(
    model_type: str = "jina-code",
    device: str | None = None,
    cache_dir: Path | None = None,
) -> EmbeddingModel:
    """
    Get a code-specialized embedding model.
    Supports cross-lingual detection (Python→Go, Java→Rust, etc.)
    """
    model_name = CODE_EMBEDDING_MODELS.get(model_type, CODE_EMBEDDING_MODELS["minilm"])

    config = SemanticConfig(
        model_name=model_name,
        model_type=model_type,
        device=device or ("cuda" if _has_cuda() else "cpu"),
        cache_dir=cache_dir,
        cross_lingual=True,
    )
    return EmbeddingModel(config)


def detect_language_from_extension(path: Path) -> str | None:
    """Detect programming language from file extension."""
    return CODE_LANGUAGE_MAP.get(path.suffix.lower())


def compare_cross_lingual(
    original_root: Path,
    suspected_root: Path,
    model: EmbeddingModel,
    include_configs: bool = False,
    exclude_dirs: set[str] | None = None,
    threshold: float = 0.80,
) -> dict:
    """
    Compare projects across different programming languages.
    Detects code translation (e.g., Python→Go, Java→Rust).
    """
    # Group files by language
    original_by_lang: dict[str, list[Path]] = {}
    suspected_by_lang: dict[str, list[Path]] = {}

    for path in iter_candidate_files(original_root, exclude_dirs, include_configs):
        lang = detect_language_from_extension(path)
        if lang:
            original_by_lang.setdefault(lang, []).append(path)

    for path in iter_candidate_files(suspected_root, exclude_dirs, include_configs):
        lang = detect_language_from_extension(path)
        if lang:
            suspected_by_lang.setdefault(lang, []).append(path)

    # Calculate cross-lingual similarities
    cross_lingual_matches: list[dict] = []
    same_lang_matches: list[dict] = []

    for orig_lang, orig_files in original_by_lang.items():
        for susp_lang, susp_files in suspected_by_lang.items():
            # Calculate similarity between file groups
            orig_emb = _average_embeddings_for_files(orig_files, model)
            susp_emb = _average_embeddings_for_files(susp_files, model)

            if orig_emb is not None and susp_emb is not None:
                sim = _cosine_similarity(orig_emb, susp_emb)

                match = {
                    "original_language": orig_lang,
                    "suspected_language": susp_lang,
                    "original_file_count": len(orig_files),
                    "suspected_file_count": len(susp_files),
                    "similarity": round(sim, 4),
                }

                if orig_lang != susp_lang:
                    cross_lingual_matches.append(match)
                else:
                    same_lang_matches.append(match)

    # Sort by similarity
    cross_lingual_matches.sort(key=lambda x: x["similarity"], reverse=True)
    same_lang_matches.sort(key=lambda x: x["similarity"], reverse=True)

    # Determine assessment
    max_cross_sim = cross_lingual_matches[0]["similarity"] if cross_lingual_matches else 0
    max_same_sim = same_lang_matches[0]["similarity"] if same_lang_matches else 0

    assessment = "no_similarity"
    if max_cross_sim >= threshold or max_same_sim >= threshold:
        if max_cross_sim > max_same_sim:
            assessment = "cross_lingual_code_translation_detected"
        else:
            assessment = "same_language_similarity_detected"

    return {
        "schema": "licenseseal.cross-lingual.v1",
        "created_at": current_utc_iso(),
        "original": str(original_root),
        "suspected": str(suspected_root),
        "model": model.config.model_name,
        "model_type": model.config.model_type,
        "threshold": threshold,
        "assessment": assessment,
        "max_cross_lingual_similarity": max_cross_sim,
        "max_same_language_similarity": max_same_sim,
        "cross_lingual_matches": cross_lingual_matches[:10],
        "same_language_matches": same_lang_matches[:10],
        "languages_in_original": list(original_by_lang.keys()),
        "languages_in_suspected": list(suspected_by_lang.keys()),
    }


def _average_embeddings_for_files(
    files: list[Path],
    model: EmbeddingModel,
) -> np.ndarray | None:
    """Calculate average embedding for a list of files."""
    embeddings = []

    for path in files:
        emb = model.encode_file(path)
        if np.any(emb):
            embeddings.append(emb)

    if not embeddings:
        return None

    return np.mean(embeddings, axis=0)


def detect_code_translation(
    original_path: Path,
    suspected_paths: list[Path],
    model: EmbeddingModel,
    threshold: float = 0.75,
) -> list[dict]:
    """
    Detect if a file was translated from another language.
    Returns list of potential translations with similarity scores.
    """
    orig_emb = model.encode_file(original_path)
    if not np.any(orig_emb):
        return []

    translations = []
    for susp_path in suspected_paths:
        susp_emb = model.encode_file(susp_path)
        if not np.any(susp_emb):
            continue

        sim = _cosine_similarity(orig_emb, susp_emb)
        if sim >= threshold:
            translations.append({
                "original_file": str(original_path),
                "suspected_file": str(susp_path),
                "original_language": detect_language_from_extension(original_path),
                "suspected_language": detect_language_from_extension(susp_path),
                "similarity": round(sim, 4),
                "likely_translation": sim >= 0.90,
            })

    translations.sort(key=lambda x: x["similarity"], reverse=True)
    return translations


# Factory function update
def get_embedding_model(
    model_name: str | None = None,
    device: str | None = None,
    cache_dir: Path | None = None,
    model_type: str = "minilm",
) -> EmbeddingModel:
    """Factory function to create an embedding model."""
    # Use code-specialized model if specified
    if model_type != "minilm" and model_type in CODE_EMBEDDING_MODELS:
        model_name = CODE_EMBEDDING_MODELS[model_type]

    config = SemanticConfig(
        model_name=model_name or CODE_EMBEDDING_MODELS["minilm"],
        model_type=model_type,
        device=device or ("cuda" if _has_cuda() else "cpu"),
        cache_dir=cache_dir,
    )
    return EmbeddingModel(config)