"""Local embedding service using sentence-transformers.

Runs entirely on-device — no external API key required.
Model is downloaded from HuggingFace Hub on first use and cached locally.
"""
from __future__ import annotations

import logging
from typing import Iterable

logger = logging.getLogger(__name__)

EMBEDDING_MODEL = "all-mpnet-base-v2"
EMBEDDING_DIM = 768

_model = None


def _get_model():
    global _model
    if _model is not None:
        return _model
    try:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBEDDING_MODEL)
        logger.info("Loaded local embedding model: %s (%d dim)", EMBEDDING_MODEL, EMBEDDING_DIM)
        return _model
    except Exception as e:
        logger.warning("Failed to load sentence-transformers model: %s", e)
        return None


def is_available() -> bool:
    return _get_model() is not None


def embeddings_available() -> bool:
    """Alias kept for backward compatibility with seed_techniques.py."""
    return is_available()


def embed_documents(texts: Iterable[str]) -> list[list[float]] | None:
    """Batch-embed documents for storage. Returns None on failure."""
    texts = [t or "" for t in texts]
    if not texts:
        return []
    model = _get_model()
    if model is None:
        return None
    try:
        embeddings = model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False)
        return [e.tolist() for e in embeddings]
    except Exception as e:
        logger.warning("embed_documents failed: %s", e)
        return None


def embed_query(text: str) -> list[float] | None:
    """Embed a single query for search. Returns None on failure."""
    model = _get_model()
    if model is None:
        return None
    try:
        return model.encode(text or "", normalize_embeddings=True).tolist()
    except Exception as e:
        logger.warning("embed_query failed: %s", e)
        return None


def pattern_text(p) -> str:
    """Serialize a PayloadPattern into text for embedding."""
    parts = [
        f"vuln_type: {p.vuln_type}",
    ]
    if getattr(p, "sub_technique", None):
        parts.append(f"sub_technique: {p.sub_technique}")
    parts.extend([
        f"name: {p.name}",
        f"category: {p.category}",
        f"safety_level: {p.safety_level}",
    ])
    if p.request_template:
        parts.append(f"template: {p.request_template}")
    if p.safety_notes:
        parts.append(f"notes: {p.safety_notes}")
    if p.tags:
        parts.append(f"tags: {', '.join(p.tags) if isinstance(p.tags, list) else p.tags}")
    if p.vulnerability_id:
        v = p.vulnerability
        if v:
            parts.append(f"vuln_title: {v.title}")
            if v.description:
                parts.append(f"vuln_desc: {v.description}")
    return "\n".join(parts)
