"""Voyage AI 임베딩 클라이언트 래퍼.

VOYAGE_API_KEY가 없거나 voyageai 패키지가 설치되지 않으면 임베딩 기능은
no-op으로 동작한다(retrieve_similar_patterns는 빈 결과, 시드 시 embedding 미생성).
"""
from __future__ import annotations

import logging
import os
from typing import Iterable

logger = logging.getLogger(__name__)

EMBEDDING_MODEL = os.environ.get("VOYAGE_MODEL", "voyage-3")
EMBEDDING_DIM = int(os.environ.get("VOYAGE_DIM", "1024"))

_client = None
_unavailable_reason: str | None = None


def _read_secret_file(path: str) -> str:
    """secrets/voyage.key 같은 한 줄 파일 read (entrypoint env 못 받는 child process용)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _get_client():
    global _client, _unavailable_reason
    if _client is not None:
        return _client
    if _unavailable_reason is not None:
        return None

    # 1) 환경변수 우선 (.env 또는 docker compose environment)
    # 2) /run/secrets/voyage.key file fallback (docker exec child process가 entrypoint
    #    env를 못 받을 때 자동 read)
    api_key = (
        os.environ.get("VOYAGE_API_KEY", "").strip()
        or _read_secret_file("/run/secrets/voyage.key")
    )
    if not api_key:
        _unavailable_reason = "VOYAGE_API_KEY not set (env + /run/secrets/voyage.key 둘 다 없음)"
        logger.warning("Voyage embedding disabled: %s", _unavailable_reason)
        return None
    try:
        import voyageai  # type: ignore
    except ImportError as e:
        _unavailable_reason = f"voyageai package missing: {e}"
        logger.warning("Voyage embedding disabled: %s", _unavailable_reason)
        return None

    _client = voyageai.Client(api_key=api_key)
    return _client


def is_available() -> bool:
    return _get_client() is not None


def embed_documents(texts: Iterable[str]) -> list[list[float]] | None:
    """문서(저장용) 임베딩. Voyage가 없으면 None 반환."""
    texts = [t or "" for t in texts]
    if not texts:
        return []
    client = _get_client()
    if client is None:
        return None
    try:
        res = client.embed(texts, model=EMBEDDING_MODEL, input_type="document")
        return list(res.embeddings)
    except Exception as e:
        logger.warning("voyage embed_documents failed: %s", e)
        return None


def embed_query(text: str) -> list[float] | None:
    """쿼리(검색용) 임베딩. Voyage가 없으면 None 반환."""
    client = _get_client()
    if client is None:
        return None
    try:
        res = client.embed([text or ""], model=EMBEDDING_MODEL, input_type="query")
        return list(res.embeddings[0])
    except Exception as e:
        logger.warning("voyage embed_query failed: %s", e)
        return None


def pattern_text(p) -> str:
    """PayloadPattern 하나를 임베딩할 텍스트로 직렬화."""
    parts = [
        f"vuln_type: {p.vuln_type}",
        f"name: {p.name}",
        f"category: {p.category}",
        f"safety_level: {p.safety_level}",
    ]
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
