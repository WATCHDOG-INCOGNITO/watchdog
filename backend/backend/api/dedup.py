"""SimHash 기반 페이로드 dedup (XBOW SimHash 패턴).

목적: 같은 본질의 페이로드를 변형만 다르게 해서 100번 시도하는 낭비를 줄인다.
예) `1' OR '1'='1` / `1' OR '2'='2` / `1' OR 1=1` 모두 본질 동일 → SimHash 거의 같음.

방식: 64-bit SimHash + Hamming distance.
- 외부 의존성 없음 (hashlib만 사용).
- 토크나이저는 식별자/연산자/공백 split — payload 의미 단위 보존.
- 거리 임계값 default=8 (XBOW 보고 기준).

자율성 원칙: dedup은 *자문(suggestion)*. LLM이 호출해서 결과 보고 판단.
강제 게이트가 아니다. 진짜 같은 본질이라도 LLM이 "이번엔 다른 sink/encoding"
이라 판단하면 시도 가능.
"""
from __future__ import annotations

import hashlib
import re

# 64-bit fingerprint
SIMHASH_BITS = 64
DEFAULT_HAMMING_THRESHOLD = 8

# 토큰 단위 — 영숫자 시퀀스 + 단일 비영숫자(연산자/구분자)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]")


def tokenize(text: str) -> list[str]:
    if not text:
        return []
    # lower-case로 정규화 (대소문자 변형은 noise)
    return _TOKEN_RE.findall(text.lower())


def _token_hash(token: str) -> int:
    # md5의 첫 8 byte → 64-bit unsigned int
    return int.from_bytes(hashlib.md5(token.encode("utf-8")).digest()[:8], "big")


def simhash(text: str, bits: int = SIMHASH_BITS) -> int:
    """텍스트 → 64-bit SimHash 정수.

    빈 문자열은 0 반환.
    """
    tokens = tokenize(text)
    if not tokens:
        return 0
    weights = [0] * bits
    for tok in tokens:
        h = _token_hash(tok)
        for i in range(bits):
            if (h >> i) & 1:
                weights[i] += 1
            else:
                weights[i] -= 1
    fingerprint = 0
    for i in range(bits):
        if weights[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint


def hamming(a: int, b: int) -> int:
    """두 정수 fingerprint의 Hamming distance (다른 비트 수)."""
    return bin(a ^ b).count("1")


def is_near_duplicate(
    a: int,
    b: int,
    threshold: int = DEFAULT_HAMMING_THRESHOLD,
) -> bool:
    """64-bit SimHash 두 개가 본질적으로 같은지 (Hamming <= threshold)."""
    return hamming(a, b) <= threshold


def find_nearest(
    target: int,
    candidates: list[tuple[int, object]],
    threshold: int = DEFAULT_HAMMING_THRESHOLD,
) -> tuple[int, object, int] | None:
    """target과 가장 가까운 candidate 반환 — (distance, ref, _).

    candidates: [(simhash_int, opaque_ref), ...]
    threshold 이내 항목 중 distance 최소를 반환. 없으면 None.
    """
    best: tuple[int, object, int] | None = None
    for fp, ref in candidates:
        d = hamming(target, fp)
        if d > threshold:
            continue
        if best is None or d < best[0]:
            best = (d, ref, 0)
    return best
