"""
LLM 라우터 모듈
Claude API를 호출하여 candidate를 분석한다.
향후 openai, gemini 등 다른 모델도 추가 가능한 구조.
"""

import os
import json
import logging

from anthropic import Anthropic

logger = logging.getLogger(__name__)

# API 키는 환경변수에서 가져옴
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

client = None


def get_client():
    global client
    if client is None:
        client = Anthropic(api_key=ANTHROPIC_API_KEY)
    return client


def analyze_candidate(candidate_data):
    """
    candidate 정보를 Claude에 보내서 분석받는다.

    Args:
        candidate_data: dict {
            "endpoint": "/api/users",
            "method": "GET",
            "params": {"id": "1"},
            "vuln_type": "sqli",
            "hypothesis": "규칙 기반 탐지: ...",
            "features": {...},
        }

    Returns:
        dict {
            "risk_level": "high" | "medium" | "low" | "none",
            "confidence": 0.0~1.0,
            "analysis": "분석 내용",
            "suggested_payloads": ["...", "..."],
            "next_action": "verify" | "dismiss" | "escalate",
        }
    """
    c = get_client()

    prompt = f"""당신은 웹 애플리케이션 보안 전문가입니다.
아래 의심 지점(candidate)을 분석하고, JSON으로 결과를 반환해주세요.

## 의심 지점 정보
- 엔드포인트: {candidate_data.get('method', 'GET')} {candidate_data.get('endpoint', '/')}
- 파라미터: {json.dumps(candidate_data.get('params', {}), ensure_ascii=False)}
- 의심 유형: {candidate_data.get('vuln_type', 'unknown')}
- 탐지 근거: {candidate_data.get('hypothesis', '')}
- 추가 정보: {json.dumps(candidate_data.get('features', {}), ensure_ascii=False)}

## 반환 형식 (JSON만 반환, 다른 텍스트 없이)
{{
    "risk_level": "high | medium | low | none",
    "confidence": 0.0~1.0,
    "analysis": "이 엔드포인트가 왜 위험한지 또는 안전한지 설명",
    "suggested_payloads": ["검증용 페이로드1", "검증용 페이로드2"],
    "next_action": "verify | dismiss | escalate",
    "reasoning": "판단 근거"
}}"""

    try:
        response = c.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()

        # JSON 파싱 (```json ... ``` 감싸져있을 수 있음)
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            raw = raw.rsplit("```", 1)[0]

        result = json.loads(raw)

        # 토큰 사용량 기록
        result["_usage"] = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }

        logger.info(f"LLM 분석 완료: {candidate_data.get('endpoint')} → "
                     f"risk={result.get('risk_level')}, action={result.get('next_action')}")

        return result

    except json.JSONDecodeError as e:
        logger.error(f"LLM 응답 JSON 파싱 실패: {e}\nraw={raw}")
        return {
            "risk_level": "unknown",
            "confidence": 0.0,
            "analysis": f"JSON 파싱 실패: {raw[:200]}",
            "suggested_payloads": [],
            "next_action": "escalate",
        }
    except Exception as e:
        logger.error(f"LLM 호출 실패: {e}")
        return {
            "risk_level": "unknown",
            "confidence": 0.0,
            "analysis": f"API 호출 실패: {str(e)}",
            "suggested_payloads": [],
            "next_action": "escalate",
        }


def batch_analyze_candidates(candidates_data, max_count=10):
    """
    여러 candidate를 분석한다.
    비용 절감을 위해 max_count만큼만 처리 (priority 높은 순으로 이미 정렬되어 있다고 가정).

    Args:
        candidates_data: list of candidate dicts
        max_count: 최대 분석 개수

    Returns:
        list of analysis results
    """
    results = []
    total_tokens = 0

    for i, cand in enumerate(candidates_data[:max_count]):
        logger.info(f"[{i+1}/{min(len(candidates_data), max_count)}] "
                     f"분석 중: {cand.get('method')} {cand.get('endpoint')}")

        result = analyze_candidate(cand)
        result["candidate_index"] = i
        result["endpoint"] = cand.get("endpoint")
        result["vuln_type"] = cand.get("vuln_type")

        usage = result.get("_usage", {})
        total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        results.append(result)

    logger.info(f"배치 분석 완료: {len(results)}개, 총 토큰: {total_tokens}")
    return results
