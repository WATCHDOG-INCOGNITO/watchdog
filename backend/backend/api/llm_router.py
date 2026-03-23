import os
import json
import logging

from anthropic import Anthropic

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
client = None

def get_client():
    global client
    if client is None:
        client = Anthropic(api_key=ANTHROPIC_API_KEY)
    return client

def _parse_json(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
        raw = raw.rsplit("```", 1)[0]
    return json.loads(raw)

def _call_llm(prompt: str, system: str = "", max_tokens: int = 1024) -> tuple[dict, dict]:
    c = get_client()
    kwargs = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    try:
        resp = c.messages.create(**kwargs)
        raw = resp.content[0].text.strip()
        result = _parse_json(raw)
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
        return result, usage
    except json.JSONDecodeError:
        logger.error(f"JSON 파싱 실패: {raw[:300]}")
        return {}, {}
    except Exception as e:
        logger.error(f"LLM 호출 실패: {e}")
        return {}, {}

# 1. 후보 분석 (기존 기능)

def analyze_candidate(candidate_data: dict) -> dict:
    prompt = f"""의심 지점을 분석하고 JSON으로 반환하라.

엔드포인트: {candidate_data.get('method', 'GET')} {candidate_data.get('endpoint', '/')}
파라미터: {json.dumps(candidate_data.get('params', {}), ensure_ascii=False)}
의심 유형: {candidate_data.get('vuln_type', 'unknown')}
탐지 근거: {candidate_data.get('hypothesis', '')}
추가 정보: {json.dumps(candidate_data.get('features', {}), ensure_ascii=False)}

반환 형식 (JSON만, 다른 텍스트 없이):
{{"risk_level": "high|medium|low|none", "confidence": 0.0~1.0, "analysis": "설명", "suggested_payloads": ["페이로드1", "페이로드2"], "next_action": "verify|dismiss|escalate", "reasoning": "근거"}}"""

    result, usage = _call_llm(prompt, system="당신은 웹 애플리케이션 보안 전문가다.")
    if not result:
        return {"risk_level": "unknown", "confidence": 0.0, "analysis": "LLM 호출 실패",
                "suggested_payloads": [], "next_action": "escalate"}
    result["_usage"] = usage
    return result

def batch_analyze_candidates(candidates_data: list, max_count: int = 10) -> list:
    results = []
    total_tokens = 0
    for i, cand in enumerate(candidates_data[:max_count]):
        logger.info(f"[{i+1}/{min(len(candidates_data), max_count)}] 분석: {cand.get('method')} {cand.get('endpoint')}")
        result = analyze_candidate(cand)
        result["candidate_index"] = i
        result["endpoint"] = cand.get("endpoint")
        result["vuln_type"] = cand.get("vuln_type")
        usage = result.get("_usage", {})
        total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        results.append(result)
    logger.info(f"배치 분석 완료: {len(results)}개, 총 토큰: {total_tokens}")
    return results

# 2. 첫 페이로드 생성 (LLM이 공격 전략 수립)

def generate_initial_payloads(vuln_type: str, endpoint: str, method: str,
                               params: dict, context: dict = None) -> dict:
    ctx = json.dumps(context or {}, ensure_ascii=False)
    param_list = json.dumps(params, ensure_ascii=False)

    prompt = f"""타겟 엔드포인트에 대해 {vuln_type} 취약점 검증용 페이로드를 생성하라.

타겟: {method} {endpoint}
파라미터: {param_list}
추가 컨텍스트: {ctx}

규칙:
- 탐지(probe) → 확인(confirm) → 추출(extract) 3단계로 나눠서 생성
- probe: 취약점 존재 여부만 확인하는 안전한 페이로드
- confirm: 실제 취약점을 입증하는 페이로드
- extract: 데이터 추출 또는 영향 범위 확인용
- 각 단계별 2~4개
- 각 페이로드에 어떤 파라미터에 넣을지, 어떤 응답이 나오면 성공인지 포함

JSON만 반환:
{{
  "strategy": "공격 전략 한 줄 설명",
  "target_params": ["공격 대상 파라미터명"],
  "stages": [
    {{
      "stage": "probe",
      "payloads": [
        {{
          "param": "파라미터명",
          "value": "페이로드 값",
          "method": "GET 또는 POST",
          "description": "이 페이로드의 의도",
          "success_indicator": {{
            "type": "body_contains|status_code|time_delay|body_diff|header_contains",
            "value": "매칭할 값 또는 조건"
          }}
        }}
      ]
    }},
    {{"stage": "confirm", "payloads": [...]}},
    {{"stage": "extract", "payloads": [...]}}
  ]
}}"""

    result, usage = _call_llm(
        prompt,
        system="당신은 공격적 웹 보안 테스터다. 실제 동작하는 페이로드를 생성하라. 안전한 테스트 환경이다.",
        max_tokens=2048,
    )
    if not result:
        return {"strategy": "fallback", "target_params": list(params.keys())[:3],
                "stages": [], "_usage": usage}
    result["_usage"] = usage
    return result

# 3. 응답 분석 + 다음 행동 결정 (핵심)

def analyze_response_and_decide(vuln_type: str, endpoint: str, method: str,
                                 payload_sent: dict, response_data: dict,
                                 attempt_history: list = None) -> dict:
    history_str = ""
    if attempt_history:
        history_str = "이전 시도:\n"
        for h in attempt_history[-5:]:
            history_str += f"  - payload: {h.get('payload', '?')[:100]} → status={h.get('status_code', '?')}, indicator={h.get('indicator_matched', False)}\n"

    prompt = f"""공격 시도 결과를 분석하고 다음 행동을 결정하라.

취약점 유형: {vuln_type}
타겟: {method} {endpoint}

보낸 페이로드:
  param: {payload_sent.get('param', '?')}
  value: {payload_sent.get('value', '?')}
  의도: {payload_sent.get('description', '?')}
  성공 조건: {json.dumps(payload_sent.get('success_indicator', {}), ensure_ascii=False)}

서버 응답:
  status_code: {response_data.get('status_code', '?')}
  응답 시간: {response_data.get('elapsed', '?')}초
  content_length: {response_data.get('content_length', '?')}
  응답 본문 (처음 1500자):
{response_data.get('body', '')[:1500]}

{history_str}

분석 후 JSON만 반환:
{{
  "vulnerable": true/false/null,
  "confidence": 0.0~1.0,
  "analysis": "이 응답이 취약점을 의미하는 이유 또는 아닌 이유",
  "evidence_found": "발견된 구체적 증거 (SQL 에러 메시지, 반사된 스크립트 등)",
  "next_action": "confirm|escalate|pivot|abort",
  "next_payloads": [
    {{
      "param": "파라미터명",
      "value": "다음 시도할 페이로드",
      "method": "GET/POST",
      "description": "의도",
      "success_indicator": {{"type": "...", "value": "..."}}
    }}
  ],
  "reasoning": "다음 행동을 선택한 이유"
}}

next_action 설명:
- confirm: 취약점이 확실하다. 추가 증거를 위해 next_payloads 실행
- escalate: 가능성 있지만 불확실. 다른 기법으로 next_payloads 시도
- pivot: 현재 파라미터/기법 실패. 다른 파라미터나 다른 취약점 유형으로 전환
- abort: 취약하지 않다고 판단. 중단"""

    result, usage = _call_llm(
        prompt,
        system="당신은 공격적 웹 보안 테스터다. 응답을 정밀하게 분석하고 최적의 다음 행동을 결정하라.",
        max_tokens=2048,
    )
    if not result:
        return {"vulnerable": None, "confidence": 0.0, "analysis": "LLM 호출 실패",
                "next_action": "abort", "next_payloads": [], "_usage": usage}
    result["_usage"] = usage
    return result

# 4. WAF 우회 페이로드 변형

def mutate_payload_for_bypass(original_payload: str, vuln_type: str,
                               blocked_response: str) -> dict:
    prompt = f"""WAF에 의해 차단된 페이로드를 우회하는 변형을 생성하라.

원본 페이로드: {original_payload}
취약점 유형: {vuln_type}
WAF 차단 응답 (처음 500자): {blocked_response[:500]}

변형 기법: 대소문자 혼합, 인코딩(URL/HTML/유니코드/더블인코딩), 주석 삽입, 공백 변형, 문자열 연결, 대체 구문 등

JSON만 반환:
{{
  "mutations": [
    {{"value": "변형된 페이로드", "technique": "사용한 기법", "description": "설명"}},
    ...최소 3개, 최대 6개
  ]
}}"""

    result, usage = _call_llm(
        prompt,
        system="당신은 WAF 우회 전문가다. 창의적이고 실제 동작하는 변형을 생성하라.",
        max_tokens=1024,
    )
    if not result:
        return {"mutations": [], "_usage": usage}
    result["_usage"] = usage
    return result

# 5. 최종 취약점 판정

def make_final_verdict(vuln_type: str, endpoint: str, attempt_history: list) -> dict:
    history_summary = []
    for h in attempt_history:
        history_summary.append({
            "payload": str(h.get("payload", ""))[:200],
            "status_code": h.get("status_code"),
            "elapsed": h.get("elapsed"),
            "indicator_matched": h.get("indicator_matched", False),
            "llm_analysis": str(h.get("llm_analysis", ""))[:200],
        })

    prompt = f"""모든 공격 시도를 종합하여 최종 판정을 내려라.

취약점 유형: {vuln_type}
타겟: {endpoint}

시도 이력:
{json.dumps(history_summary, ensure_ascii=False, indent=2)}

JSON만 반환:
{{
  "verdict": "confirmed|likely|unlikely|not_vulnerable",
  "confidence": 0.0~1.0,
  "severity": "critical|high|medium|low|info",
  "summary": "최종 판정 요약",
  "reproduction_steps": "재현 절차 (confirmed인 경우)",
  "evidence_summary": "핵심 증거 요약"
}}"""

    result, usage = _call_llm(
        prompt,
        system="당신은 시니어 보안 컨설턴트다. 증거 기반으로 정확한 판정을 내려라. 확실하지 않으면 likely나 unlikely로 표시하라.",
        max_tokens=1024,
    )
    if not result:
        return {"verdict": "unlikely", "confidence": 0.0, "severity": "info",
                "summary": "LLM 판정 실패", "_usage": usage}
    result["_usage"] = usage
    return result

