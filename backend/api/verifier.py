import json
import os
import re
from datetime import datetime
from typing import Any, List, Literal, Optional, TypedDict

from anthropic import AsyncAnthropic
from langgraph.graph import END, StateGraph

from .models import EvidenceBlob, Finding, FindingEvidenceLink, ScanRun


FAST_MODEL = os.getenv("VERIFIER_CLAUDE_FAST_MODEL", "claude-3-5-haiku-latest")
REASONER_MODEL = os.getenv("VERIFIER_CLAUDE_MODEL", "claude-3-7-sonnet-latest")

_anthropic_client: Optional[AsyncAnthropic] = None


class ResearcherCandidate(TypedDict):
    vuln_type: str
    target_path: str
    confidence: float
    hypothesis: str
    evidence_ref: str


class VerifierState(TypedDict):
    run_id: str
    candidate: ResearcherCandidate
    target_url: str
    attack_result: dict  
    mode: Literal["high_perf", "standard"]
    attempt_context: dict  

    # 정규화/신호
    normalized_result: dict
    rule_signals: dict

    # 판정
    next_action: Literal["retry", "escalate", "confirm", "stop"]
    stop_reason: Optional[str]
    confidence: float
    verifier_decision: Optional[dict]

    # 출력
    attack_guidance: Optional[dict]  # retry 시 공격 에이전트에 전달할 가이드
    finding: Optional[dict]


ALLOWED_ACTIONS = {"retry", "escalate", "confirm", "stop"}

#여기 검증부분은 하이브리드. 대조 + llm
DB_ERROR_KEYWORDS = [
    "sql syntax",
    "syntax error",
    "mysql",
    "ora-",
    "postgres",
    "pg::",
    "sqlite",
    "odbc",
    "sqlstate",
]
#재시도
WAF_KEYWORDS = [
    "access denied",
    "request blocked",
    "firewall",
    "waf",
    "forbidden",
    "security policy",
]
#성공
STRONG_SUCCESS_KEYS = [
    "exploit_succeeded",
    "sensitive_data_exposed",
    "authz_bypass_confirmed",
    "command_output_observed",
    "state_change_observed",
    "file_read_confirmed",
]
#이 값들 없으면 에러로
REQUIRED_CANDIDATE_KEYS = (
    "vuln_type",
    "target_path",
    "confidence",
    "hypothesis",
    "evidence_ref",
)

#얘는 걍 시간
def _utcnow_iso() -> str:
    return datetime.utcnow().isoformat()

#문자열 길때 자르기
def _truncate_text(value: Any, limit: int = 2000) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [truncated {len(text) - limit} chars]"

#한글깨짐 방지. llm프롬프트에 넣을때
def _json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)

#숫자 변환 실패시 0.0으로 변환. 
def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

#confidence를 0.0~1.0으로 범위를 좁힘
def _clamp_01(value: Any) -> float:
    return max(0.0, min(1.0, _safe_float(value, 0.0)))


def _normalize_candidate(candidate: Any) -> ResearcherCandidate:
    #고정스키마 사용하도록 하는 거
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be a dict matching the fixed Researcher schema")

    missing = [key for key in REQUIRED_CANDIDATE_KEYS if key not in candidate]
    if missing:
        raise ValueError(f"candidate missing required keys: {', '.join(missing)}")

    vuln_type = str(candidate.get("vuln_type") or "").strip()
    target_path = str(candidate.get("target_path") or "").strip()
    hypothesis = str(candidate.get("hypothesis") or "").strip()
    evidence_ref = str(candidate.get("evidence_ref") or "").strip()
    confidence = _clamp_01(candidate.get("confidence"))

    if not vuln_type:
        raise ValueError("candidate.vuln_type is required")
    if not target_path:
        raise ValueError("candidate.target_path is required")
    if not target_path.startswith("/"):
        target_path = "/" + target_path
    if not hypothesis:
        raise ValueError("candidate.hypothesis is required")
    if not evidence_ref:
        raise ValueError("candidate.evidence_ref is required")

    normalized: ResearcherCandidate = {
        "vuln_type": _truncate_text(vuln_type, 200),
        "target_path": _truncate_text(target_path, 2048),
        "confidence": confidence,
        "hypothesis": _truncate_text(hypothesis, 2000),
        "evidence_ref": _truncate_text(evidence_ref, 200),
    }
    return normalized

#api 환경변수 확인
def _llm_available() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))

#클로드 api 요청 보내는 객체 재사용
def _get_client() -> AsyncAnthropic:
    global _anthropic_client
    if _anthropic_client is None:
        _anthropic_client = AsyncAnthropic()
    return _anthropic_client

#클로드 대답이 블록구조라 바로 불러올 수 없어서 텍스트 부분만 추출
def _extract_text_from_anthropic_message(msg: Any) -> str:
    parts: List[str] = []
    for block in getattr(msg, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
    return "\n".join(p for p in parts if p).strip()

#얘는 json만
def _extract_json_object(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start:end + 1]
    return cleaned

#그걸 dict로 파싱
def _parse_json_text(text: str) -> dict:
    return json.loads(_extract_json_object(text))

#최종 검증 판단을 받기 위해
async def _call_claude_json(prompt: str, model: str, max_tokens: int) -> dict:
    msg = await _get_client().messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = _extract_text_from_anthropic_message(msg)
    return _parse_json_text(raw)

#헤더 전체말고 일부만. 노이즈 줄이기 위해서.
def _pick_header_subset(headers: Any) -> dict:
    if not isinstance(headers, dict):
        return {}
    keep = {"content-type", "server", "x-powered-by", "location"}
    return {
        str(k): str(v)
        for k, v in headers.items()
        if str(k).lower() in keep
    }

#공격결과가 어떻게 넘어오는지에 따라 코드 바뀔 듯
def _normalize_evidence_refs(raw_refs: Any) -> List[dict]:
    normalized: List[dict] = []
    if not isinstance(raw_refs, list):
        return normalized

    for item in raw_refs:
        if isinstance(item, str):
            normalized.append({"blob_id": item, "role": "evidence"})
            continue
        if isinstance(item, dict):
            blob_id = item.get("blob_id") or item.get("id")
            if not blob_id:
                continue
            normalized.append(
                {
                    "blob_id": str(blob_id),
                    "role": str(item.get("role") or "evidence"),
                }
            )
    return normalized

#결과를 판정하기 쉬운 형태로 변환(결과에서 요청,응답,a_s 값 꺼내기 - )
def _normalize_attack_result(candidate: ResearcherCandidate, attack_result: dict) -> dict:
    request = attack_result.get("request") if isinstance(attack_result.get("request"), dict) else {}
    response = attack_result.get("response") if isinstance(attack_result.get("response"), dict) else {}
    agent_assessment = (
        attack_result.get("agent_assessment")
        if isinstance(attack_result.get("agent_assessment"), dict)
        else {}
    )
    #여러 키들 하나로 합치기
    observations: dict = {}
    for key in ("observations", "signals", "derived_signals"):
        if isinstance(attack_result.get(key), dict):
            observations.update(attack_result[key])

    for key in STRONG_SUCCESS_KEYS + [
        "waf_blocked",
        "payload_reflected",
        "db_error",
        "out_of_scope",
        "timeout",
    ]:
        if key in attack_result and key not in observations:
            observations[key] = attack_result[key]

    payload = attack_result.get("payload")
    if not isinstance(payload, str):
        payload = request.get("payload") if isinstance(request.get("payload"), str) else None
    if not isinstance(payload, str):
        payload = request.get("inject_value") if isinstance(request.get("inject_value"), str) else ""

    status = response.get("status")
    if status is None:
        status = response.get("status_code")
    try:
        status = int(status or 0)
    except (TypeError, ValueError):
        status = 0

    body = response.get("body")
    if body is None:
        body = response.get("text")
    body_text = str(body or "")
    body_lower = body_text.lower()

    headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}

    waf_blocked = bool(observations.get("waf_blocked")) or (
        status in {403, 406, 429}
        or any(keyword in body_lower for keyword in WAF_KEYWORDS)
    )

    payload_reflected = bool(observations.get("payload_reflected")) or (
        bool(payload) and payload in body_text
    )

    db_error = bool(observations.get("db_error")) or any(
        keyword in body_lower for keyword in DB_ERROR_KEYWORDS
    )

    out_of_scope = bool(
        observations.get("out_of_scope")
        or attack_result.get("out_of_scope")
        or (attack_result.get("scope") or {}).get("out_of_scope")
    )

    timeout = bool(observations.get("timeout")) or str(attack_result.get("error", "")).lower() == "timeout"
    transport_error = bool(attack_result.get("error")) or status == 0

    explicit_success = bool(attack_result.get("success"))
    for key in STRONG_SUCCESS_KEYS:
        explicit_success = explicit_success or bool(observations.get(key))

    confirm_hits: List[str] = []
    if explicit_success:
        confirm_hits.append("explicit_success")
    if payload_reflected:
        confirm_hits.append("payload_reflected")
    if db_error:
        confirm_hits.append("db_error")
    if status >= 500:
        confirm_hits.append("server_error")

    positive_obs = [key for key in STRONG_SUCCESS_KEYS if bool(observations.get(key))]

    signal_score = 0
    signal_score += 4 if explicit_success else 0
    signal_score += 2 if db_error else 0
    signal_score += 1 if payload_reflected else 0
    signal_score += 2 if positive_obs else 0
    signal_score += 1 if status >= 500 else 0
    signal_score -= 1 if waf_blocked else 0
    signal_score -= 1 if transport_error and not body_text else 0

    agent_confidence = _clamp_01(
        agent_assessment.get("confidence")
        or agent_assessment.get("success_likelihood")
        or attack_result.get("agent_confidence")
    )

    return {
        "attempt_id": str(
            attack_result.get("attempt_id")
            or attack_result.get("execution_id")
            or attack_result.get("id")
            or ""
        ),
        "attempt_num": attack_result.get("attempt_num") or attack_result.get("attempt_count"),
        "request": {
            "method": str(request.get("method") or "GET"),
            "url": str(request.get("url") or request.get("path") or ""),
            "headers": _pick_header_subset(request.get("headers")),
            "payload": _truncate_text(payload, 500),
            "params": request.get("params") if isinstance(request.get("params"), dict) else {},
        },
        "response": {
            "status": status,
            "headers": _pick_header_subset(headers),
            "body_excerpt": _truncate_text(body_text, 3000),
            "timing_ms": response.get("timing_ms"),
        },
        "observations": observations,
        "attack_error": attack_result.get("error"),
        "execution_summary": _truncate_text(
            attack_result.get("execution_summary")
            or attack_result.get("summary")
            or agent_assessment.get("summary")
            or "",
            1000,
        ),
        "agent_assessment": {
            "confidence": agent_confidence,
            "verdict": _truncate_text(
                agent_assessment.get("verdict")
                or agent_assessment.get("assessment")
                or agent_assessment.get("reasoning")
                or "",
                800,
            ),
            "recommended_next_step": _truncate_text(
                agent_assessment.get("recommended_next_step") or "",
                500,
            ),
        },
        "evidence_refs": _normalize_evidence_refs(
            attack_result.get("evidence_refs")
            or attack_result.get("evidence_blobs")
            or []
        ),
        "out_of_scope": out_of_scope,
        "waf_blocked": waf_blocked,
        "payload_reflected": payload_reflected,
        "db_error": db_error,
        "timeout": timeout,
        "transport_error": transport_error,
        "explicit_success": explicit_success,
        "positive_observations": positive_obs,
        "confirm_hits": confirm_hits,
        "signal_score": signal_score,
        "candidate_vuln_type": candidate.get("vuln_type"),
    }

#최대 시도
def _max_attempts_reached(state: VerifierState) -> bool:
    ctx = state.get("attempt_context") or {}
    attempt_count = ctx.get("attempt_count")
    max_retries = ctx.get("max_retries")

    if attempt_count is None:
        attempt_count = state.get("normalized_result", {}).get("attempt_num")

    try:
        attempt_count = int(attempt_count)
        max_retries = int(max_retries)
    except (TypeError, ValueError):
        return False

    # attack_result는 이미 실행된 시도이므로, 같은 후보에 대한 다음 retry 가능 여부 판단은 >= 로 체크
    return attempt_count >= max_retries

#llm없이 규칙기반 다음행동 결정
def _heuristic_decision(state: VerifierState) -> dict:
    n = state["normalized_result"]
    signals = state["rule_signals"]

    if n.get("out_of_scope"):
        return {
            "next_action": "stop",
            "confidence": 0.99,
            "vuln_confirmed": False,
            "severity": "None",
            "evidence_summary": "공격 결과가 scope 위반으로 표시되어 검증을 중단합니다.",
            "false_positive_risk": "low",
            "stop_reason": "scope_violation",
            "verification_rationale": "scope policy",
            "next_attack_instruction": None,
        }

    if n.get("explicit_success") and n.get("positive_observations"):
        return {
            "next_action": "confirm",
            "confidence": 0.9,
            "vuln_confirmed": True,
            "severity": "High",
            "evidence_summary": "공격 실행 결과에 명시적 성공 신호와 강한 관측값이 포함되어 있습니다.",
            "false_positive_risk": "medium",
            "stop_reason": None,
            "verification_rationale": "explicit success + strong observations",
            "next_attack_instruction": None,
        }

    if n.get("db_error") and n.get("payload_reflected"):
        return {
            "next_action": "escalate",
            "confidence": 0.7,
            "vuln_confirmed": False,
            "severity": "Medium",
            "evidence_summary": "페이로드 반영 및 DB 에러 패턴이 관찰되었으나 확정 근거는 부족합니다.",
            "false_positive_risk": "medium",
            "stop_reason": None,
            "verification_rationale": "reflection + db error",
            "next_attack_instruction": None,
        }

    if n.get("waf_blocked"):
        return {
            "next_action": "retry",
            "confidence": 0.2,
            "vuln_confirmed": False,
            "severity": "None",
            "evidence_summary": "WAF/차단 응답으로 인해 취약점 여부를 판단하기 어렵습니다.",
            "false_positive_risk": "high",
            "stop_reason": None,
            "verification_rationale": "blocked by waf",
            "next_attack_instruction": {
                "goal": "차단 회피가 아니라, 정상적인 검증 신호를 확보할 수 있는 비파괴적 재검증",
                "focus": "입력 지점/컨텍스트 변경 후 동일 가설 검증",
                "evidence_to_collect": [
                    "요청/응답 원문",
                    "차단 패턴 일관성",
                    "애플리케이션 에러 메시지 유무",
                ],
                "constraints": ["scope 준수", "rate limit 준수", "파괴적 행위 금지"],
            },
        }

    if n.get("transport_error") and not n.get("response", {}).get("body_excerpt"):
        return {
            "next_action": "retry",
            "confidence": 0.1,
            "vuln_confirmed": False,
            "severity": "None",
            "evidence_summary": "응답 수집 실패(타임아웃/전송 오류)로 판정 불가입니다.",
            "false_positive_risk": "high",
            "stop_reason": None,
            "verification_rationale": "transport error",
            "next_attack_instruction": {
                "goal": "같은 가설에 대해 안정적인 응답 확보",
                "focus": "요청 최소화/타임아웃 조정/재현성 확인",
                "evidence_to_collect": ["응답 상태코드", "타이밍", "에러 종류"],
                "constraints": ["scope 준수", "rate limit 준수"],
            },
        }

    default_retry = {
        "next_action": "retry",
        "confidence": 0.15 if signals.get("signal_score", 0) <= 0 else 0.35,
        "vuln_confirmed": False,
        "severity": "None",
        "evidence_summary": "현재 증거만으로는 취약점 확정이 어렵습니다. 추가 검증이 필요합니다.",
        "false_positive_risk": "high",
        "stop_reason": None,
        "verification_rationale": "insufficient evidence",
        "next_attack_instruction": {
            "goal": "가설 반증 또는 재현 증거 강화",
            "focus": "다른 입력 지점/컨텍스트에서 동일 현상 비교",
            "evidence_to_collect": [
                "재현 가능한 요청/응답 쌍",
                "상태 변화 전후 비교",
                "오탐 배제를 위한 정상 입력 비교 결과",
            ],
            "constraints": ["scope 준수", "rate limit 준수", "파괴적 행위 금지"],
        },
    }

    if _max_attempts_reached(state):
        default_retry["next_action"] = "stop"
        default_retry["stop_reason"] = "max_attempts_reached"
        default_retry["verification_rationale"] = "retry exhausted"

    return default_retry


def _should_run_deep_eval(state: VerifierState) -> bool:
    if not _llm_available():
        return False

    n = state["normalized_result"]
    signal_score = int(state["rule_signals"].get("signal_score", 0))
    agent_confidence = _safe_float(n.get("agent_assessment", {}).get("confidence"), 0.0)
    has_body = bool(n.get("response", {}).get("body_excerpt"))
    status = int(n.get("response", {}).get("status") or 0)

    if state["mode"] == "standard":
        return has_body or signal_score > 0 or agent_confidence >= 0.2 or status >= 400

    # high_perf는 토큰 사용 줄이기
    return signal_score > 0 or agent_confidence >= 0.5 or status >= 500


def _sanitize_decision(raw: dict, fallback: dict) -> dict:
    result = dict(fallback)
    if not isinstance(raw, dict):
        result["llm_error"] = "invalid_decision_type"
        return result

    next_action = str(raw.get("next_action") or "").strip().lower()
    if next_action in ALLOWED_ACTIONS:
        result["next_action"] = next_action

    result["confidence"] = _clamp_01(raw.get("confidence", result.get("confidence", 0.0)))
    result["vuln_confirmed"] = bool(raw.get("vuln_confirmed", result.get("vuln_confirmed", False)))
    result["severity"] = str(raw.get("severity") or result.get("severity") or "None")
    result["evidence_summary"] = _truncate_text(
        raw.get("evidence_summary") or result.get("evidence_summary") or "",
        2000,
    )
    result["false_positive_risk"] = str(
        raw.get("false_positive_risk") or result.get("false_positive_risk") or "medium"
    ).lower()
    result["verification_rationale"] = _truncate_text(
        raw.get("verification_rationale") or result.get("verification_rationale") or "",
        1500,
    )

    stop_reason = raw.get("stop_reason")
    if stop_reason is not None:
        result["stop_reason"] = str(stop_reason)

    next_instr = raw.get("next_attack_instruction")
    if isinstance(next_instr, dict):
        result["next_attack_instruction"] = {
            "goal": _truncate_text(next_instr.get("goal"), 500),
            "focus": _truncate_text(next_instr.get("focus"), 500),
            "evidence_to_collect": [
                _truncate_text(item, 300)
                for item in (next_instr.get("evidence_to_collect") or [])
                if item is not None
            ][:10],
            "constraints": [
                _truncate_text(item, 300)
                for item in (next_instr.get("constraints") or [])
                if item is not None
            ][:10],
            "notes": _truncate_text(next_instr.get("notes"), 800),
        }

    return result


async def normalize_attack_result_node(state: VerifierState) -> dict:
    normalized = _normalize_attack_result(state["candidate"], state["attack_result"])
    return {
        "normalized_result": normalized,
        "rule_signals": {
            "signal_score": normalized["signal_score"],
            "confirm_hits": normalized["confirm_hits"],
            "strong_positive": bool(normalized["explicit_success"] or normalized["positive_observations"]),
            "waf_blocked": normalized["waf_blocked"],
            "out_of_scope": normalized["out_of_scope"],
            "transport_error": normalized["transport_error"],
        },
    }

#앞서 함수에서 심층분석 필요라고 판단되면 verify_node에서 이 함수를 호출해서 심층판정 수행. 
async def _deep_evaluate(state: VerifierState, fallback: dict) -> dict:
    n = state["normalized_result"]
    candidate = state["candidate"]
    ctx = state.get("attempt_context") or {}

    prompt = f"""당신은 웹 보안 검증용 Verifier 에이전트입니다.
역할은 "공격 실행"이 아니라, 공격 에이전트가 이미 수행한 실행 결과를 검토해
실제 취약점인지 판단하고 다음 행동을 결정하는 것입니다.

중요 규칙:
- retry가 필요하더라도 실제 익스플로잇 문자열/코드를 생성하지 마세요.
- 대신 다음 검증 목표, 수집해야 할 증거, 제약조건만 제안하세요.
- 허가된 보안 점검 상황이라는 전제입니다.

[Candidate]
{_json_dumps({
    "vuln_type": candidate.get("vuln_type"),
    "target_path": candidate.get("target_path"),
    "hypothesis": candidate.get("hypothesis"),
    "candidate_confidence": candidate.get("confidence"),
    "evidence_ref": candidate.get("evidence_ref"),
})}

[Attack Result (normalized)]
{_json_dumps(n)}

[Attempt Context]
{_json_dumps(ctx)}

[Rule Signals]
{_json_dumps(state.get("rule_signals") or {})}

다음 중 하나를 선택해 JSON으로만 응답하세요:
- confirm: 취약점 확정 (재현 가능한 근거 충분)
- retry: 공격 에이전트가 추가 검증 시도 필요
- escalate: 수동 검토 필요 (애매하지만 가능성 존재)
- stop: 더 이상 시도 무의미/정책상 중단

응답 JSON 스키마:
{{
  "next_action": "confirm|retry|escalate|stop",
  "confidence": 0.0,
  "vuln_confirmed": true,
  "severity": "Critical|High|Medium|Low|None",
  "evidence_summary": "근거 요약",
  "false_positive_risk": "low|medium|high",
  "verification_rationale": "왜 이런 판정을 했는지",
  "stop_reason": "stop인 경우 이유 (optional)",
  "next_attack_instruction": {{
    "goal": "retry일 때 검증 목표",
    "focus": "어떤 종류의 검증을 추가로 해야 하는지 (고수준)",
    "evidence_to_collect": ["증거1", "증거2"],
    "constraints": ["scope 준수", "rate limit 준수"],
    "notes": "선택사항"
  }}
}}"""

    try:
        raw = await _call_claude_json(prompt, model=REASONER_MODEL, max_tokens=1024)
        return _sanitize_decision(raw, fallback)
    except Exception as exc:
        degraded = dict(fallback)
        degraded["llm_error"] = _truncate_text(str(exc), 500)
        return degraded

#최종판정 컨ㅌ롤러
async def verify_node(state: VerifierState) -> dict:
    # attack_result 자체가 없으면 즉시 중단
    if not isinstance(state.get("attack_result"), dict) or not state["attack_result"]:
        decision = {
            "next_action": "stop",
            "confidence": 1.0,
            "vuln_confirmed": False,
            "severity": "None",
            "evidence_summary": "attack_result가 없어 verifier가 검증할 실행 결과가 없습니다.",
            "false_positive_risk": "low",
            "verification_rationale": "missing attack_result",
            "stop_reason": "missing_attack_result",
            "next_attack_instruction": None,
        }
        return {
            "next_action": "stop",
            "stop_reason": "missing_attack_result",
            "confidence": 1.0,
            "verifier_decision": decision,
        }

    fallback = _heuristic_decision(state)
    decision = fallback

    if _should_run_deep_eval(state):
        decision = await _deep_evaluate(state, fallback)

    # retry를 주더라도 외부 시도 한도 초과 시 stop으로 강제
    if decision["next_action"] == "retry" and _max_attempts_reached(state):
        decision["next_action"] = "stop"
        decision["stop_reason"] = "max_attempts_reached"
        decision["verification_rationale"] = _truncate_text(
            f'{decision.get("verification_rationale", "")}; retry exhausted',
            1500,
        )

    # scope 위반은 항상 stop 우선
    if state["normalized_result"].get("out_of_scope"):
        decision["next_action"] = "stop"
        decision["stop_reason"] = "scope_violation"
        decision["vuln_confirmed"] = False

    return {
        "next_action": decision["next_action"],
        "confidence": _clamp_01(decision.get("confidence")),
        "stop_reason": decision.get("stop_reason"),
        "verifier_decision": decision,
    }

#재시도일때 공격에이전트로 넘길 메세지 구성
async def prepare_next_action_node(state: VerifierState) -> dict:
    if state["next_action"] != "retry":
        return {"attack_guidance": None}

    decision = state.get("verifier_decision") or {}
    n = state["normalized_result"]
    instr = decision.get("next_attack_instruction") if isinstance(decision.get("next_attack_instruction"), dict) else {}

    attack_guidance = {
        "action": "retry",
        "message_type": "attack.retry.request",
        "candidate_ref": state["candidate"].get("evidence_ref"),
        "run_id": state["run_id"],
        "target_url": state["target_url"],
        "goal": instr.get("goal") or "추가 검증 시도",
        "focus": instr.get("focus") or "오탐 배제 또는 재현 증거 강화",
        "evidence_to_collect": instr.get("evidence_to_collect") or [
            "재현 가능한 요청/응답 쌍",
            "정상 입력 대비 차이",
            "상태 변화 전후 비교(있다면)",
        ],
        "constraints": instr.get("constraints") or [
            "scope 준수",
            "rate limit 준수",
            "파괴적 행위 금지",
        ],
        "notes": instr.get("notes") or "",
        "verifier_reasoning": _truncate_text(decision.get("verification_rationale"), 1000),
        "signal_snapshot": {
            "signal_score": state["rule_signals"].get("signal_score", 0),
            "confirm_hits": state["rule_signals"].get("confirm_hits", []),
            "waf_blocked": n.get("waf_blocked"),
            "payload_reflected": n.get("payload_reflected"),
            "db_error": n.get("db_error"),
        },
    }
    return {"attack_guidance": attack_guidance}

#confirm, escalate일때 db에 저장
async def record_finding_node(state: VerifierState) -> dict:
    decision = state.get("verifier_decision") or {}
    n = state["normalized_result"]
    linked_evidence_refs: List[dict] = []
    missing_evidence_refs: List[dict] = []

    try:
        run = await ScanRun.objects.aget(run_id=state["run_id"])
        db_finding = await Finding.objects.acreate(
            run=run,
            title=f"[{str(state['candidate'].get('vuln_type', 'unknown')).upper()}] {state['candidate'].get('target_path', '/')}",
            severity_raw=str(decision.get("severity") or "unknown").lower(),
            confidence=state["confidence"],
        )
        finding_id = str(db_finding.finding_id)

        for ref in n.get("evidence_refs", []):
            try:
                blob = await EvidenceBlob.objects.aget(blob_id=ref["blob_id"])
                await FindingEvidenceLink.objects.acreate(
                    finding=db_finding,
                    blob=blob,
                    role=ref.get("role") or "evidence",
                )
                linked_evidence_refs.append(ref)
            except EvidenceBlob.DoesNotExist:
                missing_evidence_refs.append(ref)
            except Exception:
                missing_evidence_refs.append(ref)

    except Exception:
        finding_id = None

    finding = {
        "finding_id": finding_id,
        "run_id": state["run_id"],
        "vuln_type": state["candidate"].get("vuln_type"),
        "target_path": state["candidate"].get("target_path"),
        "severity": decision.get("severity", "Unknown"),
        "confidence": state["confidence"],
        "status": "confirmed" if state["next_action"] == "confirm" else "escalated",
        "evidence_summary": decision.get("evidence_summary", ""),
        "false_positive_risk": decision.get("false_positive_risk", "unknown"),
        "verification_rationale": decision.get("verification_rationale", ""),
        "attack_attempt_id": n.get("attempt_id"),
        "attack_attempt_num": n.get("attempt_num"),
        "request_summary": n.get("request"),
        "response_summary": n.get("response"),
        "rule_signals": state.get("rule_signals"),
        "evidence_refs": n.get("evidence_refs", []),
        "linked_evidence_refs": linked_evidence_refs,
        "missing_evidence_refs": missing_evidence_refs,
        "candidate_evidence_ref": state["candidate"].get("evidence_ref"),
        "timestamp": _utcnow_iso(),
    }
    return {"finding": finding}


def route_after_verify(state: VerifierState) -> str:
    action = state["next_action"]
    if action in {"confirm", "escalate"}:
        return "record_finding"
    if action == "retry":
        return "prepare_next_action"
    return END


workflow = StateGraph(VerifierState)
workflow.add_node("normalize_attack_result", normalize_attack_result_node)
workflow.add_node("verify", verify_node)
workflow.add_node("prepare_next_action", prepare_next_action_node)
workflow.add_node("record_finding", record_finding_node)

workflow.set_entry_point("normalize_attack_result")
workflow.add_edge("normalize_attack_result", "verify")
workflow.add_conditional_edges(
    "verify",
    route_after_verify,
    {
        "record_finding": "record_finding",
        "prepare_next_action": "prepare_next_action",
        END: END,
    },
)
workflow.add_edge("prepare_next_action", END)
workflow.add_edge("record_finding", END)

verifier_app = workflow.compile()

#입력 검증 + 초기상태 구성 + 랭그래프 실행 + 결과 패키징 변환
async def run_verifier(
    candidate: Any,
    target_url: str,
    run_id: str,
    attack_result: Optional[dict] = None,
    mode: str = "standard",
    attempt_context: Optional[dict] = None,
) -> dict:
    """
    공격 에이전트가 이미 수행한 실행 결과(attack_result)를 검증한다.

    반환값(오케스트레이터/RabbitMQ publish payload로 사용 가능):
    {
      "next_action": "...",
      "confidence": 0.0,
      "stop_reason": "...",
      "verifier_decision": {...},
      "attack_guidance": {...}|None,   # retry 시
      "finding": {...}|None,           # confirm/escalate 시
      "rule_signals": {...},
      "normalized_result": {...}
    }
    """
    if mode not in {"standard", "high_perf"}:
        mode = "standard"

    if attack_result is None:
        raise ValueError(
            "Verifier는 공격을 직접 실행하지 않습니다. attack_result(공격 실행 결과)를 전달하세요."
        )

    normalized_candidate = _normalize_candidate(candidate)

    initial_state: VerifierState = {
        "run_id": run_id,
        "candidate": normalized_candidate,
        "target_url": target_url,
        "attack_result": attack_result,
        "mode": mode,
        "attempt_context": attempt_context or {},
        "normalized_result": {},
        "rule_signals": {},
        "next_action": "retry",
        "stop_reason": None,
        "confidence": 0.0,
        "verifier_decision": None,
        "attack_guidance": None,
        "finding": None,
    }

    final_state = await verifier_app.ainvoke(initial_state)
    return {
        "next_action": final_state.get("next_action"),
        "confidence": final_state.get("confidence", 0.0),
        "stop_reason": final_state.get("stop_reason"),
        "verifier_decision": final_state.get("verifier_decision"),
        "attack_guidance": final_state.get("attack_guidance"),
        "finding": final_state.get("finding"),
        "rule_signals": final_state.get("rule_signals"),
        "normalized_result": final_state.get("normalized_result"),
    }
