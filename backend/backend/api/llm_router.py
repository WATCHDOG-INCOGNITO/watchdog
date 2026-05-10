
import os
import json
import logging

from anthropic import Anthropic

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
client = None

ANALYZE_SYSTEM = (
    "You are a senior web application security analyst working only in an "
    "authorized internal test lab. Classify candidates carefully, prefer "
    "non-destructive validation paths, and return strict JSON."
)

PAYLOAD_SYSTEM = (
    "You are a web vulnerability verification planner for an authorized "
    "internal lab. Generate the smallest set of high-signal, non-destructive "
    "payloads needed to verify or refute one hypothesis. Prefer context-aware "
    "payloads over naive signatures."
)

RESPONSE_SYSTEM = (
    "You are a web security response analyst for an authorized internal lab. "
    "Use the response, timing, headers, and prior attempts to decide whether "
    "the current hypothesis is supported, disproved, or better explained by a "
    "different vulnerability family. Avoid repetitive next steps."
)

WAF_SYSTEM = (
    "You are a web security engineer evaluating blacklist-based request "
    "filters in an authorized internal lab. Suggest bounded, low-noise, "
    "non-destructive alternative encodings and context shifts."
)

VERDICT_SYSTEM = (
    "You are a senior application security consultant. Produce an evidence-led "
    "final verdict. If the evidence is incomplete, say so clearly instead of "
    "overstating confidence."
)


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
        

def _dump_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _call_llm(prompt: str, system: str = "", max_tokens: int = 1024) -> tuple[dict, dict]:
    c = get_client()
    kwargs = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    raw = ""
    try:
        resp = c.messages.create(**kwargs)
        raw = resp.content[0].text.strip()
        result = _parse_json(raw)
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
        return result, usage
    except json.JSONDecodeError:
        logger.error(f"JSON parse failed: {raw[:300]}")
        return {}, {}
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return {}, {}


def analyze_candidate(candidate_data: dict) -> dict:
    prompt = f"""Review one candidate from an authorized internal web security lab.

Request
- endpoint: {candidate_data.get('method', 'GET')} {candidate_data.get('endpoint', '/')}
- parameters: {_dump_json(candidate_data.get('params', {}))}
- vulnerability_type: {candidate_data.get('vuln_type', 'unknown')}
- hypothesis: {candidate_data.get('hypothesis', '')}
- features: {_dump_json(candidate_data.get('features', {}))}

Tasks
1. Classify the likely sink and parsing context.
2. Estimate whether the current evidence is strong, weak, or misleading.
3. Suggest up to 4 non-destructive validation ideas.
4. If the candidate is likely a false positive, prefer dismissal.
5. If the evidence better matches a different family, mention that in reasoning.

Return JSON only:
{{
  "risk_level": "high|medium|low|none",
  "confidence": 0.0,
  "analysis": "short evidence-led analysis",
  "suggested_payloads": ["idea 1", "idea 2"],
  "next_action": "verify|dismiss|escalate",
  "reasoning": "why this action is appropriate"
}}"""

    result, usage = _call_llm(prompt, system=ANALYZE_SYSTEM)
    if not result:
        return {
            "risk_level": "unknown",
            "confidence": 0.0,
            "analysis": "LLM analysis failed",
            "suggested_payloads": [],
            "next_action": "escalate",
            "_usage": usage,
            "_trace_prompt": prompt,
            "_trace_response_preview": "LLM analysis failed",
        }
    result["_usage"] = usage
    result["_trace_prompt"] = prompt
    result["_trace_response_preview"] = _dump_json({
        key: value for key, value in result.items() if not str(key).startswith("_")
    })
    return result


def batch_analyze_candidates(candidates_data: list, max_count: int = 10) -> list:
    results = []
    total_tokens = 0
    for i, cand in enumerate(candidates_data[:max_count]):
        logger.info(f"[{i + 1}/{min(len(candidates_data), max_count)}] analyze {cand.get('method')} {cand.get('endpoint')}")
        result = analyze_candidate(cand)
        result["candidate_index"] = i
        result["endpoint"] = cand.get("endpoint")
        result["vuln_type"] = cand.get("vuln_type")
        usage = result.get("_usage", {})
        total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        results.append(result)
    logger.info(f"Batch analysis complete: {len(results)} candidates, {total_tokens} tokens")
    return results


def generate_initial_payloads(vuln_type: str, endpoint: str, method: str, params: dict, context: dict = None) -> dict:
    prompt = f"""Plan the next validation payloads for one hypothesis in an authorized internal lab.

Input
- vulnerability_type: {vuln_type}
- endpoint: {method} {endpoint}
- parameters: {_dump_json(params)}
- context: {_dump_json(context or {})}

Global rules
1. Generate the minimum set of high-signal, non-destructive payloads.
2. Use at most 2 probe payloads, 2 confirm payloads, and 1 bounded follow-up payload.
3. Each payload must use a technically distinct technique.
4. Prefer context-aware payloads over naive signatures.
5. Never suggest destructive changes, persistence, exfiltration, or external callbacks.
6. If a blacklist or weak WAF is likely, prefer quote-less, attribute-aware, function-based, or encoding-aware alternatives.

Type-specific guidance
- SQLi: classify numeric vs string context first. For id-like numeric parameters behind a blacklist, first probes must stay within one scalar expression and avoid quotes, UNION, SELECT, semicolons, inline comments, OR, and AND. Strongly prefer quote-less CASE WHEN expressions, arithmetic rewrites, or bounded built-in function calls that can change rows, timing, or errors without changing state.
- XSS: identify whether the reflection is in HTML text, HTML attribute, inline script string, URL, or template-like context. If obvious tags are likely blocked, consider bounded breakout probes that target the exact context without relying on the most common blocked signatures.
- IDOR: prefer nearby identifiers or role-bounded object transitions. Avoid bulk enumeration.
- SSRF: use only safe internal sinks allowed in the lab and keep the scope narrow.

Return JSON only:
{{
  "strategy": "short attack strategy",
  "target_params": ["param1", "param2"],
  "stages": [
    {{
      "stage": "probe",
      "payloads": [
        {{
          "param": "parameter name",
          "value": "payload value",
          "method": "GET|POST",
          "description": "why this payload is useful",
          "success_indicator": {{
            "type": "body_contains|status_code|time_delay|body_diff|header_contains",
            "value": "expected evidence"
          }}
        }}
      ]
    }},
    {{
      "stage": "confirm",
      "payloads": []
    }},
    {{
      "stage": "extract",
      "payloads": []
    }}
  ]
}}"""

    result, usage = _call_llm(prompt, system=PAYLOAD_SYSTEM, max_tokens=2048)
    if not result:
        return {"strategy": "fallback", "target_params": list(params.keys())[:3], "stages": [], "_usage": usage}
    result["_usage"] = usage
    return result


def analyze_response_and_decide(
    vuln_type: str,
    endpoint: str,
    method: str,
    payload_sent: dict,
    response_data: dict,
    attempt_history: list = None,
) -> dict:
    history_str = ""
    if attempt_history:
        history_lines = []
        for h in attempt_history[-5:]:
            history_lines.append(
                f"- payload={str(h.get('payload', '?'))[:120]} "
                f"status={h.get('status_code', '?')} indicator={h.get('indicator_matched', False)}"
            )
        history_str = "\n".join(history_lines)

    prompt = f"""Analyze the latest validation response from an authorized internal lab and decide the next move.

Hypothesis
- vulnerability_type: {vuln_type}
- endpoint: {method} {endpoint}

Payload sent
- param: {payload_sent.get('param', '?')}
- value: {payload_sent.get('value', '?')}
- description: {payload_sent.get('description', '?')}
- success_indicator: {_dump_json(payload_sent.get('success_indicator', {}))}

Observed response
- status_code: {response_data.get('status_code', '?')}
- elapsed_seconds: {response_data.get('elapsed', '?')}
- content_length: {response_data.get('content_length', '?')}
- headers: {_dump_json(response_data.get('headers', {}))}
- body_excerpt:
{response_data.get('body', '')[:1500]}

Recent attempts
{history_str or "- none"}

Decision rules
1. If the current evidence already proves the hypothesis, use confirm.
2. If the current evidence strongly disproves the hypothesis, use abort.
3. If the response better matches a different vulnerability family, explain that and prefer pivot or abort instead of repeating the same idea.
4. Do not propose near-duplicate next payloads.
5. Keep next_payloads bounded, non-destructive, and technically distinct.

Return JSON only:
{{
  "vulnerable": true,
  "confidence": 0.0,
  "analysis": "what the response means",
  "evidence_found": "specific evidence",
  "next_action": "confirm|escalate|pivot|abort",
  "next_payloads": [
    {{
      "param": "parameter name",
      "value": "payload value",
      "method": "GET|POST",
      "description": "why this is the next step",
      "success_indicator": {{
        "type": "body_contains|status_code|time_delay|body_diff|header_contains",
        "value": "expected evidence"
      }}
    }}
  ],
  "reasoning": "why this next action is best"
}}"""

    result, usage = _call_llm(prompt, system=RESPONSE_SYSTEM, max_tokens=2048)
    if not result:
        return {
            "vulnerable": None,
            "confidence": 0.0,
            "analysis": "LLM response analysis failed",
            "next_action": "abort",
            "next_payloads": [],
            "_usage": usage,
        }
    result["_usage"] = usage
    return result


def mutate_payload_for_bypass(original_payload: str, vuln_type: str, blocked_response: str) -> dict:
    prompt = f"""A blacklist-based filter blocked a request in an authorized internal lab.

Input
- vulnerability_type: {vuln_type}
- original_payload: {original_payload}
- blocked_response_excerpt: {blocked_response[:500]}

Task
Generate 3 to 6 low-noise, non-destructive alternative payload variants that try a different encoding, parsing context, or syntax shape. Avoid trivial duplicates. Do not propose destructive or data-exfiltrating payloads.

Return JSON only:
{{
  "mutations": [
    {{
      "value": "mutated payload",
      "technique": "what changed",
      "description": "why this variant may bypass a weak blacklist"
    }}
  ]
}}"""

    result, usage = _call_llm(prompt, system=WAF_SYSTEM, max_tokens=1024)
    if not result:
        return {"mutations": [], "_usage": usage}
    result["_usage"] = usage
    return result


def make_final_verdict(vuln_type: str, endpoint: str, attempt_history: list) -> dict:
    history_summary = []
    for h in attempt_history:
        history_summary.append(
            {
                "payload": str(h.get("payload", ""))[:200],
                "status_code": h.get("status_code"),
                "elapsed": h.get("elapsed"),
                "indicator_matched": h.get("indicator_matched", False),
                "llm_analysis": str(h.get("llm_analysis", ""))[:200],
            }
        )

    prompt = f"""Produce a final evidence-led verdict for one authorized internal lab hypothesis.

Input
- vulnerability_type: {vuln_type}
- endpoint: {endpoint}
- attempts:
{_dump_json(history_summary)}

Return JSON only:
{{
  "verdict": "confirmed|likely|unlikely|not_vulnerable",
  "confidence": 0.0,
  "severity": "critical|high|medium|low|info",
  "summary": "short final summary",
  "reproduction_steps": "brief reproduction notes if confirmed",
  "evidence_summary": "most important evidence"
}}"""

    result, usage = _call_llm(prompt, system=VERDICT_SYSTEM, max_tokens=1024)
    if not result:
        return {
            "verdict": "unlikely",
            "confidence": 0.0,
            "severity": "info",
            "summary": "LLM verdict failed",
            "_usage": usage,
        }
    result["_usage"] = usage
    return result
