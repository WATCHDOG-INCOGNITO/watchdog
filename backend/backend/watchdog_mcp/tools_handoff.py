"""Role 간 handoff 종료 도구 (emit_*).

에이전트는 자유 텍스트로 JSON 코드블록을 출력해도 되고, 이 도구를 호출해
구조화된 종료 신호를 보내도 된다. 호출 시점·횟수 모두 에이전트 자율.

orchestrator(_run_role_phase)는 emit_* 호출을 감지하면 그 입력을 다음 role의
입력으로 사용하고 현재 role 루프를 종료한다.
"""
from __future__ import annotations

import json


def register(mcp):

    @mcp.tool()
    async def emit_hypotheses(hypotheses_json: str) -> str:
        """Planner가 정찰을 마치고 hypotheses를 ScanExecutor에 넘기는 종료 신호.

        호출은 선택. 자유 텍스트로 ```json {"hypotheses": [...]} ``` 코드블록을
        써도 동일하게 동작한다. 이 도구를 쓰면 파싱이 안정적이고 즉시 다음 role로 넘어간다.

        Args:
            hypotheses_json: '{"hypotheses": [...]}' 형태의 JSON 문자열.
                각 hypothesis는 {endpoint, method, param, vuln_type, rationale,
                candidate_pattern_ids?} 구조 권장. 빈 배열도 허용.
        """
        try:
            data = json.loads(hypotheses_json) if hypotheses_json else {"hypotheses": []}
        except Exception as e:
            return json.dumps({"error": f"hypotheses_json 파싱 실패: {e}"})
        return json.dumps({"emitted": "hypotheses", "data": data})

    @mcp.tool()
    async def emit_attempts(attempts_json: str) -> str:
        """ScanExecutor가 시도(attempts) 결과를 Verifier에 넘기는 종료 신호.

        Args:
            attempts_json: '{"attempts": [...]}' 형태. 각 attempt는
                {endpoint, vuln_type, pattern_id, matched, candidate_id, evidence_summary} 권장.
        """
        try:
            data = json.loads(attempts_json) if attempts_json else {"attempts": []}
        except Exception as e:
            return json.dumps({"error": f"attempts_json 파싱 실패: {e}"})
        return json.dumps({"emitted": "attempts", "data": data})

    @mcp.tool()
    async def emit_verdicts(verdicts_json: str) -> str:
        """Verifier가 verdicts를 orchestrator에 넘기는 종료 신호.

        Args:
            verdicts_json: '{"verdicts": [...]}' 형태. 각 verdict는
                {endpoint, vuln_type, verdict(confirmed|false_positive|inconclusive),
                 finding_id, candidate_id, citations: [...], needs_replan, replan_hint} 권장.
                citations는 tool 결과/응답 본문에서 인용한 짧은 발췌(2~5개 권장).
        """
        try:
            data = json.loads(verdicts_json) if verdicts_json else {"verdicts": []}
        except Exception as e:
            return json.dumps({"error": f"verdicts_json 파싱 실패: {e}"})
        return json.dumps({"emitted": "verdicts", "data": data})
