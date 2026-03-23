import json
from api.storage_service import (
    confirm_candidate as _confirm,
    dismiss_candidate as _dismiss,
    attach_evidence as _attach,
    get_finding_detail as _detail,
    get_scan_findings_summary as _summary,
    StorageError,
)

def register(mcp):

    @mcp.tool()
    def confirm_finding(cand_id: str, severity: str = "", title: str = "",
                        summary: str = "", evidence_json: str = "[]") -> str:
        """candidate를 취약점으로 확정하고 finding을 생성한다.
        severity: critical, high, medium, low, info
        evidence_json: 증거 목록 JSON. 예: '[{"kind": "request", "content": "..."}]'
        """
        try:
            evidence = json.loads(evidence_json) if evidence_json else []
        except json.JSONDecodeError:
            evidence = []

        try:
            result = _confirm(
                cand_id=cand_id,
                severity=severity or None,
                title=title or None,
                summary=summary or None,
                evidence_list=evidence or None,
            )
            return json.dumps(result)
        except StorageError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def dismiss_candidate(cand_id: str, reason: str = "false_positive") -> str:
        """candidate를 오탐/폐기 처리한다.
        reason: false_positive 또는 dismissed
        """
        try:
            result = _dismiss(cand_id=cand_id, reason=reason)
            return json.dumps(result)
        except StorageError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def save_evidence(finding_id: str, kind: str, content: str, role: str = "supporting") -> str:
        """finding에 증거를 추가한다.
        kind: request, response, log, screenshot
        role: primary, supporting
        """
        try:
            result = _attach(finding_id=finding_id, evidence_data={
                "kind": kind, "content": content, "role": role,
            })
            return json.dumps(result)
        except StorageError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_finding(finding_id: str) -> str:
        """finding 상세 정보와 증거를 조회한다."""
        try:
            result = _detail(finding_id=finding_id)
            return json.dumps(result)
        except StorageError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_scan_summary(run_id: str) -> str:
        """스캔 결과 요약 (severity별, vuln_type별 카운트 + finding 목록)."""
        result = _summary(run_id=run_id)
        return json.dumps(result)

    @mcp.tool()
    def auto_collect_evidence(finding_id: str, request_payload: str = "",
                              response_body: str = "", status_code: int = 0,
                              elapsed: float = 0.0, dom_snippet: str = "",
                              screenshot_base64: str = "", notes: str = "") -> str:
        """취약점 탐지 시 모든 증거를 한 번에 자동 수집·저장한다.
        finding 확정 후 이 도구를 호출하면 사람이 보고서만 보고도 판단 가능한 증거가 저장된다.

        finding_id: confirm_finding 반환값
        request_payload: 사용한 페이로드/요청 전문
        response_body: 서버 응답 본문 (처음 3000자 권장)
        status_code: HTTP 상태 코드
        elapsed: 응답 시간(초)
        dom_snippet: 취약점 관련 DOM 일부
        screenshot_base64: 스크린샷 base64 (browser_screenshot 결과)
        notes: 추가 메모
        """
        evidence_items = []

        if request_payload:
            evidence_items.append({
                "kind": "request", "role": "primary",
                "content": request_payload[:5000],
            })

        if response_body:
            evidence_items.append({
                "kind": "response", "role": "primary",
                "content": json.dumps({
                    "status_code": status_code,
                    "elapsed": elapsed,
                    "body": response_body[:3000],
                }, ensure_ascii=False),
            })

        if dom_snippet:
            evidence_items.append({
                "kind": "dom", "role": "supporting",
                "content": dom_snippet[:5000],
            })

        if screenshot_base64:
            evidence_items.append({
                "kind": "screenshot", "role": "supporting",
                "content": screenshot_base64[:100000],
            })

        if notes:
            evidence_items.append({
                "kind": "log", "role": "supporting",
                "content": notes,
            })

        saved = []
        for ev in evidence_items:
            try:
                result = _attach(finding_id=finding_id, evidence_data=ev)
                saved.append({"kind": ev["kind"], "role": ev["role"], "saved": True})
            except StorageError as e:
                saved.append({"kind": ev["kind"], "error": str(e)})

        return json.dumps({
            "finding_id": finding_id,
            "evidence_saved": len([s for s in saved if s.get("saved")]),
            "details": saved,
        })

