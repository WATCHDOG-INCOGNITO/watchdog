### 1. 아키텍쳐 요약

- 구조: Planner ↔ Manager ↔ Task Agents ↔ Verifier
- 역할 요약:
  - Planner: 탐색·우선순위 결정, 작업지시서 생성 (비공격성)
  - Manager: 스코프/정책 적용, 에이전트 라우팅, 승인/차단
  - Task Agents: 특정 취약점 검사(예: SQLi, XSS)
  - Verifier: 결과 판정·FP 억제 및 재현성 체크

---

### 2. 핵심 가드레일

1. **범위(Scope) 제한**

- 허용: `target_url`의 도메인(및 allowlist 서브도메인).
- 금지: 외부 도메인 요청. 단, 외부 링크 "기록"은 허용(접근 X).
- `scope_policies.in_scope_rules/out_of_scope_rules`로 정책 관리.

2. **행위 제한 (Action)**

- 금지:
  - 대량 fuzzing/브루트포스(예산 초과 시 중단)
  - 파괴적 요청(DELETE/PUT/PATCH 등은 정책 기반 허용/차단; 기본 차단 권장)
  - 서비스 가용성 저해(고빈도 요청, 대형 페이로드 반복 등)
- 허용:
  - 저강도 탐색(크롤링/일반 GET/HEAD)
  - 정책 기반 제한적 검증(낮은 cost_hint 패턴 우선)

3. **단계별 역할 제한**

- Planner: 관찰·가설 수립만 수행, 페이로드 생성/실행 금지.
- Manager: 스코프·rate·정책 검토 및 Task Agent 승인/차단.
- Task Agents: Manager가 허가한 경우에만 비파괴적 요청을 수행.
- Verifier: 후보를 낮은 영향도 방식으로 재현·확인, 최종 확정은 관리자 승인 필요.
- 자료수집 단계: 관찰/분석만. exploit/파괴적 시도 금지. "취약점 확정" 금지.
- 검증 단계: 후보 상위 K개만 제한적으로 검증. 증거 없으면 Confirmed 금지.

1. **출력 형식 지정(JSON 스키마)**

- 모든 노드는 "정형 JSON"으로 출력한다.
- (예상)필드: `target`, `run_id`, `phase`, `items[]`(각 item: `id`, `type`, `target_path`, `evidence`, `confidence`), `notes`.
- 누락 필드/스키마 불일치 시 파이프라인에서 실패 처리하고 재시도 정책 수행.

5. **판단 가드레일(Claim policy)**

- Confirmed는 `primary_proof` evidence가 존재하고, 재현 절차가 포함되어야만 가능.
- 그 외는 Likely/Hypothesis로만 표기.

---

### 3. 백엔드(현재 상태)와의 구체적 연동

- **엔드포인트 요약 (파일: `backend/api/urls.py`, `backend/api/views.py`)**
  - `GET /health/` — 헬스체크
  - `GET, POST /api/scan-runs/` — 스캔 실행 생성(POST) / 목록(GET)
  - `GET /api/scan-runs/{run_id}/` — 스캔 상태 조회
  - `GET /api/scan-runs/{run_id}/request-catalog/` — run별 요청 목록
  - `GET /api/scan-runs/{run_id}/candidates/` — run별 후보 목록
  - `GET /api/findings/` — 전체 findings 목록
  - `POST /api/evidence-blobs/` — 증거 메타 생성
  - `POST /api/request-catalog/` — 요청 항목 추가
  - `POST /api/candidates/` — 후보 추가
  - `POST /api/finding-evidence-links/` — finding ↔ evidence 연결
  - `GET/POST /api/scope-policies/`, `GET /api/scope-policies/{scope_policy_id}/` — 정책 조회/생성

- **모델/필드 (파일: `backend/api/models.py`) — Manager가 참고해야 할 필드**
  - `ScopePolicy`: `scope_policy_id`(uuid), `allowed_hosts`(list), `max_runs`(int|null), `created_runs`(int)
  - `ScanRun`: `run_id`(uuid), `target_url`, `scope_policy`(FK), `status` (`running|success|failed`), `progress`(int), `error_log`(list)
  - `RequestCatalogItem`: `request_id`, `method`, `url`, `headers`, `sent_at`
  - `Candidate` / `Finding`: `candidate_id`/`finding_id`, `title`, `severity_raw`, `confidence`
  - `EvidenceBlob`: `blob_id`, `content_type`, `storage_ref`

---

### 4. Manager 수행 체크리스트(~ing)

1. `target_url`의 호스트를 추출해 `ScopePolicy.allowed_hosts`와 일치 여부 확인.
2. `ScopePolicy.max_runs`가 있으면 `created_runs`와 비교하여 예산 초과 여부 판단.
3. 허용된 Task 종류(예: read-only 컬렉션, 응답 분석)는 정책에 포함할 것.
4. 정책 위반 시 에러 코드 매핑: `out_of_scope`→403, `rate_limit`→429, `parse_error`→400.

**[API 예시 (curl)]**

1. 스캔 실행 생성

```bash
curl -X POST http://localhost:8000/api/scan-runs/ \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://example.com","scope_policy_id":null}'
```

성공 응답(예시):

```json
{
  "data": {
    "run_id": "...",
    "target_url": "https://example.com",
    "status": "running",
    "progress": 30,
    "error_log": []
  },
  "meta": { "created": true }
}
```

2. 스캔 상태 조회

```bash
curl http://localhost:8000/api/scan-runs/<run_id>/
```

3. 후보(Candidate) 생성

```bash
curl -X POST http://localhost:8000/api/candidates/ \
  -H 'Content-Type: application/json' \
  -d '{"run_id":"<run_id>","title":"possible-xss","severity_raw":"low","confidence":0.2}'
```

4. 요청 카탈로그 추가

```bash
curl -X POST http://localhost:8000/api/request-catalog/ \
  -H 'Content-Type: application/json' \
  -d '{"run_id":"<run_id>","method":"GET","url":"/login","headers":{}}'
```

5. 증거 메타 생성

```bash
curl -X POST http://localhost:8000/api/evidence-blobs/ \
  -H 'Content-Type: application/json' \
  -d '{"content_type":"text/plain","storage_ref":"stub://path/to/evidence"}'
```

### +@.권장 출력 스키마 (Agent → Manager / DB 저장용)

```json
{
  "run_id": "...",
  "phase": "planning|task|verification",
  "items": [
    {
      "id": "...",
      "type": "xss",
      "target_path": "/login",
      "evidence": "escaped-or-storage-ref",
      "confidence": 0.25,
      "notes": "short rationale"
    }
  ]
}
```
