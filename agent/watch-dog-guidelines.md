### 1. 아키텍쳐 요약

- 구조: Planner ↔ Manager ↔ Task Agents ↔ Verifier
- 역할 요약:
  - Planner: 탐색·우선순위 결정, 작업지시서 생성 (비공격성)
  - Manager: 스코프/정책 적용, 에이전트 라우팅, 승인/차단
  - Task Agents: 특정 취약점 검사(예: SQLi, XSS)
  - Verifier: 결과 판정·FP 억제 및 재현성 체크

---

### 2. 핵심 가드레일

1. **범위(Scope) 가드레일**

- 에이전트는 `target_url`의 호스트(및 명시적 허용목록 `ScopePolicy.allowed_hosts`) 외 도메인으로 요청을 보내지 말아야 한다.
- 외부 링크는 수집(메타)만 허용하고 접근 금지.
- 서브도메인은 `allowed_hosts`에 명시적으로 포함된 경우에만 접근 허용.

2. **행위(Action) 제한**

- DoS/DDoS, 대량 fuzzing/brute-force 자동 수행 금지.
- `DELETE`, `PUT` 등 파괴적/변형성 요청은 자동 실행 금지.
- 원격 코드 실행, 인증 우회 등 공격적 익스플로잇 실행 금지 — 관리자 승인 하에서만 제한적 시도 가능.

3. **단계별 역할 분리**

- Planner: 관찰·가설 수립만 수행, 페이로드 생성/실행 금지.
- Manager: 스코프·rate·정책 검토 및 Task Agent 승인/차단.
- Task Agents: Manager가 허가한 경우에만 비파괴적 요청을 수행.
- Verifier: 후보를 낮은 영향도 방식으로 재현·확인, 최종 확정은 관리자 승인 필요.

4. **출력 포맷 지정**

- 자동화 결과는 JSON으로 표준화하여 저장/전달하도록 함.
- (예상)필드: `target`, `run_id`, `phase`, `items[]`(각 item: `id`, `type`, `target_path`, `evidence`, `confidence`), `notes`.

5. **판단(Judgement)**

- 자동 보고 단계에서는 발견을 "candidate"(후보)로 표기. "confirmed" 전환은 Verifier와 관리자 승인 필요(개입이 필요하다고 판단 될 경우).

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
