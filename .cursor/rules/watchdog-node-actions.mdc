---
description: Watchdog 노드 타입별 상세 탐색 절차. Init(STEP 0) → Explorer Loop(STEP 1) → Finalize(STEP 2) 전체 실행 흐름 포함.
globs:
alwaysApply: false
---

# Watchdog Node Actions — 실행 절차

## STEP 0: Initialize (최초 1회)

```
1. create_scan(target_url, mode="discovery", budget=200) → SCAN_ID     [CLI]
2. recall_target(target_host) → prior knowledge                         [MCP]
3. create_root(scan_run_id, target_url) → ROOT_ID                      [CLI]
4. record_trace(call_index=1, stage="init",
     tool_calls=["create_scan","recall_target","create_root"])          [CLI]
```

---

## STEP 1: Orchestrated Explorer Loop (큐가 빌 때까지 반복)

```
WHILE true:
  1. scan_next(scan_run_id)                              [CLI]
     → EXPLORE: candidates 배열 + recommend(=0)
                · 0번이 BFS 정석 (depth 낮은 순)
                · 다른 후보가 더 가치 있다고 판단(예: parent confirmed 후속,
                  KB hit 많은 endpoint)하면 그것을 선택해도 OK
     → RESUME:   exploring 상태로 멈춘 노드 마저 진행
     → COMPLETE: 큐 비었음 → STEP 2로 이동

  2. update_node_status(선택한 node_id, "exploring")
  3. CONTEXT: get_chain_context + get_siblings + get_secrets + get_scan_notes
  4. EXPLORE: 아래 노드 타입별 절차 수행

  5. validate_node(node_id)  ← 🛡️ 진단 신호 [CLI]
     → passed=true  → finalize
     → passed=false → warnings 보고 판단:
                       · 진짜 빠진 작업이면 마저 수행
                       · 환경 제약(WAF/404/SPA로 child 0개)이면 mark_dead_end
                       · 무시해도 되는 경고면 그대로 finalize (selfcheck로 누적)

  6. FINALIZE: update_node_status(explored/confirmed/dead_end) + record_trace
```

> 🛡️ scan_next는 *후보 N개* 제공. LLM이 직접 선택. validate_node는 *진단*. 강제 게이트 아님.
> 자율성 우선: 도구는 신호 제공, 결정은 LLM.

---

## node_type = "target" (root)

**목표**: 엔드포인트 발견 → 자식 노드로 push

```
1. http_request(target_url) → 헤더, HTML, 리다이렉트 관찰
2. update_target_profile(target_host, framework, server)
3. add_scan_note(topic="architecture", content="...")
4. HTML 파싱 → 엔드포인트, JS, 폼, API 호출 추출
5. (white-box인 경우) list_source_tree → read_source → grep_source
6. 발견한 EACH 엔드포인트:
   a. push_discovery(parent=ROOT_ID, node_type="endpoint", endpoint="/path",
        summary="...", context_json={"methods":[...], "params":[...]})
   b. analyze_endpoint(endpoint, method, params)
   c. IF 취약점 의심 → create_candidate_manual(endpoint, vuln_type, hypothesis)
7. update_node_status(ROOT_ID, "explored")
8. record_trace(tool_calls=["http_request","update_target_profile",
     "add_scan_note","push_discovery","analyze_endpoint",
     "create_candidate_manual","update_node_status"])
```

---

## node_type = "endpoint"

**목표**: 취약점 유형 식별 → vuln 자식 노드로 push

```
1. analyze_endpoint(endpoint, method, params) → vuln_type scores
2. EACH 의심 vuln_type:
   a. push_discovery(parent=ENDPOINT_NODE_ID, node_type="vuln",
        vuln_type=TYPE, endpoint="/path",
        summary="Suspected X in ?param",
        context_json={"params":{...}, "evidence":"..."})
   b. create_candidate_manual(endpoint, vuln_type, hypothesis)
3. 의심 없음 → mark_dead_end(endpoint_node, "Clean after inspection")
4. update_node_status(ENDPOINT_NODE_ID, "explored")
5. record_trace(tool_calls=["analyze_endpoint","push_discovery",
     "create_candidate_manual","update_node_status"])
```

---

## node_type = "vuln"

**목표**: KB 패턴으로 테스트 → confirm 또는 dead_end

```
1. update_node_status(VULN_NODE_ID, "exploring")
2. search_knowledge(vuln_type) → technique_steps_md 읽기
3. recall_dead_ends(target_host, vuln_type, endpoint) → 실패 패턴 건너뛰기

4. EACH KB pattern / payload:
   a. technique_steps_md 순서대로 수행
   b. http_request(payload) 또는 http_session_request(session_id, payload)
   c. oracle_*(verify) → 결과 검증
   d. record_pattern_use(pattern_id, succeeded=true/false)  ← 매번!
   e. record_trace(stage="vuln_test", tool_calls=[...])

5. IF 확인됨:
   a. create_finding(scan_run_id, node_id, title, vuln_type, severity) → finding_id
   b. save_evidence(finding_id, kind="request", content="payload+응답")
   c. confirm_finding(cand_id, severity, title, summary)
   d. learn_from_finding(finding_id, target_host, payload_used, is_novel)
   e. update_node_status(VULN_NODE_ID, "confirmed")
   f. store_secret(...) ← credential 추출 시
   g. push_discovery(node_type="exploit_step", ...) ← 체이닝 큐 등록
   h. record_trace(tool_calls=["create_finding","save_evidence",
        "confirm_finding","learn_from_finding","update_node_status",
        "store_secret","push_discovery"])

6. IF 전부 실패:
   a. mark_dead_end(VULN_NODE_ID, "All N patterns failed")
   b. learn_dead_end(target_host, endpoint, vuln_type, payload_used, reason)
   c. record_trace(tool_calls=["mark_dead_end","learn_dead_end"])
```

---

## node_type = "exploit_step"

**목표**: 확인된 취약점으로 체이닝 → 추가 발견

```
1. get_chain_context → 현재까지 체인
2. get_secrets → 모든 credential
3. get_scan_notes → 아키텍처 컨텍스트
4. exploit 활용:
   - 탈취한 cred로 로그인 → 새 엔드포인트 발견
   - SSRF로 내부 서비스 → 내부 엔드포인트 발견
   - config 파일 읽기 → secret/clue 발견
5. EACH 새 발견:
   a. push_discovery(node_type="endpoint"/"clue", ...)
   b. analyze_endpoint(...) ← 엔드포인트인 경우
   c. create_candidate_manual(...) ← 분석 결과 있으면
6. store_secret(...) ← 새 credential 발견 시
7. update_node_status("confirmed" 또는 "explored")
8. record_trace(tool_calls=[...사용한 모든 도구...])
```

---

## node_type = "clue"

**목표**: 단서 조사 → 자식 노드 또는 dead_end

```
1. 단서 조사 (HTTP 요청, 소스 분석)
2. 유의미함 → push_discovery(자식 노드)
3. 무의미함 → mark_dead_end
4. update_node_status("explored")
5. record_trace(tool_calls=[...])
```

---

## node_type = "flag"

**목표**: 목표 달성 기록

```
1. create_finding(severity="critical", title="Flag Captured", summary="full chain")
2. save_evidence(finding_id, kind="response", content=FLAG_VALUE)
3. store_secret(key="flag", value=FLAG_VALUE)
4. confirm_finding(cand_id, ...)
5. learn_from_finding(is_novel=true/false)
6. update_node_status("confirmed")
7. record_trace(tool_calls=["create_finding","save_evidence","store_secret",
     "confirm_finding","learn_from_finding","update_node_status"])
```

---

## STEP 2: Finalize Scan

### 정상 완료 (큐 비어있음):
```
1. scan_selfcheck(scan_run_id)  ← 🛡️ 진단              [CLI]
   → errors 검토:
       · 데이터 손실 위험(예: confirmed인데 finding 0)이면 fix 후 재실행
       · 환경 제약/판단 결과면 그대로 진행 (보고서 limitations로 노출됨)
2. get_exploit_chains(scan_run_id)
3. get_scan_summary(run_id)
4. generate_report(scan_run_id)                          [MCP]
5. complete_scan(scan_run_id)                             [CLI] → finished
6. record_trace(stage="complete", tool_calls=[...])       [CLI]
```

> 🛡️ scan_selfcheck는 진단 신호. 강제 게이트 아님. errors가 있어도
> 보고서 'limitations' 섹션에 명시한 후 complete_scan 가능.

### 중단:
```
1. stop_scan(scan_run_id, reason="...")  [CLI] → stopped
2. record_trace(stage="stopped")         [CLI]
```

### 오류:
```
1. fail_scan(scan_run_id, error="...")   [CLI] → failed
2. record_trace(stage="failed")          [CLI]
```

---

## Chain Strategy

1. **공격 표면 파악** → 2. **프리미티브 식별** (read/write/execute/redirect) → 3. **조합**
4. credential → `store_secret`, 아키텍처 → `add_scan_note`
5. 모든 발견 → `push_discovery` → 큐

### Common Chains
- SSRF + LFI → internal file read
- SQLi + file_read → secret → auth bypass
- Auth bypass + IDOR → cross-user data
- Path traversal + config → cred → privilege escalation
- Deserialization → RCE
