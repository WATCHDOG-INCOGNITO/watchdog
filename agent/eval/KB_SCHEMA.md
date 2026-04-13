# Watchdog Knowledge Base — Schema 가이드 (팀 공용)

이 문서는 **다른 사람도 같은 뇌를 가지도록** 우리 KB에 어떤 데이터가 어떤 형태로 누적되는지 정리한다.

## 개요 — 4가지 KB 자원

| 자원 | 모델 | 무엇이 들어가나 | 누가 활용 |
|---|---|---|---|
| **Vulnerability catalog** | `VulnerabilityEntry` | OWASP/CWE 기본 카탈로그 (commodity) | LLM `search_knowledge(vuln_type)` |
| **Payload pattern** | `PayloadPattern` (source='seed') | sqlmap/dalfox 류 표준 페이로드 | `search_knowledge`, `retrieve_similar_patterns` |
| **Living KB — host-specific** | `PayloadPattern` (source='learned') + `TargetProfile` + `DeadEnd` | 우리 스캔에서 *실제로 통한* 페이로드 (host별), framework/server/WAF, 막힌 시도 | LLM `recall_target` / `recall_dead_ends` |
| **★ Exploit Technique (transferable trick)** | `PayloadPattern` (source='technique') | **문제 박제가 아닌** 일반화된 trick — *"이런 조건 보이면 이렇게 풀어라"* | LLM `search_knowledge`, `retrieve_similar_patterns` |

**핵심 통찰** — 우리 시스템의 차별화는 **★ Exploit Technique** 누적에서 나온다.
sqlmap이 매번 시도하는 `1' OR '1'='1`은 KB에 저장 가치 0이지만, *EXIF passthrough + safe_eval attribute chain* 같은 트릭은 진짜 자산.

---

## ★ Exploit Technique schema

`PayloadPattern.attack_metadata` JSON 필드에 다음 표준 구조:

```json
{
  "kind": "exploit_technique",
  "name": "EXIF passthrough — binary marker + JSON payload",
  "applies_when": "어떤 코드/응답에서 이 trick이 통하는지 자연어 (LLM이 매칭에 사용)",
  "prerequisites": [
    "필요 조건 1",
    "필요 조건 2"
  ],
  "technique_steps_md": "1. 단계 ...\n2. 단계 ...\n3. ...",
  "code_template": "import io, piexif\n... {placeholder} ...",
  "examples": [
    {
      "problem_id": "2024-combination",
      "captured_flag": "codegate2024{test}",
      "params": {"marker": "CODEGATE2024", "tag_used": "MakerNote"},
      "notes": "공식 정답은 UserComment 사용 — 동일 효과"
    }
  ],
  "tags": ["exif", "passthrough", "image_upload"]
}
```

`PayloadPattern` 행 자체에는:

| field | technique 값 |
|---|---|
| `source` | `"technique"` (필수 — 검색 필터 키) |
| `name` | snake_case 식별자 (예: `exif_passthrough_marker`) |
| `vuln_type` | 가장 가까운 클래스 (`code_injection`, `ssti`, `file_upload_quirk`, ...) |
| `category` | `"exploitation"` (보통) |
| `safety_level` | `safe` / `cautious` / `destructive` |
| `request_template` | 보통 빈 문자열 (technique은 단일 페이로드 아님) |
| `tags` | 짧은 키워드 배열 |
| `attack_metadata` | 위 표준 구조 |
| `embedding` | 자동 생성 (`name + applies_when + prerequisites + steps + tags` 임베딩) |

---

## 새 technique 추가 가이드

### 1) 어떤 chain에서 추출할지

`agent/eval/PROGRESS.md` 의 `flag_captured` 또는 `chain_sim_ok` 상태 문제에서 풀이 분석. 한 chain이 보통 2-4개 독립 trick으로 분해된다.

예 — 2024-combination chain은 두 trick으로 분해:
1. **EXIF passthrough marker** — JPEG 메타데이터에 임의 binary + JSON 박는 표준 기법
2. **safe_eval attribute chain** — Python eval/Jinja2 환경의 BLACKLIST 우회 attribute access

### 2) 일반화 (가장 중요)

**박제 X**: ❌ "ImageDescription = 'os.environ' 박고 TRACE /verify 호출"
**일반화 ✓**: ✅ "사용자 입력이 eval/safe_eval에 전달되면 attribute chain (`os.environ`, `__class__.__mro__`) 으로 dict/file 도달"

`applies_when` 작성 가이드:
- "어떤 sink에서" + "어떤 환경 조건이면" 적용 가능한지
- LLM이 *비슷한 패턴* 만나면 hit 하도록 핵심 키워드 포함 (eval, allowed_globals, attribute, BLACKLIST 등)

### 3) examples 누적

같은 technique이 다른 문제에 적용될 때마다 `examples` 배열에 한 항목 추가. 각 항목:
- `problem_id` — `2024-combination`, `2025-censored-board` 등
- `captured_flag` — 풀이 성공 시 (또는 null)
- `params` — 그 문제 특이 변수 (sink 이름, expr, 우회한 필터, output path 등)
- `notes` — 미세한 차이 / 정답과 비교

### 4) seed_techniques.py 에 추가

`backend/backend/api/management/commands/seed_techniques.py` 의 `TECHNIQUES` 리스트에 dict 한 개 추가 → `--reset` 플래그로 재시드.

```bash
docker compose exec backend python manage.py seed_techniques --reset
```

임베딩이 자동 갱신되어 `retrieve_similar_patterns(query="<자연어>")`가 hit.

---

## 다른 KB 자원 (참고)

### Living KB — host-specific learned

```python
# Verifier가 confirmed 시 자동:
learn_from_finding(
    finding_id="...",
    target_host="warmup",
    payload_used="<a id='download' href='javascript:...'>",
    is_novel=True,           # commodity sqlmap default 라면 False (저장 X)
    novelty_reason="DOM clobbering anchor + tel: quirk",
)
# → PayloadPattern(source='learned', target_host='warmup', ...) 한 행
```

```python
# 다음 스캔의 Planner:
recall_target(target_host="warmup")  # → 이 host의 learned patterns + dead_ends + framework/server/WAF
```

### Dead end (negative knowledge)

```python
learn_dead_end(
    target_host="warmup",
    endpoint="/login",
    vuln_type="sqli",
    pattern_id="<seed_uuid>",
    payload_used="' OR 1=1 --",
    reason="oracle_sqli_boolean returned false (length diff < 5%)",
)
```

다음 스캔 Executor의 `recall_dead_ends(target_host)` 가 회수 → 같은 시도 회피.

### Target profile

```python
update_target_profile(
    target_host="warmup",
    framework="PHP 7.4",
    server="apache",
    waf="",
    fingerprint_json='{"php_version":"7.4","cms":"custom"}',
    notes="iptables outgoing DROP",
)
```

---

## 검색 인터페이스 (LLM이 KB에 도달하는 방식)

| MCP 도구 | 검색 대상 | 사용 시점 |
|---|---|---|
| `search_knowledge(vuln_type, keyword, limit)` | 모든 PayloadPattern + VulnerabilityEntry, 키워드 부분 일치 | Planner가 가설 만들 때, Executor가 페이로드 변종 찾을 때 |
| `retrieve_similar_patterns(query, k, vuln_type)` | PayloadPattern, **Voyage 임베딩 cosine 유사도** | Planner가 자연어 query로 trick 찾을 때 (예: "BLACKLIST 우회 SSTI") |
| `recall_target(target_host)` | TargetProfile + 그 host의 learned PayloadPattern + DeadEnd | 모든 스캔 시작 시 |
| `recall_dead_ends(target_host, vuln_type, endpoint)` | DeadEnd 좁은 범위 | Executor 시도 직전 |

**Technique 검색**: `search_knowledge(keyword="attribute chain")` 또는 `retrieve_similar_patterns(query="filter bypass eval")` 호출하면 attack_metadata.kind='exploit_technique' 들이 hit. `attack_metadata.technique_steps_md` 와 `code_template` 을 LLM이 읽어 자기 페이로드 작성에 적용.

---

## 협업 — 같은 뇌 공유

현재 Living KB는 local Postgres. 협업자가 같은 KB 가지려면:

| 옵션 | 방법 | 비용 |
|---|---|---|
| Cloud SQL / Supabase | `DATABASE_URL` 환경변수만 cloud Postgres로 변경 → 모든 협업자 같은 backend 접속 | $7-30/월 |
| GCS dump 동기화 | `pg_dump > gs://watchdog-kb/dump-YYYY-MM-DD.sql` cron, 협업자 `pg_restore` | $0-1/월 |
| Git에 fixture 동기화 | `python manage.py dumpdata api.PayloadPattern api.TargetProfile api.DeadEnd > fixtures/kb.json` 커밋 | $0 |

(현재 권장 — git fixture 가장 단순. 큰 binary 없으면 충분.)

---

## 추가/수정 시 체크리스트

- [ ] technique 이름이 snake_case
- [ ] `applies_when` 에 LLM이 매칭할 핵심 키워드 포함
- [ ] `prerequisites` 가 *적용 조건* 명확
- [ ] `code_template` 에 `{placeholder}` 변수 표시
- [ ] 적어도 1개 `examples` (검증 안 된 기법은 추가 보류)
- [ ] `seed_techniques --reset` 으로 재시드
- [ ] (옵션) `VOYAGE_API_KEY` 있으면 임베딩 자동
- [ ] PROGRESS.md 의 해당 chain 줄에 *[추출 technique: name1, name2]* 표시
