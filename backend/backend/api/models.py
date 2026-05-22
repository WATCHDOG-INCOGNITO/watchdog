import uuid
from django.db import models

try:
    from pgvector.django import VectorField
    _PGVECTOR_AVAILABLE = True
except ImportError:  # pgvector 미설치 환경 (로컬 lint 등)
    _PGVECTOR_AVAILABLE = False

    class VectorField(models.JSONField):  # type: ignore[no-redef]
        """pgvector 미설치 시 fallback. 실제 Docker 런타임에는 pgvector 사용."""

        def __init__(self, *args, dimensions: int = 1024, **kwargs):
            self.dimensions = dimensions
            kwargs.setdefault("null", True)
            kwargs.setdefault("blank", True)
            super().__init__(*args, **kwargs)

# Scan 관련

class ScanRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued"
        RUNNING = "running"
        FINISHED = "finished"
        FAILED = "failed"
        STOPPED = "stopped"

    class Mode(models.TextChoices):
        HYBRID_MAX = "hybrid-max"
        HYBRID_LITE = "hybrid-lite"
        DISCOVERY = "discovery"

    run_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_url = models.TextField()
    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.DISCOVERY)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    request_budget_total = models.IntegerField(default=10)
    request_budget_used = models.IntegerField(default=0)
    llm_calls_count = models.IntegerField(default=0)
    llm_tokens_used = models.IntegerField(default=0)
    llm_cost_usd = models.DecimalField(max_digits=10, decimal_places=4, default=0)

    config = models.JSONField(null=True, blank=True)
    error_log = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "scan_runs"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            fields = set(update_fields)
            fields.add("updated_at")
            kwargs["update_fields"] = list(fields)
        super().save(*args, **kwargs)


class LLMTrace(models.Model):
    trace_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="llm_traces")
    call_index = models.IntegerField(default=0)
    stage = models.CharField(max_length=32, default="analysis")
    model = models.CharField(max_length=64, blank=True, default="")
    prompt_preview = models.TextField(blank=True, default="")
    response_preview = models.TextField(blank=True, default="")
    tool_calls = models.JSONField(default=list, blank=True)
    stop_reason = models.CharField(max_length=64, blank=True, default="")
    input_tokens = models.IntegerField(default=0)
    output_tokens = models.IntegerField(default=0)
    metadata = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    target_node = models.ForeignKey(
        "DiscoveryNode",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="traces",
    )

    class Meta:
        db_table = "llm_traces"
        ordering = ["-call_index", "-created_at"]

class RequestCatalog(models.Model):
    req_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="requests")
    endpoint = models.TextField()
    method = models.CharField(max_length=10, default="GET")
    params = models.JSONField(default=dict, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=128, null=True, blank=True)
    headers = models.JSONField(null=True, blank=True)
    body_hash = models.CharField(max_length=64, null=True, blank=True)
    auth_required = models.BooleanField(default=False)
    sample_request = models.JSONField(null=True, blank=True)
    source = models.CharField(max_length=64, default="crawler")
    discovered_from = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "request_catalog"

class Candidate(models.Model):
    class DetectionStage(models.TextChoices):
        RULE = "rule"
        LLM_SCREEN = "llm_screen"
        LLM_DEEP = "llm_deep"

    class CandidateStatus(models.TextChoices):
        OPEN = "open"                # 초기 상태
        VERIFYING = "verifying"      # 검증 중
        CONFIRMED = "confirmed"      # 취약점 확정 → finding 생성됨
        FALSE_POSITIVE = "false_positive"  # 오탐
        DISMISSED = "dismissed"      # 무시/폐기

    cand_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="candidates")
    request = models.ForeignKey(RequestCatalog, on_delete=models.SET_NULL, null=True, blank=True, related_name="candidates")
    vuln_type = models.CharField(max_length=64, default="signal_stub")
    hypothesis = models.TextField(null=True, blank=True)
    priority_score = models.FloatField(default=0.0)
    detection_stage = models.CharField(max_length=16, choices=DetectionStage.choices, default=DetectionStage.RULE)
    status = models.CharField(max_length=16, choices=CandidateStatus.choices, default=CandidateStatus.OPEN)
    required_auth_context = models.JSONField(null=True, blank=True)
    features = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "candidates"
        ordering = ["-priority_score"]

class Finding(models.Model):
    class Severity(models.TextChoices):
        INFO = "info"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    finding_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="findings")
    candidate = models.ForeignKey(Candidate, on_delete=models.SET_NULL, null=True, blank=True, related_name="findings")
    title = models.CharField(max_length=256)
    vuln_type = models.CharField(max_length=64, null=True, blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.INFO)
    confidence = models.FloatField(default=0.0)
    summary = models.TextField(null=True, blank=True)
    reproduction_steps = models.TextField(null=True, blank=True)
    llm_analysis = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "findings"

class EvidenceBlob(models.Model):
    blob_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, null=True, blank=True, related_name="evidence_items")
    kind = models.CharField(max_length=32, default="log")
    storage_ref = models.TextField(default="local://dummy")
    content = models.TextField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, null=True, blank=True)
    byte_size = models.IntegerField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "evidence_blobs"

class FindingEvidenceLink(models.Model):
    link_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="evidence_links")
    blob = models.ForeignKey(EvidenceBlob, on_delete=models.CASCADE, related_name="finding_links")
    role = models.CharField(max_length=32, default="supporting")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "finding_evidence_links"

# 다중 에이전트 / 검증 루프 / 가설

class AgentTask(models.Model):
    class AgentType(models.TextChoices):
        PLANNER = "planner"
        SQLI = "sqli_agent"
        XSS = "xss_agent"
        IDOR = "idor_agent"
        UPLOAD = "upload_agent"
        SSRF = "ssrf_agent"

    class TaskStatus(models.TextChoices):
        PENDING = "pending"
        RUNNING = "running"
        COMPLETED = "completed"
        FAILED = "failed"

    task_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="agent_tasks")
    assigned_agent = models.CharField(max_length=32, choices=AgentType.choices)
    task_type = models.CharField(max_length=32)
    target_endpoint = models.TextField(null=True, blank=True)
    task_config = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=TaskStatus.choices, default=TaskStatus.PENDING)
    result_summary = models.JSONField(null=True, blank=True)
    parent_task = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True, related_name="subtasks")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "agent_tasks"
        ordering = ["-created_at"]

class VerificationLoop(models.Model):
    class NextAction(models.TextChoices):
        RETRY = "retry"
        ESCALATE = "escalate"
        ABORT = "abort"
        CONFIRMED = "confirmed"

    loop_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, related_name="loops")
    attempt_number = models.IntegerField(default=1)
    payload_sent = models.TextField(null=True, blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    response_body_hash = models.CharField(max_length=64, null=True, blank=True)
    analysis_result = models.JSONField(null=True, blank=True)
    next_action = models.CharField(max_length=16, choices=NextAction.choices, default=NextAction.RETRY)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "verification_loops"
        ordering = ["candidate", "attempt_number"]

class Hypothesis(models.Model):
    class Result(models.TextChoices):
        PENDING = "pending"
        CONFIRMED = "confirmed"
        REFUTED = "refuted"
        INCONCLUSIVE = "inconclusive"

    hypothesis_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, related_name="hypotheses")
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="hypotheses")
    description = models.TextField()
    test_plan = models.JSONField(null=True, blank=True)
    result = models.CharField(max_length=16, choices=Result.choices, default=Result.PENDING)
    evidence_ids = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "hypotheses"

class VisualAnalysis(models.Model):
    analysis_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="visual_analyses")
    page_url = models.TextField()
    screenshot_path = models.CharField(max_length=512, null=True, blank=True)
    identified_elements = models.JSONField(null=True, blank=True)
    functional_inferences = models.JSONField(null=True, blank=True)
    llm_provider = models.CharField(max_length=32, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "visual_analysis"

class IDORTestSession(models.Model):
    class Verdict(models.TextChoices):
        VULNERABLE = "vulnerable"
        SAFE = "safe"
        UNCERTAIN = "uncertain"

    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="idor_sessions")
    persona_a = models.JSONField()
    persona_b = models.JSONField()
    target_endpoint = models.TextField()
    response_status = models.IntegerField(null=True, blank=True)
    contains_sensitive_data = models.BooleanField(default=False)
    analysis_detail = models.JSONField(null=True, blank=True)
    verdict = models.CharField(max_length=16, choices=Verdict.choices, default=Verdict.UNCERTAIN)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "idor_test_sessions"
class WAFBypassAttempt(models.Model):
    class MutationType(models.TextChoices):
        ORIGINAL = "original"
        COMMENT_BYPASS = "comment_bypass"
        HEX_ENCODE = "hex_encode"
        CASE_MIX = "case_mix"
        DOUBLE_ENCODE = "double_encode"
        UNICODE = "unicode"

    attempt_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="waf_attempts")
    original_payload = models.TextField()
    mutated_payload = models.TextField()
    mutation_type = models.CharField(max_length=32, choices=MutationType.choices)
    waf_blocked = models.BooleanField(default=True)
    response_status = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "waf_bypass_attempts"

# Knowledge DB (3종 자산)

class VulnerabilityEntry(models.Model):
    vuln_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cwe_id = models.CharField(max_length=16, null=True, blank=True)
    owasp_category = models.CharField(max_length=64, null=True, blank=True)
    title = models.CharField(max_length=256)
    vuln_type = models.CharField(max_length=64)
    severity_default = models.CharField(max_length=16, default="medium")

    description = models.TextField(null=True, blank=True)
    preconditions = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    false_positive_hints = models.TextField(null=True, blank=True)
    evidence_points = models.TextField(null=True, blank=True)

    affected_components = models.JSONField(null=True, blank=True)
    references = models.JSONField(null=True, blank=True)
    tags = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "vulnerability_entries"

class PayloadPattern(models.Model):
    class SafetyLevel(models.TextChoices):
        SAFE = "safe"
        CAUTIOUS = "cautious"
        DESTRUCTIVE = "destructive"

    pattern_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(VulnerabilityEntry, on_delete=models.SET_NULL, null=True, blank=True, related_name="patterns")
    name = models.CharField(max_length=256)
    vuln_type = models.CharField(max_length=64)
    sub_technique = models.CharField(max_length=128, null=True, blank=True)

    category = models.CharField(max_length=64, default="detection")

    request_template = models.TextField(null=True, blank=True)
    matcher = models.JSONField(null=True, blank=True)
    safety_notes = models.TextField(null=True, blank=True)

    safety_level = models.CharField(max_length=16, choices=SafetyLevel.choices, default=SafetyLevel.SAFE)
    request_cost = models.IntegerField(default=1)
    requires_auth = models.BooleanField(default=False)
    target_context = models.JSONField(null=True, blank=True)

    mutation_type = models.CharField(max_length=32, default="original")
    parent_pattern = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True, related_name="mutations")

    times_used = models.IntegerField(default=0)
    times_succeeded = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)
    avg_llm_cost = models.DecimalField(max_digits=10, decimal_places=4, default=0)
    is_gold = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    source = models.CharField(max_length=64, null=True, blank=True)
    tags = models.JSONField(null=True, blank=True)

    embedding = VectorField(dimensions=768, null=True, blank=True)
    embedding_model = models.CharField(max_length=64, null=True, blank=True)

    # Living KB — host-specific learned 패턴
    # NULL이면 일반 patterns(seed 또는 generic mutation), 값이 있으면 그 host에서 통한 패턴
    target_host = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    # 학습 메타: 사용된 endpoint, oracle 결과, 응답 fingerprint 등
    attack_metadata = models.JSONField(null=True, blank=True)

    # SimHash dedup (XBOW pattern) — request_template 또는 attack_metadata.payload 의 64-bit fingerprint.
    # 같은 본질의 변종 페이로드를 100번 시도하는 낭비를 줄인다. NULL = 미계산(legacy).
    simhash = models.BigIntegerField(null=True, blank=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "payload_patterns"

    @property
    def success_rate(self):
        return self.times_succeeded / self.times_used if self.times_used else 0.0


class TargetProfile(models.Model):
    """Living KB — host별 누적 지식.
    같은 host 재스캔 시 Planner가 즉시 활용. CWE/OWASP commodity가 아닌
    이 host에 대한 사적 메모(framework, server, WAF, 통한 우회, 막힌 경로).
    """
    profile_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    host = models.CharField(max_length=255, unique=True, db_index=True)
    framework = models.CharField(max_length=128, null=True, blank=True)
    server = models.CharField(max_length=128, null=True, blank=True)
    waf = models.CharField(max_length=128, null=True, blank=True)
    fingerprint = models.JSONField(null=True, blank=True)  # response headers, tech detection 등
    notes = models.TextField(null=True, blank=True)        # 자유 메모

    # 통한 패턴/체인 카운트
    confirmed_findings_count = models.IntegerField(default=0)
    learned_patterns_count = models.IntegerField(default=0)
    dead_ends_count = models.IntegerField(default=0)

    last_scan_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "target_profiles"


class OOBHit(models.Model):
    """Out-of-band callback 수신 기록 — XSS bot, SSRF, RCE 등이 우리 서버를 hit 하면 저장.

    공격 페이로드가 외부 callback URL로 사용할 수 있게 backend에 `/oob/<token>/...` view 노출.
    공격이 admin bot 등을 통해 우리 endpoint를 hit하면 method/headers/query/body 전부 저장.
    Verifier 등이 oob_get_hits(token) 으로 폴링.
    """
    hit_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=128, db_index=True)
    method = models.CharField(max_length=16)
    path = models.TextField()
    query_string = models.TextField(null=True, blank=True)
    headers = models.JSONField(null=True, blank=True)
    body = models.TextField(null=True, blank=True)
    remote_addr = models.CharField(max_length=64, null=True, blank=True)
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "oob_hits"
        ordering = ["-received_at"]


class DeadEnd(models.Model):
    """Negative knowledge — 이 host/endpoint/vuln_type 조합에 시도했으나 실패한 패턴.
    다음 스캔에서 같은 시도 회피해 cost/turn 절약.
    """
    dead_end_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_host = models.CharField(max_length=255, db_index=True)
    endpoint = models.TextField()
    vuln_type = models.CharField(max_length=64)
    pattern_id = models.UUIDField(null=True, blank=True)  # PayloadPattern.pattern_id (옵션)
    payload_used = models.TextField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)  # "oracle returned false", "no diff" 등
    times_seen = models.IntegerField(default=1)
    # SimHash dedup — payload_used 의 64-bit fingerprint. 새 시도가 본질적으로 같은지 즉시 비교.
    simhash = models.BigIntegerField(null=True, blank=True, db_index=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "dead_ends"
        unique_together = [("target_host", "endpoint", "vuln_type", "pattern_id")]
    @property
    def fp_rate(self):
        return self.false_positive_count / self.times_used if self.times_used else 0.0


class EndpointSpec(models.Model):
    """API endpoint 명세 KB — host 별 endpoint 메타데이터 누적.

    PayloadPattern (technique/learned/cve) 가 *어떻게 공격할지* 라면, 이건
    *어디를 공격할지* 의 누적. 같은 host 재방문 시 RouteMap 이 정찰을
    skip 하고 바로 EntryPoint 단계로 진입 가능.

    Resume + EndpointSpec 활용 흐름:
      1. 첫 scan: EntryPoint 가 endpoint 분석 → record_endpoint_spec 호출
      2. 다음 scan: RouteMap 이 recall_target(host) → endpoint specs 받음 →
         재정찰 skip + EntryPoint 노드로 바로 시드
      3. 변화 감지: 같은 host 같은 endpoint 인데 response_shape 달라지면
         "변경됨" 표시 → 재분석 트리거
    """
    spec_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_host = models.CharField(max_length=255, db_index=True)
    method = models.CharField(max_length=8)
    endpoint = models.TextField()
    # endpoint param 명세 — JSON Schema-lite. 예: {"q": {"type":"str","in":"query","required":true}}
    params_schema = models.JSONField(null=True, blank=True)
    headers_required = models.JSONField(null=True, blank=True)  # ["Authorization", "X-CSRF"]
    auth_required = models.BooleanField(default=False)
    # 응답 구조: {"status_codes":[200,401], "content_types":["application/json"], "fields":["id","email"]}
    response_shape = models.JSONField(null=True, blank=True)
    # EntryPoint sub-agent 가 분석한 의심 vuln_type — KB의 "이 endpoint는 이 공격 받을 가능성"
    suspected_vuln_types = models.JSONField(null=True, blank=True)  # ["sqli", "xss"]
    # 코드/응답에서 식별한 sink hint
    sink_hints = models.JSONField(null=True, blank=True)  # ["db_query", "render_html", "include"]
    notes = models.TextField(null=True, blank=True)
    times_seen = models.IntegerField(default=1)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    embedding = VectorField(dimensions=768, null=True, blank=True)
    embedding_model = models.CharField(max_length=64, null=True, blank=True)

    class Meta:
        db_table = "endpoint_specs"
        unique_together = [("target_host", "method", "endpoint")]
        indexes = [
            models.Index(fields=["target_host", "last_seen_at"]),
        ]

    def __str__(self):
        return f"{self.method} {self.endpoint} @ {self.target_host}"


# Discovery Queue — 단서 축적형 탐색 트리

class DiscoveryNode(models.Model):
    """탐색 중 발견한 단서 하나. parent를 따라가면 exploit chain이 자동 재구성된다.

    Queue = DiscoveryNode.objects.filter(status="pending").order_by("-depth", "created_at")
    """

    class NodeType(models.TextChoices):
        TARGET = "target"
        ENDPOINT = "endpoint"
        VULN = "vuln"
        CLUE = "clue"
        EXPLOIT_STEP = "exploit_step"
        FLAG = "flag"
        DEAD_END = "dead_end"

    class Status(models.TextChoices):
        PENDING = "pending"
        EXPLORING = "exploring"
        EXPLORED = "explored"
        DEAD_END = "dead_end"
        CONFIRMED = "confirmed"

    node_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="discoveries")
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.CASCADE, related_name="children",
    )
    depth = models.IntegerField(default=0)

    node_type = models.CharField(max_length=32, choices=NodeType.choices)
    endpoint = models.CharField(max_length=512, null=True, blank=True)
    vuln_type = models.CharField(max_length=64, null=True, blank=True)
    summary = models.TextField()
    context = models.JSONField(default=dict, blank=True)

    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    worker_id = models.CharField(max_length=64, null=True, blank=True)
    queue_lane = models.CharField(max_length=32, default="hypothesis", blank=True)
    priority_score = models.FloatField(default=0.0)
    score_breakdown = models.JSONField(default=dict, blank=True)
    lease_owner = models.CharField(max_length=128, null=True, blank=True)
    leased_until = models.DateTimeField(null=True, blank=True)
    attempt_count = models.IntegerField(default=0)
    blocked_by = models.JSONField(default=list, blank=True)
    provider_hint = models.CharField(max_length=32, default="", blank=True)
    mission = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    explored_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "discovery_nodes"
        indexes = [
            models.Index(fields=["scan_run", "status", "-depth", "created_at"]),
            models.Index(fields=["scan_run", "status", "-priority_score", "-depth", "created_at"]),
            models.Index(fields=["scan_run", "queue_lane", "status", "-priority_score"]),
        ]


class WorkItem(models.Model):
    """Action queue item derived from artifacts such as DiscoveryNode.

    DiscoveryNode remains the audit/chain graph. WorkItem is the schedulable
    unit that a Claude, Codex, or deterministic worker leases and finalizes.
    """

    class WorkType(models.TextChoices):
        RECON = "recon"
        ENDPOINT_ANALYSIS = "endpoint_analysis"
        HYPOTHESIS_TEST = "hypothesis_test"
        PROOF = "proof"
        CHAIN = "chain"
        RECHECK = "recheck"
        REPORT = "report"

    class Status(models.TextChoices):
        PENDING = "pending"
        LEASED = "leased"
        DONE = "done"
        FAILED = "failed"
        BLOCKED = "blocked"
        CANCELLED = "cancelled"
        EXPIRED = "expired"

    work_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="work_items")
    node = models.ForeignKey(
        DiscoveryNode, on_delete=models.CASCADE, null=True, blank=True, related_name="work_items",
    )
    candidate = models.ForeignKey(
        Candidate, on_delete=models.SET_NULL, null=True, blank=True, related_name="work_items",
    )

    work_type = models.CharField(max_length=32, choices=WorkType.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    queue_lane = models.CharField(max_length=32, default="hypothesis", blank=True)
    objective = models.TextField(blank=True, default="")
    context = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)

    preconditions = models.JSONField(default=list, blank=True)
    expected_outputs = models.JSONField(default=list, blank=True)
    oracle = models.CharField(max_length=64, default="", blank=True)
    provider_hint = models.CharField(max_length=32, default="", blank=True)
    diversity_key = models.CharField(max_length=512, default="", blank=True)

    priority_score = models.FloatField(default=0.0)
    score_breakdown = models.JSONField(default=dict, blank=True)
    lease_owner = models.CharField(max_length=128, null=True, blank=True)
    leased_until = models.DateTimeField(null=True, blank=True)
    attempt_count = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "work_items"
        indexes = [
            models.Index(fields=["scan_run", "status", "-priority_score", "created_at"]),
            models.Index(fields=["scan_run", "queue_lane", "status", "-priority_score"]),
            models.Index(fields=["scan_run", "work_type", "status", "-priority_score"]),
            models.Index(fields=["scan_run", "diversity_key"]),
        ]


class AgentExchange(models.Model):
    """Structured handoff/debate message between subscription workers."""

    class Provider(models.TextChoices):
        CLAUDE = "claude"
        CODEX = "codex"
        DETERMINISTIC = "deterministic"
        HUMAN = "human"
        UNKNOWN = "unknown"

    class MessageType(models.TextChoices):
        CLAIM = "claim"
        QUESTION = "question"
        COUNTERARGUMENT = "counterargument"
        EVIDENCE = "evidence"
        DECISION = "decision"
        HANDOFF = "handoff"
        RECHECK_REQUEST = "recheck_request"
        CONSENSUS = "consensus"

    class Stance(models.TextChoices):
        SUPPORTS = "supports"
        DISPUTES = "disputes"
        BLOCKS = "blocks"
        NEUTRAL = "neutral"

    class ResolutionStatus(models.TextChoices):
        OPEN = "open"
        RESOLVED = "resolved"
        SUPERSEDED = "superseded"

    exchange_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="agent_exchanges")
    work = models.ForeignKey(
        WorkItem, on_delete=models.CASCADE, null=True, blank=True, related_name="agent_exchanges",
    )
    node = models.ForeignKey(
        DiscoveryNode, on_delete=models.CASCADE, null=True, blank=True, related_name="agent_exchanges",
    )
    parent_exchange = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="replies",
    )

    agent_name = models.CharField(max_length=128, blank=True, default="")
    provider = models.CharField(max_length=32, choices=Provider.choices, default=Provider.UNKNOWN)
    message_type = models.CharField(max_length=32, choices=MessageType.choices, default=MessageType.HANDOFF)
    stance = models.CharField(max_length=16, choices=Stance.choices, default=Stance.NEUTRAL)
    content = models.TextField()
    confidence = models.FloatField(default=0.0)
    evidence_refs = models.JSONField(default=list, blank=True)
    requested_action = models.CharField(max_length=64, blank=True, default="")
    resolution_status = models.CharField(
        max_length=16, choices=ResolutionStatus.choices, default=ResolutionStatus.OPEN,
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "agent_exchanges"
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["scan_run", "created_at"]),
            models.Index(fields=["scan_run", "provider", "message_type", "created_at"]),
            models.Index(fields=["scan_run", "work", "created_at"]),
            models.Index(fields=["scan_run", "node", "created_at"]),
            models.Index(fields=["scan_run", "resolution_status", "created_at"]),
        ]


class EvidenceNode(models.Model):
    """Normalized strategic fact used by the global queue composer.

    DiscoveryNode/Candidate/Finding/Trace remain the operational source of
    truth. EvidenceNode is the read model that lets the strategy brain reason
    over those artifacts without rewriting the Discovery Tree.
    """

    class Status(models.TextChoices):
        OBSERVED = "observed"
        CLAIMED = "claimed"
        VERIFIED = "verified"
        CONTRADICTED = "contradicted"
        STALE = "stale"
        DEAD_END = "dead_end"

    evidence_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="evidence_nodes")
    kind = models.CharField(max_length=64)
    subtype = models.CharField(max_length=64, blank=True, default="")
    semantic_key = models.CharField(max_length=512)
    title = models.CharField(max_length=512, blank=True, default="")
    summary = models.TextField(blank=True, default="")
    value_json = models.JSONField(default=dict, blank=True)
    scope_json = models.JSONField(default=dict, blank=True)
    auth_scope = models.CharField(max_length=128, blank=True, default="")
    confidence = models.FloatField(default=0.0)
    freshness = models.FloatField(default=1.0)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.OBSERVED)
    source_worker = models.CharField(max_length=128, blank=True, default="")
    provider = models.CharField(max_length=32, blank=True, default="")
    semantic_hash = models.CharField(max_length=64, blank=True, default="")
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "evidence_nodes"
        unique_together = [("scan_run", "semantic_key")]
        indexes = [
            models.Index(fields=["scan_run", "kind", "subtype"], name="evidence_no_scan_r_14888c_idx"),
            models.Index(fields=["scan_run", "status", "-confidence"], name="evidence_no_scan_r_404bfb_idx"),
            models.Index(fields=["scan_run", "semantic_hash"], name="evidence_no_scan_r_cf235a_idx"),
        ]


class EvidenceEdge(models.Model):
    edge_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="evidence_edges")
    src = models.ForeignKey(EvidenceNode, on_delete=models.CASCADE, related_name="out_edges")
    dst = models.ForeignKey(EvidenceNode, on_delete=models.CASCADE, related_name="in_edges")
    edge_type = models.CharField(max_length=64)
    weight = models.FloatField(default=1.0)
    rationale = models.TextField(blank=True, default="")
    created_by = models.CharField(max_length=64, blank=True, default="strategy")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "evidence_edges"
        unique_together = [("scan_run", "src", "dst", "edge_type")]
        indexes = [
            models.Index(fields=["scan_run", "edge_type"], name="evidence_ed_scan_r_dbb1a1_idx"),
            models.Index(fields=["scan_run", "active"], name="evidence_ed_scan_r_7613d6_idx"),
        ]


class PrimitiveInstance(models.Model):
    """Evidence-backed exploit capability extracted from the graph."""

    class Status(models.TextChoices):
        PROPOSED = "proposed"
        VERIFIED = "verified"
        CONTRADICTED = "contradicted"
        STALE = "stale"

    primitive_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="primitive_instances")
    category = models.CharField(max_length=64)
    name = models.CharField(max_length=256)
    endpoint = models.TextField(blank=True, default="")
    vuln_type = models.CharField(max_length=64, blank=True, default="")
    semantic_key = models.CharField(max_length=512)
    supporting_evidence_ids = models.JSONField(default=list, blank=True)
    contradicting_evidence_ids = models.JSONField(default=list, blank=True)
    preconditions_json = models.JSONField(default=list, blank=True)
    effects_json = models.JSONField(default=list, blank=True)
    auth_scope = models.CharField(max_length=128, blank=True, default="")
    confidence = models.FloatField(default=0.0)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PROPOSED)
    state_fingerprint = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "primitive_instances"
        unique_together = [("scan_run", "semantic_key")]
        indexes = [
            models.Index(fields=["scan_run", "category", "-confidence"], name="primitive_i_scan_r_ee62db_idx"),
            models.Index(fields=["scan_run", "status", "-confidence"], name="primitive_i_scan_r_70d37c_idx"),
        ]


class ChainCandidate(models.Model):
    """A composed attack path candidate over one or more primitives."""

    class Status(models.TextChoices):
        PROPOSED = "proposed"
        NEEDS_EVIDENCE = "needs_evidence"
        NEEDS_RECHECK = "needs_recheck"
        VERIFIED = "verified"
        REJECTED = "rejected"
        STALE = "stale"

    chain_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="chain_candidates")
    name = models.CharField(max_length=256)
    goal_type = models.CharField(max_length=64)
    semantic_key = models.CharField(max_length=512)
    chain_graph_json = models.JSONField(default=dict, blank=True)
    linearization_json = models.JSONField(default=list, blank=True)
    supporting_evidence_ids = models.JSONField(default=list, blank=True)
    primitive_ids = models.JSONField(default=list, blank=True)
    confidence_score = models.FloatField(default=0.0)
    impact_score = models.FloatField(default=0.0)
    execution_score = models.FloatField(default=0.0)
    total_score = models.FloatField(default=0.0)
    novelty_score = models.FloatField(default=0.0)
    cost_score = models.FloatField(default=0.0)
    missing_evidence_json = models.JSONField(default=list, blank=True)
    prerequisite_gap_json = models.JSONField(default=list, blank=True)
    contradiction_json = models.JSONField(default=list, blank=True)
    provider_hint = models.CharField(max_length=32, blank=True, default="")
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PROPOSED)
    rationale = models.TextField(blank=True, default="")
    last_promoted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "chain_candidates"
        unique_together = [("scan_run", "semantic_key")]
        indexes = [
            models.Index(fields=["scan_run", "status", "-total_score"], name="chain_candi_scan_r_778471_idx"),
            models.Index(fields=["scan_run", "goal_type", "-total_score"], name="chain_candi_scan_r_0ea487_idx"),
        ]


class StrategySnapshot(models.Model):
    snapshot_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="strategy_snapshots")
    top_chain_ids_json = models.JSONField(default=list, blank=True)
    queue_plan_json = models.JSONField(default=list, blank=True)
    rationale_md = models.TextField(blank=True, default="")
    graph_stats_json = models.JSONField(default=dict, blank=True)
    created_by = models.CharField(max_length=64, default="strategy_brain")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "strategy_snapshots"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan_run", "-created_at"], name="strategy_sn_scan_r_9fb13f_idx"),
        ]


class ReportArchive(models.Model):
    class ValidationStatus(models.TextChoices):
        UNVERIFIED = "unverified"
        VERIFIED = "verified"
        DISPUTED = "disputed"
        DUPLICATE = "duplicate"

    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(max_length=64)
    source_id = models.CharField(max_length=128, null=True, blank=True)
    source_url = models.TextField(null=True, blank=True)
    title = models.CharField(max_length=512)
    vuln_type = models.CharField(max_length=64, null=True, blank=True)
    severity = models.CharField(max_length=16, null=True, blank=True)
    target_program = models.CharField(max_length=256, null=True, blank=True)

    reproduction_steps = models.TextField(null=True, blank=True)
    evidence_summary = models.TextField(null=True, blank=True)
    env_conditions = models.TextField(null=True, blank=True)
    triage_comments = models.TextField(null=True, blank=True)

    has_public_poc = models.BooleanField(default=False)
    poc_urls = models.JSONField(null=True, blank=True)
    poc_code_stored = models.BooleanField(default=False)
    poc_hash = models.CharField(max_length=64, null=True, blank=True)

    validation_status = models.CharField(max_length=32, choices=ValidationStatus.choices, default=ValidationStatus.UNVERIFIED)
    bounty_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    disclosed_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    severity_history = models.JSONField(null=True, blank=True)
    lifecycle_events = models.JSONField(null=True, blank=True)
    attachments = models.JSONField(null=True, blank=True)
    tags = models.JSONField(null=True, blank=True)
    references = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "report_archives"
        unique_together = [("source", "source_id")]

# Report (P5)

class RunReport(models.Model):
    """Stored, reproducible report artifacts for a ScanRun (P5)."""

    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.OneToOneField(ScanRun, on_delete=models.CASCADE, related_name="report")

    markdown = models.TextField()
    json = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "run_reports"
