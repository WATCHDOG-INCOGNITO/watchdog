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

    run_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_url = models.TextField()
    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.HYBRID_LITE)
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

    embedding = VectorField(dimensions=1024, null=True, blank=True)
    embedding_model = models.CharField(max_length=64, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "payload_patterns"

    @property
    def success_rate(self):
        return self.times_succeeded / self.times_used if self.times_used else 0.0

    @property
    def fp_rate(self):
        return self.false_positive_count / self.times_used if self.times_used else 0.0

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
