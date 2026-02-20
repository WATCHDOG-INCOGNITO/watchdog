from django.db import models
import uuid


class ScopePolicy(models.Model):
    """
    views.py stub policy dict와 키 호환을 목표로 함.

    {
      "scope_policy_id": "...uuid...",
      "name": "...",
      "allowed_hosts": [...],
      "max_runs": int | None,
      "_created_runs": int
    }
    """
    scope_policy_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, default="default-policy")
    allowed_hosts = models.JSONField(default=list, blank=True)
    max_runs = models.IntegerField(null=True, blank=True)
    created_runs = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "scope_policy_id": str(self.scope_policy_id),
            "name": self.name,
            "allowed_hosts": self.allowed_hosts or [],
            "max_runs": self.max_runs,
            "_created_runs": int(self.created_runs or 0),
        }


class ScanRun(models.Model):
    """
    views.py stub run dict와 키 호환을 목표로 함.

    {
      "run_id": "...uuid...",
      "target_url": "...",
      "scope_policy_id": "...uuid..." | None,
      "status": "running"|"success"|"failed",
      "progress": int,
      "error_log": [ {error_type, subtype, message}, ... ]
    }
    """

    class Status(models.TextChoices):
        RUNNING = "running"
        SUCCESS = "success"
        FAILED = "failed"

    run_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_url = models.URLField()

    scope_policy = models.ForeignKey(
        ScopePolicy,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_runs",
        db_column="scope_policy_id",
    )

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.RUNNING)
    progress = models.IntegerField(default=0)
    error_log = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "run_id": str(self.run_id),
            "target_url": self.target_url,
            "scope_policy_id": str(self.scope_policy_id) if self.scope_policy_id else None,
            "status": self.status,
            "progress": int(self.progress or 0),
            "error_log": self.error_log or [],
        }


# =========================================================
# ✅ 아래부터: stub -> DB 전환용 모델들
# =========================================================

class RequestCatalogItem(models.Model):
    """
    run별로 발생한 HTTP 요청(시연/추후 확장용)
    """
    request_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="request_catalog_items",
        db_column="run_id",
    )

    method = models.CharField(max_length=16, default="GET")
    url = models.CharField(max_length=2048, default="/")
    headers = models.JSONField(default=dict, blank=True)

    # sent_at은 지금 단계에서 None 허용
    sent_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "request_id": str(self.request_id),
            "method": self.method,
            "url": self.url,
            "headers": self.headers or {},
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
        }


class Candidate(models.Model):
    """
    후보 취약점/가설(시연/추후 확장용)
    """
    candidate_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="candidates",
        db_column="run_id",
    )

    title = models.CharField(max_length=255, default="candidate")
    severity_raw = models.CharField(max_length=32, default="info")
    confidence = models.FloatField(default=0.0)

    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "candidate_id": str(self.candidate_id),
            "title": self.title,
            "severity_raw": self.severity_raw,
            "confidence": float(self.confidence or 0.0),
        }


class EvidenceBlob(models.Model):
    """
    증거(로그/파일/스크린샷 등) 메타
    storage_ref는 실제 저장소 경로/키를 가리키는 문자열
    """
    blob_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    content_type = models.CharField(max_length=255, default="text/plain")
    storage_ref = models.CharField(max_length=2048, default="stub://storage")

    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "blob_id": str(self.blob_id),
            "content_type": self.content_type,
            "storage_ref": self.storage_ref,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Finding(models.Model):
    """
    확정된 취약점(시연/추후 확장용)
    """
    finding_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="findings",
        db_column="run_id",
    )

    title = models.CharField(max_length=255, default="finding")
    severity_raw = models.CharField(max_length=32, default="info")
    confidence = models.FloatField(default=0.0)

    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "finding_id": str(self.finding_id),
            "title": self.title,
            "severity_raw": self.severity_raw,
            "confidence": float(self.confidence or 0.0),
        }


class FindingEvidenceLink(models.Model):
    """
    finding <-> evidence 연결 테이블
    """
    link_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name="evidence_links",
        db_column="finding_id",
    )

    blob = models.ForeignKey(
        EvidenceBlob,
        on_delete=models.CASCADE,
        related_name="finding_links",
        db_column="blob_id",
    )

    role = models.CharField(max_length=64, default="evidence")
    created_at = models.DateTimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return {
            "link_id": str(self.link_id),
            "finding_id": str(self.finding_id),
            "blob_id": str(self.blob_id),
            "role": self.role,
        }
