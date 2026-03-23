from rest_framework import serializers
from .models import (
    ScanRun, RequestCatalog, Candidate, Finding, EvidenceBlob,
    FindingEvidenceLink, AgentTask, VerificationLoop, Hypothesis,
    VisualAnalysis, IDORTestSession, WAFBypassAttempt,
    VulnerabilityEntry, PayloadPattern, ReportArchive,
)

class ScanRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRun
        fields = "__all__"
        read_only_fields = ["run_id", "created_at"]

class RequestCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RequestCatalog
        fields = "__all__"
        read_only_fields = ["req_id", "created_at"]

class CandidateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Candidate
        fields = "__all__"
        read_only_fields = ["cand_id", "created_at"]

class FindingSerializer(serializers.ModelSerializer):
    evidence_ids = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = "__all__"
        read_only_fields = ["finding_id", "created_at"]

    def get_evidence_ids(self, obj):
        return list(obj.evidence_links.values_list("blob_id", flat=True))

class EvidenceBlobSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvidenceBlob
        fields = "__all__"
        read_only_fields = ["blob_id", "created_at"]

class FindingEvidenceLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingEvidenceLink
        fields = "__all__"
        read_only_fields = ["link_id", "created_at"]

class AgentTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentTask
        fields = "__all__"
        read_only_fields = ["task_id", "created_at"]

class VerificationLoopSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationLoop
        fields = "__all__"
        read_only_fields = ["loop_id", "created_at"]

class HypothesisSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hypothesis
        fields = "__all__"
        read_only_fields = ["hypothesis_id", "created_at"]

class VisualAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = VisualAnalysis
        fields = "__all__"
        read_only_fields = ["analysis_id", "created_at"]

class IDORTestSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = IDORTestSession
        fields = "__all__"
        read_only_fields = ["session_id", "created_at"]

class WAFBypassAttemptSerializer(serializers.ModelSerializer):
    class Meta:
        model = WAFBypassAttempt
        fields = "__all__"
        read_only_fields = ["attempt_id", "created_at"]

class VulnerabilityEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityEntry
        fields = "__all__"
        read_only_fields = ["vuln_id", "created_at", "updated_at"]

class PayloadPatternSerializer(serializers.ModelSerializer):
    success_rate = serializers.ReadOnlyField()
    fp_rate = serializers.ReadOnlyField()

    class Meta:
        model = PayloadPattern
        fields = "__all__"
        read_only_fields = ["pattern_id", "created_at", "updated_at"]

class ReportArchiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportArchive
        fields = "__all__"
        read_only_fields = ["report_id", "created_at", "updated_at"]

