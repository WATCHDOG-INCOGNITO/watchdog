from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r"tasks", views.AgentTaskViewSet, basename="tasks")
router.register(r"verification-loops", views.VerificationLoopViewSet, basename="verification-loops")
router.register(r"hypotheses", views.HypothesisViewSet, basename="hypotheses")
router.register(r"vulnerabilities", views.VulnerabilityEntryViewSet, basename="vulnerabilities")
router.register(r"patterns", views.PayloadPatternViewSet, basename="patterns")
router.register(r"report-archives", views.ReportArchiveViewSet, basename="report-archives")

urlpatterns = [
    path("health/", views.health),

    path("api/scan-runs/", views.scan_runs),
    path("api/scan-runs/<str:run_id>/", views.get_scan_run),
    path("api/scan-runs/<str:run_id>/start/", views.start_scan),
    path("api/scan-runs/<str:run_id>/summary/", views.scan_findings_summary),
    path("api/scan-runs/<str:run_id>/llm-analyze/", views.llm_analyze_candidates),
    path("api/scan-runs/<str:run_id>/verify/", views.start_verification),
    path("api/scan-runs/<str:run_id>/report/", views.scan_run_report),

    path("api/request-catalog/", views.create_request_catalog_item),
    path("api/request-catalog/list/", views.list_request_catalog),

    path("api/candidates/", views.create_candidate),
    path("api/candidates/list/", views.list_candidates),
    path("api/candidates/<str:cand_id>/", views.get_candidate),
    path("api/candidates/<str:cand_id>/confirm/", views.confirm_candidate),
    path("api/candidates/<str:cand_id>/dismiss/", views.dismiss_candidate),
    path("api/candidates/<str:cand_id>/verify/", views.verify_single_candidate),
    path("api/candidates/<str:cand_id>/loops/", views.list_verification_loops),

    path("api/findings/", views.list_findings),
    path("api/findings/<str:finding_id>/", views.get_finding),
    path("api/findings/<str:finding_id>/detail/", views.finding_detail),
    path("api/findings/<str:finding_id>/evidence/", views.attach_evidence),

    path("api/evidence-blobs/", views.create_evidence_blob),
    path("api/finding-evidence-links/", views.create_finding_evidence_link),
    path("api/finding-evidence-links/list/", views.list_finding_evidence_links),

    path("api/llm/analyze/", views.llm_analyze_single),

    path("api/v1/", include(router.urls)),
]
