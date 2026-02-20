from django.urls import path
from . import views

urlpatterns = [
    # Health
    path("health/", views.health),

    # Scan Runs (LIST+CREATE)
    path("api/scan-runs/", views.scan_runs),  # GET(list), POST(create)
    path("api/scan-runs/<str:run_id>/", views.get_scan_run),  # GET(detail)

    # Run-scoped convenience endpoints (권장 형태: /scan-runs/{run_id}/...)
    path("api/scan-runs/<str:run_id>/request-catalog/", views.list_request_catalog_by_run),
    path("api/scan-runs/<str:run_id>/candidates/", views.list_candidates_by_run),
    path("api/scan-runs/<str:run_id>/findings/", views.list_findings_by_run),

    # Findings (global list)
    path("api/findings/", views.list_findings),  # GET (전체 findings list)

    # Evidence Blobs
    path("api/evidence-blobs/", views.create_evidence_blob),  # POST

    # Request Catalog (기존 경로 유지)
    path("api/request-catalog/", views.create_request_catalog_item),        # POST
    path("api/request-catalog/list/", views.list_request_catalog),          # GET (?run_id=...)

    # Candidates (기존 경로 유지)
    path("api/candidates/", views.create_candidate),                        # POST
    path("api/candidates/list/", views.list_candidates),                    # GET (?run_id=...)

    # Finding ↔ Evidence Links (기존 경로 유지)
    path("api/finding-evidence-links/", views.create_finding_evidence_link),        # POST
    path("api/finding-evidence-links/list/", views.list_finding_evidence_links),   # GET (?finding_id=...)

    # Scope Policies (가능하면 생성까지)
    path("api/scope-policies/", views.scope_policies),                      # GET(list), POST(create)
    path("api/scope-policies/<str:scope_policy_id>/", views.get_scope_policy),  # GET(detail)
]
