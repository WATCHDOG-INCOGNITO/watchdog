from django.urls import path
from . import views

urlpatterns = [
    # Health
    path("health/", views.health),

    # Scan Runs
    path("api/scan-runs/", views.create_scan_run),              # POST
    path("api/scan-runs/<str:run_id>/", views.get_scan_run),    # GET

    # Findings
    path("api/findings/", views.list_findings),                 # GET

    # Evidence Blobs
    path("api/evidence-blobs/", views.create_evidence_blob),    # POST

    # Request Catalog
    path("api/request-catalog/", views.create_request_catalog_item),  # POST
    path("api/request-catalog/list/", views.list_request_catalog),    # GET (?run_id=...)

    # Candidates
    path("api/candidates/", views.create_candidate),                  # POST
    path("api/candidates/list/", views.list_candidates),              # GET (?run_id=...)

    # Finding ↔ Evidence Links
    path("api/finding-evidence-links/", views.create_finding_evidence_link),  # POST
    path("api/finding-evidence-links/list/", views.list_finding_evidence_links),# GET (?finding_id=...)
]
