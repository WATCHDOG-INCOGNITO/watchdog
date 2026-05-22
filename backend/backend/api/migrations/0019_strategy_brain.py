import uuid
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0018_agent_exchange"),
    ]

    operations = [
        migrations.CreateModel(
            name="EvidenceNode",
            fields=[
                ("evidence_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("kind", models.CharField(max_length=64)),
                ("subtype", models.CharField(blank=True, default="", max_length=64)),
                ("semantic_key", models.CharField(max_length=512)),
                ("title", models.CharField(blank=True, default="", max_length=512)),
                ("summary", models.TextField(blank=True, default="")),
                ("value_json", models.JSONField(blank=True, default=dict)),
                ("scope_json", models.JSONField(blank=True, default=dict)),
                ("auth_scope", models.CharField(blank=True, default="", max_length=128)),
                ("confidence", models.FloatField(default=0.0)),
                ("freshness", models.FloatField(default=1.0)),
                ("status", models.CharField(choices=[
                    ("observed", "Observed"),
                    ("claimed", "Claimed"),
                    ("verified", "Verified"),
                    ("contradicted", "Contradicted"),
                    ("stale", "Stale"),
                    ("dead_end", "Dead End"),
                ], default="observed", max_length=32)),
                ("source_worker", models.CharField(blank=True, default="", max_length=128)),
                ("provider", models.CharField(blank=True, default="", max_length=32)),
                ("semantic_hash", models.CharField(blank=True, default="", max_length=64)),
                ("first_seen_at", models.DateTimeField(auto_now_add=True)),
                ("last_seen_at", models.DateTimeField(auto_now=True)),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="evidence_nodes", to="api.scanrun")),
            ],
            options={
                "db_table": "evidence_nodes",
                "indexes": [
                    models.Index(fields=["scan_run", "kind", "subtype"], name="evidence_no_scan_r_14888c_idx"),
                    models.Index(fields=["scan_run", "status", "-confidence"], name="evidence_no_scan_r_404bfb_idx"),
                    models.Index(fields=["scan_run", "semantic_hash"], name="evidence_no_scan_r_cf235a_idx"),
                ],
                "unique_together": {("scan_run", "semantic_key")},
            },
        ),
        migrations.CreateModel(
            name="ChainCandidate",
            fields=[
                ("chain_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=256)),
                ("goal_type", models.CharField(max_length=64)),
                ("semantic_key", models.CharField(max_length=512)),
                ("chain_graph_json", models.JSONField(blank=True, default=dict)),
                ("linearization_json", models.JSONField(blank=True, default=list)),
                ("supporting_evidence_ids", models.JSONField(blank=True, default=list)),
                ("primitive_ids", models.JSONField(blank=True, default=list)),
                ("confidence_score", models.FloatField(default=0.0)),
                ("impact_score", models.FloatField(default=0.0)),
                ("execution_score", models.FloatField(default=0.0)),
                ("total_score", models.FloatField(default=0.0)),
                ("novelty_score", models.FloatField(default=0.0)),
                ("cost_score", models.FloatField(default=0.0)),
                ("missing_evidence_json", models.JSONField(blank=True, default=list)),
                ("prerequisite_gap_json", models.JSONField(blank=True, default=list)),
                ("contradiction_json", models.JSONField(blank=True, default=list)),
                ("provider_hint", models.CharField(blank=True, default="", max_length=32)),
                ("status", models.CharField(choices=[
                    ("proposed", "Proposed"),
                    ("needs_evidence", "Needs Evidence"),
                    ("needs_recheck", "Needs Recheck"),
                    ("verified", "Verified"),
                    ("rejected", "Rejected"),
                    ("stale", "Stale"),
                ], default="proposed", max_length=32)),
                ("rationale", models.TextField(blank=True, default="")),
                ("last_promoted_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="chain_candidates", to="api.scanrun")),
            ],
            options={
                "db_table": "chain_candidates",
                "indexes": [
                    models.Index(fields=["scan_run", "status", "-total_score"], name="chain_candi_scan_r_778471_idx"),
                    models.Index(fields=["scan_run", "goal_type", "-total_score"], name="chain_candi_scan_r_0ea487_idx"),
                ],
                "unique_together": {("scan_run", "semantic_key")},
            },
        ),
        migrations.CreateModel(
            name="PrimitiveInstance",
            fields=[
                ("primitive_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("category", models.CharField(max_length=64)),
                ("name", models.CharField(max_length=256)),
                ("endpoint", models.TextField(blank=True, default="")),
                ("vuln_type", models.CharField(blank=True, default="", max_length=64)),
                ("semantic_key", models.CharField(max_length=512)),
                ("supporting_evidence_ids", models.JSONField(blank=True, default=list)),
                ("contradicting_evidence_ids", models.JSONField(blank=True, default=list)),
                ("preconditions_json", models.JSONField(blank=True, default=list)),
                ("effects_json", models.JSONField(blank=True, default=list)),
                ("auth_scope", models.CharField(blank=True, default="", max_length=128)),
                ("confidence", models.FloatField(default=0.0)),
                ("status", models.CharField(choices=[
                    ("proposed", "Proposed"),
                    ("verified", "Verified"),
                    ("contradicted", "Contradicted"),
                    ("stale", "Stale"),
                ], default="proposed", max_length=32)),
                ("state_fingerprint", models.CharField(blank=True, default="", max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="primitive_instances", to="api.scanrun")),
            ],
            options={
                "db_table": "primitive_instances",
                "indexes": [
                    models.Index(fields=["scan_run", "category", "-confidence"], name="primitive_i_scan_r_ee62db_idx"),
                    models.Index(fields=["scan_run", "status", "-confidence"], name="primitive_i_scan_r_70d37c_idx"),
                ],
                "unique_together": {("scan_run", "semantic_key")},
            },
        ),
        migrations.CreateModel(
            name="StrategySnapshot",
            fields=[
                ("snapshot_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("top_chain_ids_json", models.JSONField(blank=True, default=list)),
                ("queue_plan_json", models.JSONField(blank=True, default=list)),
                ("rationale_md", models.TextField(blank=True, default="")),
                ("graph_stats_json", models.JSONField(blank=True, default=dict)),
                ("created_by", models.CharField(default="strategy_brain", max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="strategy_snapshots", to="api.scanrun")),
            ],
            options={
                "db_table": "strategy_snapshots",
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["scan_run", "-created_at"], name="strategy_sn_scan_r_9fb13f_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="EvidenceEdge",
            fields=[
                ("edge_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("edge_type", models.CharField(max_length=64)),
                ("weight", models.FloatField(default=1.0)),
                ("rationale", models.TextField(blank=True, default="")),
                ("created_by", models.CharField(blank=True, default="strategy", max_length=64)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("dst", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="in_edges", to="api.evidencenode")),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="evidence_edges", to="api.scanrun")),
                ("src", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="out_edges", to="api.evidencenode")),
            ],
            options={
                "db_table": "evidence_edges",
                "indexes": [
                    models.Index(fields=["scan_run", "edge_type"], name="evidence_ed_scan_r_dbb1a1_idx"),
                    models.Index(fields=["scan_run", "active"], name="evidence_ed_scan_r_7613d6_idx"),
                ],
                "unique_together": {("scan_run", "src", "dst", "edge_type")},
            },
        ),
    ]
