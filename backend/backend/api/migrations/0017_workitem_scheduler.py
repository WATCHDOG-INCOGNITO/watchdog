import uuid
import django.db.models.deletion
from django.db import migrations, models


def seed_work_items(apps, schema_editor):
    DiscoveryNode = apps.get_model("api", "DiscoveryNode")
    WorkItem = apps.get_model("api", "WorkItem")

    work_type_by_node = {
        "target": "recon",
        "endpoint": "endpoint_analysis",
        "vuln": "hypothesis_test",
        "clue": "hypothesis_test",
        "exploit_step": "chain",
        "flag": "proof",
        "dead_end": "report",
    }

    for node in DiscoveryNode.objects.filter(status__in=["pending", "exploring"]).iterator():
        work_type = work_type_by_node.get(node.node_type, "hypothesis_test")
        diversity_key = ":".join([
            work_type,
            (node.endpoint or "-")[:160].lower(),
            (node.vuln_type or "-")[:160].lower(),
            "-",
        ])
        WorkItem.objects.get_or_create(
            scan_run_id=node.scan_run_id,
            node_id=node.node_id,
            work_type=work_type,
            diversity_key=diversity_key,
            defaults={
                "status": "pending",
                "queue_lane": node.queue_lane or "hypothesis",
                "objective": (node.mission or {}).get("objective", node.summary or ""),
                "context": node.context or {},
                "preconditions": node.blocked_by or [],
                "expected_outputs": (node.mission or {}).get("success_criteria", []),
                "oracle": "",
                "provider_hint": node.provider_hint or "",
                "priority_score": node.priority_score or 0.0,
                "score_breakdown": node.score_breakdown or {},
                "max_attempts": 3,
            },
        )


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0016_discovery_queue_priority"),
    ]

    operations = [
        migrations.CreateModel(
            name="WorkItem",
            fields=[
                ("work_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("work_type", models.CharField(choices=[
                    ("recon", "Recon"),
                    ("endpoint_analysis", "Endpoint Analysis"),
                    ("hypothesis_test", "Hypothesis Test"),
                    ("proof", "Proof"),
                    ("chain", "Chain"),
                    ("recheck", "Recheck"),
                    ("report", "Report"),
                ], max_length=32)),
                ("status", models.CharField(choices=[
                    ("pending", "Pending"),
                    ("leased", "Leased"),
                    ("done", "Done"),
                    ("failed", "Failed"),
                    ("blocked", "Blocked"),
                    ("cancelled", "Cancelled"),
                    ("expired", "Expired"),
                ], default="pending", max_length=16)),
                ("queue_lane", models.CharField(blank=True, default="hypothesis", max_length=32)),
                ("objective", models.TextField(blank=True, default="")),
                ("context", models.JSONField(blank=True, default=dict)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("preconditions", models.JSONField(blank=True, default=list)),
                ("expected_outputs", models.JSONField(blank=True, default=list)),
                ("oracle", models.CharField(blank=True, default="", max_length=64)),
                ("provider_hint", models.CharField(blank=True, default="", max_length=32)),
                ("diversity_key", models.CharField(blank=True, default="", max_length=512)),
                ("priority_score", models.FloatField(default=0.0)),
                ("score_breakdown", models.JSONField(blank=True, default=dict)),
                ("lease_owner", models.CharField(blank=True, max_length=128, null=True)),
                ("leased_until", models.DateTimeField(blank=True, null=True)),
                ("attempt_count", models.IntegerField(default=0)),
                ("max_attempts", models.IntegerField(default=3)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("last_error", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("candidate", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="work_items", to="api.candidate")),
                ("node", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="work_items", to="api.discoverynode")),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="work_items", to="api.scanrun")),
            ],
            options={
                "db_table": "work_items",
                "indexes": [
                    models.Index(fields=["scan_run", "status", "-priority_score", "created_at"], name="work_items_scan_ru_fa8f5b_idx"),
                    models.Index(fields=["scan_run", "queue_lane", "status", "-priority_score"], name="work_items_scan_ru_b42b62_idx"),
                    models.Index(fields=["scan_run", "work_type", "status", "-priority_score"], name="work_items_scan_ru_bbb90a_idx"),
                    models.Index(fields=["scan_run", "diversity_key"], name="work_items_scan_ru_80da83_idx"),
                ],
            },
        ),
        migrations.RunPython(seed_work_items, migrations.RunPython.noop),
    ]
