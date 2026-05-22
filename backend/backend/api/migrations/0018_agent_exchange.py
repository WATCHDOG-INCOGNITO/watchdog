import uuid
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0017_workitem_scheduler"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentExchange",
            fields=[
                ("exchange_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("agent_name", models.CharField(blank=True, default="", max_length=128)),
                ("provider", models.CharField(choices=[
                    ("claude", "Claude"),
                    ("codex", "Codex"),
                    ("deterministic", "Deterministic"),
                    ("human", "Human"),
                    ("unknown", "Unknown"),
                ], default="unknown", max_length=32)),
                ("message_type", models.CharField(choices=[
                    ("claim", "Claim"),
                    ("question", "Question"),
                    ("counterargument", "Counterargument"),
                    ("evidence", "Evidence"),
                    ("decision", "Decision"),
                    ("handoff", "Handoff"),
                    ("recheck_request", "Recheck Request"),
                    ("consensus", "Consensus"),
                ], default="handoff", max_length=32)),
                ("stance", models.CharField(choices=[
                    ("supports", "Supports"),
                    ("disputes", "Disputes"),
                    ("blocks", "Blocks"),
                    ("neutral", "Neutral"),
                ], default="neutral", max_length=16)),
                ("content", models.TextField()),
                ("confidence", models.FloatField(default=0.0)),
                ("evidence_refs", models.JSONField(blank=True, default=list)),
                ("requested_action", models.CharField(blank=True, default="", max_length=64)),
                ("resolution_status", models.CharField(choices=[
                    ("open", "Open"),
                    ("resolved", "Resolved"),
                    ("superseded", "Superseded"),
                ], default="open", max_length=16)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("node", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="agent_exchanges", to="api.discoverynode")),
                ("parent_exchange", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="replies", to="api.agentexchange")),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="agent_exchanges", to="api.scanrun")),
                ("work", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="agent_exchanges", to="api.workitem")),
            ],
            options={
                "db_table": "agent_exchanges",
                "ordering": ["created_at"],
                "indexes": [
                    models.Index(fields=["scan_run", "created_at"], name="agent_exch_scan_ru_74f67a_idx"),
                    models.Index(fields=["scan_run", "provider", "message_type", "created_at"], name="agent_exch_scan_ru_35aa22_idx"),
                    models.Index(fields=["scan_run", "work", "created_at"], name="agent_exch_scan_ru_6fc118_idx"),
                    models.Index(fields=["scan_run", "node", "created_at"], name="agent_exch_scan_ru_90d710_idx"),
                    models.Index(fields=["scan_run", "resolution_status", "created_at"], name="agent_exch_scan_ru_47cad3_idx"),
                ],
            },
        ),
    ]
