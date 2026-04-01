import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0004_scanrun_updated_at"),
    ]

    operations = [
        migrations.CreateModel(
            name="LLMTrace",
            fields=[
                ("trace_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("call_index", models.IntegerField(default=0)),
                ("stage", models.CharField(default="analysis", max_length=32)),
                ("model", models.CharField(blank=True, default="", max_length=64)),
                ("prompt_preview", models.TextField(blank=True, default="")),
                ("response_preview", models.TextField(blank=True, default="")),
                ("tool_calls", models.JSONField(blank=True, default=list)),
                ("stop_reason", models.CharField(blank=True, default="", max_length=64)),
                ("input_tokens", models.IntegerField(default=0)),
                ("output_tokens", models.IntegerField(default=0)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("error", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("scan_run", models.ForeignKey(on_delete=models.CASCADE, related_name="llm_traces", to="api.scanrun")),
            ],
            options={
                "db_table": "llm_traces",
                "ordering": ["-call_index", "-created_at"],
            },
        ),
    ]
