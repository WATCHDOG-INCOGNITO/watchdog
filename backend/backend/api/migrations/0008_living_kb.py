import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0007_payload_pattern_embedding"),
    ]

    operations = [
        # PayloadPattern: host-specific learning
        migrations.AddField(
            model_name="payloadpattern",
            name="target_host",
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="payloadpattern",
            name="attack_metadata",
            field=models.JSONField(blank=True, null=True),
        ),
        # TargetProfile
        migrations.CreateModel(
            name="TargetProfile",
            fields=[
                ("profile_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("host", models.CharField(db_index=True, max_length=255, unique=True)),
                ("framework", models.CharField(blank=True, max_length=128, null=True)),
                ("server", models.CharField(blank=True, max_length=128, null=True)),
                ("waf", models.CharField(blank=True, max_length=128, null=True)),
                ("fingerprint", models.JSONField(blank=True, null=True)),
                ("notes", models.TextField(blank=True, null=True)),
                ("confirmed_findings_count", models.IntegerField(default=0)),
                ("learned_patterns_count", models.IntegerField(default=0)),
                ("dead_ends_count", models.IntegerField(default=0)),
                ("last_scan_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "target_profiles"},
        ),
        # DeadEnd
        migrations.CreateModel(
            name="DeadEnd",
            fields=[
                ("dead_end_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("target_host", models.CharField(db_index=True, max_length=255)),
                ("endpoint", models.TextField()),
                ("vuln_type", models.CharField(max_length=64)),
                ("pattern_id", models.UUIDField(blank=True, null=True)),
                ("payload_used", models.TextField(blank=True, null=True)),
                ("reason", models.TextField(blank=True, null=True)),
                ("times_seen", models.IntegerField(default=1)),
                ("last_seen_at", models.DateTimeField(auto_now=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "dead_ends",
                "unique_together": {("target_host", "endpoint", "vuln_type", "pattern_id")},
            },
        ),
    ]
