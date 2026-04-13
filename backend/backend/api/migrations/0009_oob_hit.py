import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0008_living_kb"),
    ]

    operations = [
        migrations.CreateModel(
            name="OOBHit",
            fields=[
                ("hit_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("token", models.CharField(db_index=True, max_length=128)),
                ("method", models.CharField(max_length=16)),
                ("path", models.TextField()),
                ("query_string", models.TextField(blank=True, null=True)),
                ("headers", models.JSONField(blank=True, null=True)),
                ("body", models.TextField(blank=True, null=True)),
                ("remote_addr", models.CharField(blank=True, max_length=64, null=True)),
                ("received_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "oob_hits",
                "ordering": ["-received_at"],
            },
        ),
    ]
