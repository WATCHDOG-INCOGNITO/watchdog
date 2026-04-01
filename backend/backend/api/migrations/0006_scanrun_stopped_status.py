from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0005_llmtrace"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scanrun",
            name="status",
            field=models.CharField(
                choices=[
                    ("queued", "Queued"),
                    ("running", "Running"),
                    ("finished", "Finished"),
                    ("failed", "Failed"),
                    ("stopped", "Stopped"),
                ],
                default="queued",
                max_length=16,
            ),
        ),
    ]
