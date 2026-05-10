from django.db import migrations, models

try:
    from pgvector.django import VectorExtension, VectorField
    _PGVECTOR = True
except ImportError:  # 보조: pgvector 미설치 환경에서도 마이그레이션 정의는 로드되도록
    _PGVECTOR = False
    VectorExtension = None  # type: ignore
    VectorField = None  # type: ignore


def _embedding_field():
    if _PGVECTOR:
        return VectorField(dimensions=1024, null=True, blank=True)
    return models.JSONField(null=True, blank=True)


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0006_scanrun_stopped_status"),
    ]

    operations = [
        # CREATE EXTENSION IF NOT EXISTS vector;
        migrations.RunSQL(
            sql="CREATE EXTENSION IF NOT EXISTS vector;",
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.AddField(
            model_name="payloadpattern",
            name="embedding",
            field=_embedding_field(),
        ),
        migrations.AddField(
            model_name="payloadpattern",
            name="embedding_model",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
    ]
