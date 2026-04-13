"""Change embedding VectorField from 1024 to 768 dimensions.

Drops the existing column (all values were NULL — Voyage API never produced
embeddings) and recreates it with 768 dimensions to match the local
sentence-transformers model (all-mpnet-base-v2).
"""
from django.db import migrations

try:
    from pgvector.django import VectorField
    _PGVECTOR = True
except ImportError:
    from django.db import models
    _PGVECTOR = False
    VectorField = None  # type: ignore


def _embedding_field():
    if _PGVECTOR:
        return VectorField(dimensions=768, null=True, blank=True)
    from django.db import models
    return models.JSONField(null=True, blank=True)


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0009_oob_hit"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="payloadpattern",
            name="embedding",
        ),
        migrations.AddField(
            model_name="payloadpattern",
            name="embedding",
            field=_embedding_field(),
        ),
    ]
