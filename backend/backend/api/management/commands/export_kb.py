"""KB export — 협업자 동기화용.
- Git fixture (기본): backend/fixtures/kb_<timestamp>.json
- GCS (옵션 — GCS_BUCKET_NAME 환경변수 + gcp-key1.json 있을 때): gs://<bucket>/kb/<timestamp>.json

사용:
  docker compose exec backend python manage.py export_kb           # fixture만
  docker compose exec backend python manage.py export_kb --gcs     # fixture + GCS
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand


KB_MODELS = [
    "api.VulnerabilityEntry",
    "api.PayloadPattern",
    "api.TargetProfile",
    "api.DeadEnd",
]


class Command(BaseCommand):
    help = "Export KB (VulnerabilityEntry + PayloadPattern + TargetProfile + DeadEnd) to fixture/GCS"

    def add_arguments(self, parser):
        parser.add_argument(
            "--gcs", action="store_true",
            help="GCS_BUCKET_NAME 있으면 gs://<bucket>/kb/ 에도 업로드",
        )
        parser.add_argument(
            "--out-dir", default="/app/fixtures",
            help="local fixture 출력 디렉터리 (default /app/fixtures)",
        )

    def handle(self, *args, **opts):
        out_dir = Path(opts["out_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fixture_path = out_dir / f"kb_{ts}.json"

        # Django dumpdata
        with fixture_path.open("w", encoding="utf-8") as f:
            call_command(
                "dumpdata", *KB_MODELS,
                indent=2, format="json", stdout=f, use_natural_primary_keys=False,
            )

        size = fixture_path.stat().st_size
        self.stdout.write(self.style.SUCCESS(
            f"local fixture: {fixture_path} ({size} bytes)"
        ))

        if not opts.get("gcs"):
            return

        bucket_name = os.environ.get("GCS_BUCKET_NAME", "").strip()
        if not bucket_name:
            self.stdout.write(self.style.WARNING("GCS_BUCKET_NAME 미설정 — GCS upload skip"))
            return
        if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip():
            self.stdout.write(self.style.WARNING(
                "GOOGLE_APPLICATION_CREDENTIALS 미설정 — GCS upload skip"
            ))
            return

        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            self.stdout.write(self.style.WARNING("google-cloud-storage 미설치 — GCS upload skip"))
            return

        try:
            client = gcs_storage.Client()
            bucket = client.bucket(bucket_name)
            gcs_path = f"kb/{fixture_path.name}"
            gcs_blob = bucket.blob(gcs_path)
            gcs_blob.upload_from_filename(
                str(fixture_path), content_type="application/json"
            )
            ref = f"gs://{bucket_name}/{gcs_path}"
            self.stdout.write(self.style.SUCCESS(f"GCS upload: {ref}"))

            # latest pointer
            latest_blob = bucket.blob("kb/latest.json")
            latest_blob.upload_from_filename(
                str(fixture_path), content_type="application/json"
            )
            self.stdout.write(self.style.SUCCESS(
                f"GCS latest: gs://{bucket_name}/kb/latest.json"
            ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"GCS upload failed: {e}"))
