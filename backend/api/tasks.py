from celery import shared_task
from .models import ScanRun

@shared_task
def execute_scan_run(run_id: str):
    run = ScanRun.objects.get(run_id=run_id)

    run.progress = 50
    run.save(update_fields=["progress"])

    run.status = ScanRun.Status.SUCCESS
    run.progress = 100
    run.save(update_fields=["status", "progress"])

    return {"ok": True}
