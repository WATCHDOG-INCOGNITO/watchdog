from __future__ import annotations

from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import Candidate, EvidenceBlob, Finding, FindingEvidenceLink, RequestCatalog, ScanRun
from .realtime import broadcast_scan_update


def _schedule_broadcast(run_id) -> None:
    if not run_id:
        return

    transaction.on_commit(lambda rid=str(run_id): broadcast_scan_update(rid))


@receiver(post_save, sender=ScanRun)
def _scan_run_saved(sender, instance, **kwargs):
    _schedule_broadcast(instance.run_id)


@receiver(post_save, sender=RequestCatalog)
@receiver(post_delete, sender=RequestCatalog)
def _request_catalog_changed(sender, instance, **kwargs):
    _schedule_broadcast(instance.scan_run_id)


@receiver(post_save, sender=Candidate)
@receiver(post_delete, sender=Candidate)
def _candidate_changed(sender, instance, **kwargs):
    _schedule_broadcast(instance.scan_run_id)


@receiver(post_save, sender=Finding)
@receiver(post_delete, sender=Finding)
def _finding_changed(sender, instance, **kwargs):
    _schedule_broadcast(instance.scan_run_id)


@receiver(post_save, sender=EvidenceBlob)
@receiver(post_delete, sender=EvidenceBlob)
def _evidence_blob_changed(sender, instance, **kwargs):
    _schedule_broadcast(instance.finding.scan_run_id if instance.finding_id else None)


@receiver(post_save, sender=FindingEvidenceLink)
@receiver(post_delete, sender=FindingEvidenceLink)
def _finding_evidence_link_changed(sender, instance, **kwargs):
    _schedule_broadcast(instance.finding.scan_run_id if instance.finding_id else None)
