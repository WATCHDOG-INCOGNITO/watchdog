import threading
import time

from django.utils import timezone


STOP_MESSAGE = "사용자가 실행 중지를 요청했습니다."

_STOP_EVENTS = {}
_LOCK = threading.Lock()


class ScanStopped(Exception):
    pass


def register_scan(run_id):
    key = str(run_id)
    with _LOCK:
        event = _STOP_EVENTS.get(key)
        if event is None:
            event = threading.Event()
            _STOP_EVENTS[key] = event
    return event


def unregister_scan(run_id):
    with _LOCK:
        _STOP_EVENTS.pop(str(run_id), None)


def is_stop_requested(run_id):
    with _LOCK:
        event = _STOP_EVENTS.get(str(run_id))
        return bool(event and event.is_set())


def raise_if_stop_requested(scan_run):
    if is_stop_requested(scan_run.run_id):
        raise ScanStopped(STOP_MESSAGE)


def stop_sleep(scan_run, seconds, interval=0.25):
    remaining = float(seconds or 0)
    while remaining > 0:
        raise_if_stop_requested(scan_run)
        sleep_for = min(interval, remaining)
        time.sleep(sleep_for)
        remaining -= sleep_for


def mark_scan_stopped(scan_run, message=STOP_MESSAGE):
    scan_run.status = "stopped"
    if not scan_run.finished_at:
        scan_run.finished_at = timezone.now()
    scan_run.error_log = message
    scan_run.save(update_fields=["status", "finished_at", "error_log"])

    from .realtime import broadcast_scan_update

    broadcast_scan_update(scan_run.run_id)


def request_scan_stop(scan_run, message=STOP_MESSAGE):
    key = str(scan_run.run_id)
    with _LOCK:
        event = _STOP_EVENTS.get(key)
        if event is None:
            event = threading.Event()
            _STOP_EVENTS[key] = event
        event.set()

    mark_scan_stopped(scan_run, message=message)
