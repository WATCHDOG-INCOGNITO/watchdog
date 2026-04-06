from django.urls import path

from .consumers import ScanListConsumer, ScanRunConsumer


websocket_urlpatterns = [
    path("ws/scans/", ScanListConsumer.as_asgi()),
    path("ws/scan-runs/<str:run_id>/", ScanRunConsumer.as_asgi()),
]
