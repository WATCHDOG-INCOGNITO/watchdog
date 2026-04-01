from __future__ import annotations

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from .realtime import build_scan_detail_payload, build_scan_list_payload


class ScanListConsumer(AsyncJsonWebsocketConsumer):
    group_name = "scan_list"

    async def connect(self):
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        await self.send_json(await self._initial_payload())

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def scan_list_message(self, event):
        await self.send_json(event["payload"])

    @database_sync_to_async
    def _initial_payload(self):
        return build_scan_list_payload()


class ScanRunConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.run_id = str(self.scope["url_route"]["kwargs"]["run_id"])
        self.group_name = f"scan_run_{self.run_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        payload = await self._initial_payload()
        if payload is None:
            await self.send_json(
                {
                    "type": "scan_run_missing",
                    "run_id": self.run_id,
                }
            )
            await self.close(code=4404)
            return

        await self.send_json(payload)

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def scan_run_message(self, event):
        await self.send_json(event["payload"])

    @database_sync_to_async
    def _initial_payload(self):
        return build_scan_detail_payload(self.run_id)
