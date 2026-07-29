"""WebSocket connection hub."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class WebSocketHub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, socket: WebSocket) -> None:
        await socket.accept()
        self.clients.add(socket)

    def disconnect(self, socket: WebSocket) -> None:
        self.clients.discard(socket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        disconnected: list[WebSocket] = []
        for client in tuple(self.clients):
            try:
                await client.send_json(message)
            except Exception:
                disconnected.append(client)
        for client in disconnected:
            self.disconnect(client)

    def broadcast_from_sync(self, message: dict[str, Any]) -> None:
        if self.loop:
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)

