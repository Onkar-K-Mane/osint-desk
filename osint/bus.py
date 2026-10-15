"""In-memory SSE event bus with replay buffer per lookup."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Any, AsyncIterator


class LookupBus:
    def __init__(self) -> None:
        self._buffers: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._done: set[str] = set()
        self._lock = asyncio.Lock()

    async def publish(self, lookup_id: str, event: str, data: Any) -> None:
        payload = json.dumps(data, ensure_ascii=False, default=str)
        async with self._lock:
            self._buffers[lookup_id].append((event, payload))
            if event == "done":
                self._done.add(lookup_id)
            queues = list(self._subs.get(lookup_id, []))
        for q in queues:
            try:
                q.put_nowait((event, payload))
            except asyncio.QueueFull:
                pass

    async def subscribe(self, lookup_id: str) -> AsyncIterator[tuple[str, str]]:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            replay = list(self._buffers.get(lookup_id, []))
            already_done = lookup_id in self._done
            self._subs[lookup_id].append(q)
        try:
            for event, payload in replay:
                yield event, payload
            if already_done:
                return
            while True:
                event, payload = await q.get()
                yield event, payload
                if event == "done":
                    return
        finally:
            async with self._lock:
                subs = self._subs.get(lookup_id, [])
                if q in subs:
                    subs.remove(q)

    def has(self, lookup_id: str) -> bool:
        return lookup_id in self._buffers


BUS = LookupBus()
