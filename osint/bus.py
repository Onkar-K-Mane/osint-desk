"""In-memory SSE event bus with replay buffer per lookup."""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict, defaultdict
from typing import Any, AsyncIterator


# Replay buffers of finished lookups are dropped after this long (seconds) or once more
# than MAX_FINISHED are retained. Results stay in SQLite; only the SSE replay goes away.
FINISHED_TTL = 600.0
MAX_FINISHED = 200
MAX_TOMBSTONES = 10_000


class LookupBus:
    def __init__(self) -> None:
        self._buffers: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._done: OrderedDict[str, float] = OrderedDict()  # id -> finish time
        self._gone: OrderedDict[str, None] = OrderedDict()  # finished and buffer freed
        self._lock = asyncio.Lock()

    def _prune(self) -> None:
        """Free replay buffers of finished lookups that nobody is listening to."""
        now = time.monotonic()
        for lid in list(self._done):
            if self._subs.get(lid):
                continue
            expired = now - self._done[lid] > FINISHED_TTL
            if expired or len(self._done) > MAX_FINISHED:
                self._done.pop(lid)
                self._buffers.pop(lid, None)
                self._subs.pop(lid, None)
                self._gone[lid] = None
        while len(self._gone) > MAX_TOMBSTONES:
            self._gone.popitem(last=False)

    async def publish(self, lookup_id: str, event: str, data: Any) -> None:
        payload = json.dumps(data, ensure_ascii=False, default=str)
        async with self._lock:
            self._buffers[lookup_id].append((event, payload))
            if event == "done":
                self._done[lookup_id] = time.monotonic()
                self._prune()
            queues = list(self._subs.get(lookup_id, []))
        for q in queues:
            try:
                q.put_nowait((event, payload))
            except asyncio.QueueFull:
                pass

    async def subscribe(self, lookup_id: str) -> AsyncIterator[tuple[str, str]]:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            if lookup_id in self._gone:
                # Finished long ago and freed; the client should load results over HTTP.
                yield "done", json.dumps({"lookup_id": lookup_id})
                return
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
                if not subs:
                    self._subs.pop(lookup_id, None)

    def has(self, lookup_id: str) -> bool:
        return lookup_id in self._buffers or lookup_id in self._gone


BUS = LookupBus()
