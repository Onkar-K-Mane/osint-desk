import asyncio

from osint import bus as bus_mod
from osint.bus import LookupBus


def test_replay_until_done_then_freed(monkeypatch):
    monkeypatch.setattr(bus_mod, "MAX_FINISHED", 1)

    async def main():
        b = LookupBus()
        for lid in ("a", "b"):
            await b.publish(lid, "lookup_started", {})
            await b.publish(lid, "done", {})
        # "a" exceeded MAX_FINISHED and was freed; it must not hang or grow memory
        assert "a" not in b._buffers and "a" in b._gone
        assert [e async for e, _ in b.subscribe("a")] == ["done"]
        # "b" is still replayable
        assert [e async for e, _ in b.subscribe("b")] == ["lookup_started", "done"]
        assert not b._subs

    asyncio.run(main())


def test_ttl_prunes_finished(monkeypatch):
    monkeypatch.setattr(bus_mod, "FINISHED_TTL", -1.0)

    async def main():
        b = LookupBus()
        await b.publish("x", "done", {})
        assert "x" not in b._buffers and b.has("x")

    asyncio.run(main())


def test_active_lookup_never_pruned(monkeypatch):
    monkeypatch.setattr(bus_mod, "MAX_FINISHED", 0)

    async def main():
        b = LookupBus()
        await b.publish("live", "lookup_started", {})
        await b.publish("other", "done", {})
        assert b._buffers["live"]

    asyncio.run(main())
