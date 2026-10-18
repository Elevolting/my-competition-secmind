from __future__ import annotations

from secmind.service import EventHub


async def test_event_hub_delivers_and_signals_queue_gap() -> None:
    hub = EventHub()
    async with hub.subscribe("run") as queue:
        await hub.publish({"run_id": "run", "sequence": 1, "event_type": "one"})
        assert (await queue.get())["sequence"] == 1

        for sequence in range(2, 502):
            await hub.publish({"run_id": "run", "sequence": sequence, "event_type": "many"})
        await hub.publish({"run_id": "run", "sequence": 502, "event_type": "overflow"})
        gap = await queue.get()
        assert gap["event_type"] == "stream.gap"
        assert gap["sequence"] == 502


async def test_event_hub_ignores_runs_without_subscribers() -> None:
    hub = EventHub()
    await hub.publish({"run_id": "absent", "sequence": 1, "event_type": "noop"})
