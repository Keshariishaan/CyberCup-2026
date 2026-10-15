"""
PURPOSE : Non-blocking audit queue: pipeline code calls emit(); a background task writes to the
          sink so audit I/O does not count against request latency. If the queue is full or the
          worker is not running, events are written synchronously (never dropped).
INPUTS  : DBAuditSink.
OUTPUTS : emit(), start(), flush(), stop().
HOW TO EXTEND : add extra sinks to `self.sinks` (e.g. a webhook for "alert" events).
"""
from __future__ import annotations

import asyncio
from typing import Any

from core.logging import get_logger

log = get_logger("audit")


class AuditQueue:
    def __init__(self, sink: Any, maxsize: int = 1000) -> None:
        self.sinks = [sink]
        self.db = sink
        self._q: asyncio.Queue[dict[str, Any]] | None = None
        self._task: asyncio.Task[None] | None = None
        self._maxsize = maxsize

    async def start(self) -> None:
        self._q = asyncio.Queue(self._maxsize)
        self._task = asyncio.create_task(self._worker())

    async def _worker(self) -> None:
        assert self._q is not None
        while True:
            ev = await self._q.get()
            try:
                await asyncio.to_thread(self._write, ev)
            except Exception as exc:  # noqa: BLE001
                log.error("audit write failed: %s", type(exc).__name__)
            finally:
                self._q.task_done()

    def _write(self, ev: dict[str, Any]) -> None:
        for s in self.sinks:
            s.write(ev)

    def emit(self, ev: dict[str, Any]) -> None:
        if self._q is None or self._q.full():
            self._write(ev)
            return
        self._q.put_nowait(ev)

    async def flush(self) -> None:
        if self._q is not None:
            await self._q.join()

    async def stop(self) -> None:
        await self.flush()
        if self._task:
            self._task.cancel()
