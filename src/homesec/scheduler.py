"""In-process scheduler: one asyncio loop, fixed intervals, state in SQLite.

No cron: each job has an interval, the time of its last run is kept in the
state database, so a weekly scan stays weekly across restarts and reboots.
Jobs run one at a time (a Pi does not need a port scan and a SIEM export
competing for CPU), and a failing job is logged and retried at its next slot.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from collections.abc import Callable, Sequence
from typing import Protocol

from homesec.inventory import Inventory

log = logging.getLogger(__name__)


class Job(Protocol):
    name: str

    @property
    def interval(self) -> float: ...

    async def run(self) -> dict: ...


class Scheduler:
    def __init__(
        self,
        jobs: Sequence[Job],
        inventory: Inventory,
        *,
        clock: Callable[[], float] = time.time,
        max_sleep: float = 60.0,
        grace: float = 5.0,
    ) -> None:
        self.jobs = list(jobs)
        self.grace = grace
        self.inventory = inventory
        self._clock = clock
        self.max_sleep = max_sleep
        self.runs: list[tuple[str, str]] = []  # (job, status) for tests and logging

    def next_due(self, job: Job) -> float:
        last = self.inventory.last_run(job.name)
        return 0.0 if last is None else last + job.interval

    async def run_job(self, job: Job) -> dict | None:
        started = self._clock()
        try:
            summary = await job.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("job %s failed", job.name)
            self.inventory.set_last_run(job.name, started, "error", f"{type(exc).__name__}: {exc}")
            self.runs.append((job.name, "error"))
            return None
        self.inventory.set_last_run(job.name, started, "ok")
        self.runs.append((job.name, "ok"))
        log.info("job %s finished in %.1fs", job.name, self._clock() - started)
        return summary

    async def _run_interruptible(self, job: Job, stop: asyncio.Event) -> None:
        """Run ``job``; on shutdown give it ``grace`` seconds, then cancel it.

        A cancelled job is not recorded as run, so it starts again after a restart.
        """
        task = asyncio.create_task(self.run_job(job))
        stopper = asyncio.create_task(stop.wait())
        try:
            await asyncio.wait({task, stopper}, return_when=asyncio.FIRST_COMPLETED)
            if not task.done():
                log.info("stop requested while %s is running; waiting %ss", job.name, self.grace)
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=self.grace)
                except TimeoutError:
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
                    log.warning("job %s cancelled during shutdown", job.name)
        finally:
            stopper.cancel()

    async def run_forever(self, stop: asyncio.Event) -> None:
        if not self.jobs:
            await stop.wait()
            return
        for job in self.jobs:
            due = self.next_due(job)
            log.info(
                "job %s: every %ss, next run in %ds",
                job.name,
                f"{job.interval:g}",
                max(0, round(due - self._clock())),
            )
        while not stop.is_set():
            now = self._clock()
            due_jobs = sorted((j for j in self.jobs if self.next_due(j) <= now), key=self.next_due)
            for job in due_jobs:
                if stop.is_set():
                    break
                await self._run_interruptible(job, stop)
            wait = min(self.next_due(j) for j in self.jobs) - self._clock()
            wait = max(0.05, min(wait, self.max_sleep))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=wait)
        log.info("scheduler stopped")


def install_stop_handlers(stop: asyncio.Event) -> None:
    """SIGINT/SIGTERM set ``stop`` (docker stop sends SIGTERM). No-op on Windows."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)
