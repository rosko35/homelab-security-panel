import asyncio

from homesec.scheduler import Scheduler


class CountingJob:
    def __init__(self, name, interval, fail=False, duration=0.0):
        self.name = name
        self._interval = interval
        self.fail = fail
        self.duration = duration
        self.calls = 0
        self.cancelled = False

    @property
    def interval(self):
        return self._interval

    async def run(self):
        self.calls += 1
        try:
            await asyncio.sleep(self.duration)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        if self.fail:
            raise RuntimeError("boom")
        return {"calls": self.calls}


def test_jobs_run_on_their_intervals_and_failures_are_recorded(inventory):
    fast = CountingJob("fast", 0.05)
    slow = CountingJob("slow", 3600)
    broken = CountingJob("broken", 0.05, fail=True)
    sched = Scheduler([fast, slow, broken], inventory, max_sleep=0.02)

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(sched.run_forever(stop))
        await asyncio.sleep(0.4)
        stop.set()
        await asyncio.wait_for(task, 2)

    asyncio.run(go())
    assert fast.calls >= 3
    assert slow.calls == 1
    assert broken.calls >= 2  # a failing job does not kill the loop
    runs = {r["name"]: r for r in inventory.job_runs()}
    assert runs["broken"]["status"] == "error"
    assert "boom" in runs["broken"]["error"]
    assert runs["slow"]["status"] == "ok"


def test_last_run_survives_restart(inventory):
    weekly = CountingJob("scan", 7 * 86400)

    async def once():
        stop = asyncio.Event()
        task = asyncio.create_task(Scheduler([weekly], inventory, max_sleep=0.02).run_forever(stop))
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, 2)

    asyncio.run(once())
    asyncio.run(once())  # "restart": the weekly job is not due again
    assert weekly.calls == 1


def test_long_job_is_cancelled_after_grace_period(inventory):
    stuck = CountingJob("stuck", 60, duration=30)
    sched = Scheduler([stuck], inventory, max_sleep=0.02, grace=0.1)

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(sched.run_forever(stop))
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, 2)

    asyncio.run(go())
    assert stuck.cancelled
    assert inventory.last_run("stuck") is None  # will run again after restart


class SkippingJob(CountingJob):
    async def run(self):
        self.calls += 1
        return {"skipped": "no devices yet", "retry_after": 600}


def test_skipped_job_is_retried_soon_not_after_a_full_interval(inventory):
    now = [1_000_000.0]
    weekly = SkippingJob("scan", 7 * 86400)
    sched = Scheduler([weekly], inventory, clock=lambda: now[0])
    asyncio.run(sched.run_job(weekly))
    assert sched.next_due(weekly) == 1_000_000.0 + 600
    run = inventory.job_runs()[0]
    assert (run["status"], run["error"]) == ("skipped", "no devices yet")
