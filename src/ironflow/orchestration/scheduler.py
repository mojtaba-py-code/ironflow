"""Cron scheduler.

A self-contained scheduler rather than a dependency, for two reasons: it is
~200 lines, and it needs to interoperate with IronFlow's own run history to
enforce ``max_concurrent_runs`` - which an external library cannot do.

Semantics that matter in production
-----------------------------------
* **Timezone-aware.**  Schedules are evaluated in the pipeline's declared zone,
  so ``0 2 * * *`` means 02:00 local even across a DST change.  All internal
  arithmetic is UTC.
* **No catch-up by default.**  If the scheduler was down for six hours, a daily
  job runs once at the next occurrence, not six times.  ``catchup: true`` opts
  into the other behaviour.
* **Overlap protection.**  A pipeline whose previous run is still going is
  skipped rather than started concurrently, unless ``max_concurrent_runs`` says
  otherwise.  Two concurrent incremental loads race on the same watermark.
* **Misfire grace period.**  A tick that arrives slightly late still fires; one
  that arrives an hour late does not, because the next occurrence is imminent
  anyway.

For multi-replica deployments this scheduler must run as a single instance
(a Kubernetes ``Deployment`` with one replica, or a leader-elected sidecar);
distributed locking is out of scope and is documented as such.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ironflow.config.models import PipelineSpec, validate_cron
from ironflow.core.context import utcnow
from ironflow.core.errors import SchedulerError

logger = logging.getLogger(__name__)

#: A tick later than this after its due time is abandoned, not fired.
DEFAULT_MISFIRE_GRACE = 300.0

_FIELD_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
_FIELD_NAMES = ("minute", "hour", "day", "month", "weekday")


class CronExpression:
    """A parsed 5-field cron expression.

    Supports ``*``, ``N``, ``N-M``, ``*/S`` and comma lists.  Deliberately not
    the full Vixie/Quartz grammar: ``@reboot``, ``L``, ``W`` and ``#`` have
    surprising semantics that produce schedules nobody can reason about at 3am.
    """

    __slots__ = ("expression", "fields")

    def __init__(self, expression: str) -> None:
        validate_cron(expression)
        self.expression = expression.strip()
        self.fields = [
            self._parse_field(value, *_FIELD_RANGES[index])
            for index, value in enumerate(self.expression.split())
        ]

    @staticmethod
    def _parse_field(value: str, low: int, high: int) -> set[int]:
        allowed: set[int] = set()
        for part in value.split(","):
            if part == "*":
                allowed |= set(range(low, high + 1))
            elif part.startswith("*/"):
                step = int(part[2:])
                if step < 1:
                    raise SchedulerError("cron step must be >= 1", context={"field": part})
                allowed |= set(range(low, high + 1, step))
            elif "-" in part:
                start, _, end = part.partition("-")
                allowed |= set(range(int(start), int(end) + 1))
            else:
                allowed.add(int(part))

        out_of_range = [v for v in allowed if not low <= v <= high]
        if out_of_range:
            raise SchedulerError(
                "cron value out of range",
                context={"values": sorted(out_of_range), "range": [low, high]},
            )
        return allowed

    def matches(self, moment: datetime) -> bool:
        """Does ``moment`` (minute precision) satisfy the expression?

        Day-of-month and day-of-week are OR-ed when both are restricted, which
        is the historical crontab behaviour every operator expects.
        """
        minute, hour, day, month, weekday = self.fields
        # Python: Monday=0; cron: Sunday=0.
        cron_weekday = (moment.weekday() + 1) % 7

        if moment.minute not in minute or moment.hour not in hour or moment.month not in month:
            return False

        day_restricted = len(day) < 31
        weekday_restricted = len(weekday) < 7
        if day_restricted and weekday_restricted:
            return moment.day in day or cron_weekday in weekday
        if day_restricted:
            return moment.day in day
        if weekday_restricted:
            return cron_weekday in weekday
        return True

    def next_after(self, moment: datetime, *, horizon_days: int = 1830) -> datetime | None:
        """First matching minute strictly after ``moment``.

        The horizon is five years, not one: ``0 0 29 2 *`` can be more than two
        years away, and a shorter horizon returned ``None`` for it, which made
        the caller fall back to an arbitrary time and fire on the wrong day.
        The day-skip below keeps the scan cheap - a few thousand iterations even
        at that horizon.
        """
        candidate = moment.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = moment + timedelta(days=horizon_days)
        while candidate <= limit:
            if self.matches(candidate):
                return candidate
            # Skip a whole day when the date part cannot match - turns a
            # ~576,000-iteration scan for "Feb 29" into ~400.
            if not self._date_could_match(candidate):
                candidate = (candidate + timedelta(days=1)).replace(hour=0, minute=0)
                continue
            candidate += timedelta(minutes=1)
        return None

    def _date_could_match(self, moment: datetime) -> bool:
        _, _, day, month, weekday = self.fields
        if moment.month not in month:
            return False
        cron_weekday = (moment.weekday() + 1) % 7
        day_restricted = len(day) < 31
        weekday_restricted = len(weekday) < 7
        if day_restricted and weekday_restricted:
            return moment.day in day or cron_weekday in weekday
        if day_restricted:
            return moment.day in day
        if weekday_restricted:
            return cron_weekday in weekday
        return True

    def __repr__(self) -> str:
        return f"CronExpression({self.expression!r})"


@dataclass(slots=True)
class ScheduledJob:
    """A pipeline bound to a schedule."""

    pipeline: PipelineSpec
    next_run: datetime
    cron: CronExpression | None = None
    interval_seconds: int | None = None
    timezone: str = "UTC"
    catchup: bool = False
    max_concurrent_runs: int = 1
    last_run: datetime | None = None
    run_count: int = 0
    failure_count: int = 0
    enabled: bool = True

    @property
    def name(self) -> str:
        return self.pipeline.name

    def advance(self, now: datetime) -> None:
        """Compute the next due time after ``now``."""
        if self.interval_seconds:
            nxt = (self.last_run or now) + timedelta(seconds=self.interval_seconds)
            # Without catch-up, roll forward past every missed interval at once.
            while nxt <= now and not self.catchup:
                nxt += timedelta(seconds=self.interval_seconds)
            self.next_run = nxt
        elif self.cron is not None:
            local = _to_zone(now, self.timezone)
            following = self.cron.next_after(local)
            if following is None:
                # An expression that matches nothing in five years (e.g. 31
                # February) is a mistake. Disable the job loudly rather than
                # inventing a time and firing on the wrong day.
                logger.error(
                    "cron expression %r has no occurrence within the search horizon; "
                    "disabling the schedule for pipeline %r",
                    self.cron.expression,
                    self.pipeline.name,
                )
                self.enabled = False
                self.next_run = now + timedelta(days=365)
                return
            self.next_run = _to_utc(following, self.timezone)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pipeline": self.name,
            "schedule": self.cron.expression if self.cron else f"every {self.interval_seconds}s",
            "timezone": self.timezone,
            "enabled": self.enabled,
            "next_run": self.next_run.isoformat(),
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "runs": self.run_count,
            "failures": self.failure_count,
        }


def _to_zone(moment: datetime, timezone_name: str) -> datetime:
    if timezone_name.upper() == "UTC":
        return moment.astimezone(UTC)
    try:
        from zoneinfo import ZoneInfo

        return moment.astimezone(ZoneInfo(timezone_name))
    except Exception:
        logger.warning("unknown timezone %r; falling back to UTC", timezone_name)
        return moment.astimezone(UTC)


def _to_utc(moment: datetime, timezone_name: str) -> datetime:
    if moment.tzinfo is None:
        moment = _to_zone(utcnow(), timezone_name).replace(
            year=moment.year,
            month=moment.month,
            day=moment.day,
            hour=moment.hour,
            minute=moment.minute,
            second=0,
            microsecond=0,
        )
    return moment.astimezone(UTC)


class Scheduler:
    """Evaluates schedules and triggers pipeline runs."""

    def __init__(
        self,
        trigger: Callable[[PipelineSpec], Any],
        *,
        poll_interval: float = 30.0,
        misfire_grace: float = DEFAULT_MISFIRE_GRACE,
        running_count: Callable[[str], int] | None = None,
    ) -> None:
        self._trigger = trigger
        self._poll_interval = max(1.0, poll_interval)
        self._misfire_grace = misfire_grace
        self._running_count = running_count
        self._jobs: dict[str, ScheduledJob] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    # -- registration ------------------------------------------------------ #
    def register(self, pipeline: PipelineSpec) -> ScheduledJob | None:
        """Add a pipeline whose spec declares a schedule."""
        schedule = pipeline.schedule
        if schedule is None or not schedule.enabled:
            return None

        now = utcnow()
        cron = CronExpression(schedule.cron) if schedule.cron else None
        job = ScheduledJob(
            pipeline=pipeline,
            next_run=now,
            cron=cron,
            interval_seconds=schedule.interval_seconds,
            timezone=schedule.timezone,
            catchup=schedule.catchup,
            max_concurrent_runs=schedule.max_concurrent_runs,
        )
        job.advance(now)
        with self._lock:
            self._jobs[pipeline.name] = job
        logger.info(
            "scheduled %r (%s), next run %s",
            pipeline.name,
            schedule.cron or f"every {schedule.interval_seconds}s",
            job.next_run.isoformat(),
        )
        return job

    def register_all(self, pipelines: Iterator[PipelineSpec] | list[PipelineSpec]) -> int:
        return sum(1 for p in pipelines if self.register(p) is not None)

    def unregister(self, name: str) -> bool:
        with self._lock:
            return self._jobs.pop(name, None) is not None

    def jobs(self) -> list[ScheduledJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda job: job.next_run)

    # -- execution --------------------------------------------------------- #
    def due_jobs(self, now: datetime | None = None) -> list[ScheduledJob]:
        """Jobs whose time has come and whose misfire window has not passed."""
        moment = now or utcnow()
        due: list[ScheduledJob] = []
        with self._lock:
            for job in self._jobs.values():
                if not job.enabled or job.next_run > moment:
                    continue
                lateness = (moment - job.next_run).total_seconds()
                if lateness > self._misfire_grace and not job.catchup:
                    logger.warning(
                        "skipping missed run of %r (%.0fs late, grace %.0fs)",
                        job.name,
                        lateness,
                        self._misfire_grace,
                    )
                    job.advance(moment)
                    continue
                due.append(job)
        return due

    def tick(self, now: datetime | None = None) -> list[str]:
        """Run one scheduling cycle; returns the names triggered."""
        moment = now or utcnow()
        triggered: list[str] = []

        for job in self.due_jobs(moment):
            if self._is_overlapping(job):
                logger.warning(
                    "skipping %r: %d run(s) already in flight (max_concurrent_runs=%d)",
                    job.name,
                    self._running_count(job.name) if self._running_count else 1,
                    job.max_concurrent_runs,
                )
                job.last_run = moment
                job.advance(moment)
                continue

            logger.info("triggering scheduled run of %r", job.name)
            try:
                self._trigger(job.pipeline)
                job.run_count += 1
                triggered.append(job.name)
            except Exception:
                job.failure_count += 1
                logger.error("scheduled run of %r failed to start", job.name, exc_info=True)
            finally:
                job.last_run = moment
                job.advance(moment)

        return triggered

    def _is_overlapping(self, job: ScheduledJob) -> bool:
        if self._running_count is None:
            return False
        return self._running_count(job.name) >= job.max_concurrent_runs

    # -- lifecycle --------------------------------------------------------- #
    def start(self) -> None:
        """Run the scheduling loop on a background thread."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ironflow-scheduler", daemon=True)
        self._thread.start()
        logger.info("scheduler started with %d job(s)", len(self._jobs))

    def stop(self, timeout: float = 30.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("scheduler stopped")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            try:
                self.tick()
            except Exception:
                logger.error("scheduler tick failed", exc_info=True)

    def describe(self) -> list[dict[str, Any]]:
        return [job.to_dict() for job in self.jobs()]


__all__ = ["DEFAULT_MISFIRE_GRACE", "CronExpression", "ScheduledJob", "Scheduler"]
