"""Process resource sampling.

Memory is the resource that actually kills ETL jobs: an unexpected 5x day in the
source data turns a comfortable job into an OOM kill, and the container is
restarted with no diagnostics.  Sampling RSS on a background thread and
recording the peak means the run history shows *why* the pod died.

``psutil`` is an optional-at-runtime dependency: if it is missing the sampler
degrades to reporting zeros rather than failing the pipeline.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from types import TracebackType
from typing import Any

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import guard
    import psutil

    _PROCESS: Any | None = psutil.Process()
except Exception:
    psutil = None  # type: ignore[assignment]
    _PROCESS = None


@dataclass(slots=True)
class ResourceSample:
    """A point-in-time view of the process's resource usage."""

    rss_bytes: int = 0
    vms_bytes: int = 0
    cpu_percent: float = 0.0
    num_threads: int = 0
    open_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rss_bytes": self.rss_bytes,
            "rss_mb": round(self.rss_bytes / 1_048_576, 2),
            "vms_bytes": self.vms_bytes,
            "cpu_percent": round(self.cpu_percent, 2),
            "num_threads": self.num_threads,
            "open_files": self.open_files,
        }


def sample_resources(*, include_open_files: bool = False) -> ResourceSample:
    """Take a single sample; returns zeros when ``psutil`` is unavailable.

    ``include_open_files`` is off by default and should stay off in any hot
    path.  ``Process.open_files()`` enumerates the OS handle table - measured at
    tens of seconds on Windows for a process with an open database - which would
    make the monitor cost more than the pipeline it is measuring.
    """
    if _PROCESS is None:
        return ResourceSample()
    try:
        memory = _PROCESS.memory_info()
        open_files = 0
        if include_open_files:
            try:
                open_files = len(_PROCESS.open_files())
            except Exception:
                open_files = 0
        return ResourceSample(
            rss_bytes=int(memory.rss),
            vms_bytes=int(memory.vms),
            cpu_percent=float(_PROCESS.cpu_percent(interval=None)),
            num_threads=int(_PROCESS.num_threads()),
            open_files=open_files,
        )
    except Exception:
        logger.debug("resource sampling failed", exc_info=True)
        return ResourceSample()


class ResourceMonitor:
    """Background sampler that records peak usage for a run.

    Used as a context manager around a pipeline execution.  The thread is a
    daemon and the interval is bounded so it cannot delay interpreter shutdown.
    """

    def __init__(self, interval: float = 2.0) -> None:
        self.interval = max(0.25, interval)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.peak = ResourceSample()
        self.samples = 0
        self._cpu_total = 0.0

    def __enter__(self) -> ResourceMonitor:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        if self._thread is not None:
            return
        if _PROCESS is not None:
            _PROCESS.cpu_percent(interval=None)  # prime the CPU delta
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="ironflow-resource-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 1.0)
            self._thread = None
        self._record(sample_resources())

    @property
    def average_cpu_percent(self) -> float:
        return self._cpu_total / self.samples if self.samples else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.peak.to_dict(),
            "samples": self.samples,
            "avg_cpu_percent": round(self.average_cpu_percent, 2),
        }

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._record(sample_resources())

    def _record(self, sample: ResourceSample) -> None:
        self.samples += 1
        self._cpu_total += sample.cpu_percent
        self.peak = ResourceSample(
            rss_bytes=max(self.peak.rss_bytes, sample.rss_bytes),
            vms_bytes=max(self.peak.vms_bytes, sample.vms_bytes),
            cpu_percent=max(self.peak.cpu_percent, sample.cpu_percent),
            num_threads=max(self.peak.num_threads, sample.num_threads),
            open_files=max(self.peak.open_files, sample.open_files),
        )


__all__ = ["ResourceMonitor", "ResourceSample", "sample_resources"]
