"""Metric collection with Prometheus text exposition.

A ~200-line in-process registry rather than ``prometheus_client`` because the
platform must run as a short-lived batch job as often as it runs as a service.
In batch mode there is no scrape endpoint, so metrics have to be snapshotted
into the run history at the end of the process; a pull-only client cannot do
that.  The exposition format is still Prometheus-compatible, so the FastAPI
``/metrics`` endpoint works with a standard scraper.

Histograms use explicit buckets rather than summaries: quantiles computed
per-instance cannot be aggregated across replicas, whereas bucket counters can.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

#: Seconds. Tuned for ETL stages: sub-second to ~1 hour.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005,
    0.025,
    0.1,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    300.0,
    900.0,
    3600.0,
)

Labels = Mapping[str, str]


def _label_key(labels: Labels | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _render_labels(key: tuple[tuple[str, str], ...], extra: tuple[str, str] | None = None) -> str:
    pairs = list(key)
    if extra:
        pairs.append(extra)
    if not pairs:
        return ""
    body = ",".join(f'{k}="{_escape(v)}"' for k, v in pairs)
    return "{" + body + "}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass(slots=True)
class _Metric:
    name: str
    help: str
    type: str
    values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)


@dataclass(slots=True)
class _Histogram:
    name: str
    help: str
    buckets: tuple[float, ...]
    counts: dict[tuple[tuple[str, str], ...], list[int]] = field(default_factory=dict)
    sums: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)
    totals: dict[tuple[tuple[str, str], ...], int] = field(default_factory=dict)


class MetricsRegistry:
    """Thread-safe counters, gauges and histograms."""

    def __init__(self, namespace: str = "ironflow") -> None:
        self._namespace = namespace
        self._lock = threading.RLock()
        self._counters: dict[str, _Metric] = {}
        self._gauges: dict[str, _Metric] = {}
        self._histograms: dict[str, _Histogram] = {}

    # -- counters ---------------------------------------------------------- #
    def counter(
        self, name: str, value: float = 1.0, *, labels: Labels | None = None, help: str = ""
    ) -> None:
        """Increment a monotonically increasing counter."""
        if value < 0:
            raise ValueError("counters cannot decrease")
        full = self._qualify(name)
        with self._lock:
            metric = self._counters.setdefault(full, _Metric(full, help, "counter"))
            key = _label_key(labels)
            metric.values[key] = metric.values.get(key, 0.0) + value

    # -- gauges ------------------------------------------------------------ #
    def gauge(
        self, name: str, value: float, *, labels: Labels | None = None, help: str = ""
    ) -> None:
        """Set a gauge to an absolute value."""
        full = self._qualify(name)
        with self._lock:
            metric = self._gauges.setdefault(full, _Metric(full, help, "gauge"))
            metric.values[_label_key(labels)] = float(value)

    # -- histograms -------------------------------------------------------- #
    def observe(
        self,
        name: str,
        value: float,
        *,
        labels: Labels | None = None,
        buckets: Sequence[float] = DEFAULT_BUCKETS,
        help: str = "",
    ) -> None:
        """Record an observation into a bucketed histogram."""
        full = self._qualify(name)
        with self._lock:
            hist = self._histograms.get(full)
            if hist is None:
                hist = _Histogram(full, help, tuple(buckets))
                self._histograms[full] = hist
            key = _label_key(labels)
            counts = hist.counts.setdefault(key, [0] * len(hist.buckets))
            for index, bound in enumerate(hist.buckets):
                if value <= bound:
                    counts[index] += 1
            hist.sums[key] = hist.sums.get(key, 0.0) + value
            hist.totals[key] = hist.totals.get(key, 0) + 1

    @contextmanager
    def timer(self, name: str, *, labels: Labels | None = None) -> Iterator[None]:
        """Time the enclosed block into a ``*_seconds`` histogram.

        Uses ``perf_counter`` so an NTP correction mid-run cannot produce a
        negative duration.
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(name, time.perf_counter() - start, labels=labels)

    # -- reading ----------------------------------------------------------- #
    def get_counter(self, name: str, labels: Labels | None = None) -> float:
        with self._lock:
            metric = self._counters.get(self._qualify(name))
            return metric.values.get(_label_key(labels), 0.0) if metric else 0.0

    def get_gauge(self, name: str, labels: Labels | None = None) -> float:
        with self._lock:
            metric = self._gauges.get(self._qualify(name))
            return metric.values.get(_label_key(labels), 0.0) if metric else 0.0

    def histogram_stats(self, name: str, labels: Labels | None = None) -> dict[str, float]:
        """Count/sum/mean plus an interpolated p95 from the bucket counts."""
        with self._lock:
            hist = self._histograms.get(self._qualify(name))
            if hist is None:
                return {"count": 0.0, "sum": 0.0, "mean": 0.0, "p95": 0.0}
            key = _label_key(labels)
            total = hist.totals.get(key, 0)
            if not total:
                return {"count": 0.0, "sum": 0.0, "mean": 0.0, "p95": 0.0}
            counts = hist.counts.get(key, [])
            target = math.ceil(total * 0.95)
            p95 = hist.buckets[-1] if hist.buckets else 0.0
            for index, cumulative in enumerate(counts):
                if cumulative >= target:
                    p95 = hist.buckets[index]
                    break
            total_sum = hist.sums.get(key, 0.0)
            return {
                "count": float(total),
                "sum": total_sum,
                "mean": total_sum / total,
                "p95": p95,
            }

    def snapshot(self) -> dict[str, Any]:
        """Plain-dict view persisted into run history and returned by the API."""
        with self._lock:
            return {
                "counters": {
                    m.name: {_flatten(k): v for k, v in m.values.items()}
                    for m in self._counters.values()
                },
                "gauges": {
                    m.name: {_flatten(k): v for k, v in m.values.items()}
                    for m in self._gauges.values()
                },
                "histograms": {
                    h.name: {
                        _flatten(k): {
                            "count": h.totals.get(k, 0),
                            "sum": round(h.sums.get(k, 0.0), 6),
                        }
                        for k in h.totals
                    }
                    for h in self._histograms.values()
                },
            }

    def render_prometheus(self) -> str:
        """Prometheus text exposition format (version 0.0.4)."""
        lines: list[str] = []
        with self._lock:
            for metric in (*self._counters.values(), *self._gauges.values()):
                if metric.help:
                    lines.append(f"# HELP {metric.name} {metric.help}")
                lines.append(f"# TYPE {metric.name} {metric.type}")
                for key, value in sorted(metric.values.items()):
                    lines.append(f"{metric.name}{_render_labels(key)} {_format_float(value)}")

            for hist in self._histograms.values():
                if hist.help:
                    lines.append(f"# HELP {hist.name} {hist.help}")
                lines.append(f"# TYPE {hist.name} histogram")
                for key, counts in sorted(hist.counts.items()):
                    for bound, cumulative in zip(hist.buckets, counts, strict=True):
                        label = _render_labels(key, ("le", _format_float(bound)))
                        lines.append(f"{hist.name}_bucket{label} {cumulative}")
                    total = hist.totals.get(key, 0)
                    lines.append(f"{hist.name}_bucket{_render_labels(key, ('le', '+Inf'))} {total}")
                    lines.append(
                        f"{hist.name}_sum{_render_labels(key)} "
                        f"{_format_float(hist.sums.get(key, 0.0))}"
                    )
                    lines.append(f"{hist.name}_count{_render_labels(key)} {total}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()

    def _qualify(self, name: str) -> str:
        return name if name.startswith(f"{self._namespace}_") else f"{self._namespace}_{name}"


def _flatten(key: tuple[tuple[str, str], ...]) -> str:
    return ",".join(f"{k}={v}" for k, v in key) or "_"


def _format_float(value: float) -> str:
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


#: Process-wide default.  A singleton is justified here: metrics are inherently
#: process-global, and threading one through every call site would add a
#: parameter to functions that otherwise need no dependencies.
METRICS = MetricsRegistry()


# --------------------------------------------------------------------------- #
# Canonical metric names - referenced by dashboards, so defined once.
# --------------------------------------------------------------------------- #
class Metric:
    """Canonical metric names."""

    PIPELINE_RUNS = "pipeline_runs_total"
    PIPELINE_DURATION = "pipeline_duration_seconds"
    TASK_RUNS = "task_runs_total"
    TASK_DURATION = "task_duration_seconds"
    ROWS_EXTRACTED = "rows_extracted_total"
    ROWS_LOADED = "rows_loaded_total"
    ROWS_FAILED = "rows_failed_total"
    ROWS_SKIPPED = "rows_skipped_total"
    ROWS_QUARANTINED = "rows_quarantined_total"
    BATCHES = "batches_total"
    VALIDATION_VIOLATIONS = "validation_violations_total"
    RETRY_ATTEMPTS = "retry_attempts_total"
    CONNECTOR_ERRORS = "connector_errors_total"
    MEMORY_RSS = "process_memory_rss_bytes"
    CPU_PERCENT = "process_cpu_percent"
    THROUGHPUT = "throughput_rows_per_second"


__all__ = ["DEFAULT_BUCKETS", "METRICS", "Metric", "MetricsRegistry"]
