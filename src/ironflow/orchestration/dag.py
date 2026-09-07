"""Task dependency graph.

The graph answers three questions the runner needs:

1. **In what order may tasks run?**  Kahn's algorithm produces *levels* rather
   than a flat topological order.  Every task in a level has all its
   dependencies satisfied, so the level can be executed concurrently - which is
   where the parallelism in a pipeline actually comes from.
2. **Is the graph valid?**  A cycle makes execution impossible and is reported
   with the participating tasks, not just "cycle detected".  Kahn's algorithm
   detects this for free: whatever remains unemitted is exactly the cycle.
3. **What must be abandoned when a task fails?**  Everything transitively
   downstream, computed once so the runner does not re-walk the graph per task.

The implementation is deliberately dependency-free and O(V+E); a pipeline with
thousands of tasks orders in microseconds.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from ironflow.config.models import PipelineSpec, TaskSpec
from ironflow.core.errors import CircularDependencyError, ConfigurationError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TaskNode:
    """A task plus its resolved edges."""

    spec: TaskSpec
    dependencies: frozenset[str] = frozenset()
    dependents: set[str] = field(default_factory=set)

    @property
    def name(self) -> str:
        return self.spec.name


class TaskGraph:
    """A validated, immutable DAG of tasks."""

    def __init__(self, tasks: Sequence[TaskSpec]) -> None:
        if not tasks:
            raise ConfigurationError("a pipeline must define at least one task")

        self._nodes: dict[str, TaskNode] = {}
        for spec in tasks:
            if spec.name in self._nodes:
                raise ConfigurationError("duplicate task name", context={"task": spec.name})
            self._nodes[spec.name] = TaskNode(spec=spec, dependencies=frozenset(spec.depends_on))

        for node in self._nodes.values():
            for dependency in node.dependencies:
                parent = self._nodes.get(dependency)
                if parent is None:
                    raise ConfigurationError(
                        "task depends on an unknown task",
                        context={"task": node.name, "missing": dependency},
                    )
                parent.dependents.add(node.name)

        self._levels = self._compute_levels()

    @classmethod
    def from_spec(cls, pipeline: PipelineSpec) -> TaskGraph:
        return cls(pipeline.tasks)

    # -- structure --------------------------------------------------------- #
    def _compute_levels(self) -> list[list[str]]:
        """Kahn's algorithm, grouped into concurrently runnable levels."""
        indegree = {name: len(node.dependencies) for name, node in self._nodes.items()}
        # Sorted so the execution order is deterministic across runs, which
        # matters when comparing two runs' logs.
        ready = deque(sorted(name for name, degree in indegree.items() if degree == 0))
        levels: list[list[str]] = []
        emitted = 0

        while ready:
            level = sorted(ready)
            ready.clear()
            levels.append(level)
            emitted += len(level)
            for name in level:
                for dependent in sorted(self._nodes[name].dependents):
                    indegree[dependent] -= 1
                    if indegree[dependent] == 0:
                        ready.append(dependent)

        if emitted != len(self._nodes):
            # Anything with a non-zero indegree left over is in (or fed by) a cycle.
            remaining = sorted(name for name, degree in indegree.items() if degree > 0)
            raise CircularDependencyError(
                "the task graph contains a circular dependency",
                context={"tasks_in_cycle": remaining},
            )
        return levels

    @property
    def levels(self) -> list[list[str]]:
        """Task names grouped into concurrently executable levels."""
        return [list(level) for level in self._levels]

    @property
    def names(self) -> list[str]:
        return list(self._nodes)

    @property
    def size(self) -> int:
        return len(self._nodes)

    @property
    def max_width(self) -> int:
        """Widest level - the useful upper bound on worker threads."""
        return max((len(level) for level in self._levels), default=0)

    @property
    def depth(self) -> int:
        return len(self._levels)

    def node(self, name: str) -> TaskNode:
        try:
            return self._nodes[name]
        except KeyError:
            raise ConfigurationError("unknown task", context={"task": name}) from None

    def spec(self, name: str) -> TaskSpec:
        return self.node(name).spec

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    def __iter__(self) -> Iterator[TaskSpec]:
        """Iterate in topological order."""
        for level in self._levels:
            for name in level:
                yield self._nodes[name].spec

    # -- traversal --------------------------------------------------------- #
    def topological_order(self) -> list[str]:
        return [name for level in self._levels for name in level]

    def dependencies_of(self, name: str) -> frozenset[str]:
        return self.node(name).dependencies

    def dependents_of(self, name: str) -> set[str]:
        return set(self.node(name).dependents)

    def descendants(self, name: str) -> set[str]:
        """Every task transitively downstream of ``name``."""
        seen: set[str] = set()
        queue = deque(self.node(name).dependents)
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(self._nodes[current].dependents)
        return seen

    def ancestors(self, name: str) -> set[str]:
        seen: set[str] = set()
        queue = deque(self.node(name).dependencies)
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(self._nodes[current].dependencies)
        return seen

    def subgraph(self, names: Iterable[str]) -> TaskGraph:
        """Graph limited to ``names`` plus everything they depend on.

        Used by ``--only`` and by ``pipeline resume``: running a task without
        its ancestors would execute against stale inputs.
        """
        selected: set[str] = set()
        for name in names:
            if name not in self._nodes:
                raise ConfigurationError("unknown task", context={"task": name})
            selected.add(name)
            selected |= self.ancestors(name)

        specs = []
        for name in self.topological_order():
            if name not in selected:
                continue
            spec = self._nodes[name].spec.model_copy(deep=True)
            spec.depends_on = [d for d in spec.depends_on if d in selected]
            specs.append(spec)
        return TaskGraph(specs)

    def describe(self) -> dict[str, object]:
        """Structure summary for ``ironflow pipeline show`` and the API."""
        return {
            "tasks": self.size,
            "levels": self.levels,
            "depth": self.depth,
            "max_parallelism": self.max_width,
            "edges": [
                {"from": dependency, "to": name}
                for name, node in self._nodes.items()
                for dependency in sorted(node.dependencies)
            ],
        }

    def to_mermaid(self) -> str:
        """Render the DAG as a Mermaid diagram for docs and the dashboard."""
        lines = ["graph LR"]
        for name in self.topological_order():
            node = self._nodes[name]
            safe = _mermaid_id(name)
            lines.append(f'    {safe}["{name}"]')
            for dependency in sorted(node.dependencies):
                lines.append(f"    {_mermaid_id(dependency)} --> {safe}")
        return "\n".join(lines)


def _mermaid_id(name: str) -> str:
    return "t_" + "".join(c if c.isalnum() else "_" for c in name)


__all__ = ["TaskGraph", "TaskNode"]
