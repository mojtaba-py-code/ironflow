"""IronFlow - an enterprise ETL data pipeline platform.

The package is organised in concentric layers.  The inner layers know nothing
about the outer ones, which keeps the domain logic independent of frameworks:

``core``
    Pure domain primitives: record batches, execution context, the exception
    hierarchy, the component registry and the retry policy.
``config``
    Declarative pipeline specifications plus loading/merging of YAML, JSON,
    environment variables and ``.env`` files.
``security``
    Cryptography, secret resolution, PII masking, RBAC and the input guards
    used by every connector.
``observability``
    Structured logging, metrics and the tamper-evident audit trail.
``connectors`` / ``extraction`` / ``validation`` / ``transformation`` / ``loading``
    The ETL stages themselves, each behind a narrow interface.
``orchestration`` / ``pipeline``
    DAG construction, scheduling, checkpointing and run execution.
``services`` / ``cli`` / ``api``
    Application-level facades and the delivery mechanisms.
"""

from __future__ import annotations

from ironflow.version import __version__

__all__ = ["__version__"]
