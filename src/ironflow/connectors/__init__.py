"""Connector package.

Importing this package registers every built-in connector with
:data:`SOURCE_REGISTRY` / :data:`SINK_REGISTRY`.  The imports at the bottom are
therefore load-bearing, not incidental: they are what makes ``type: csv``
resolvable from a pipeline file.

Optional-dependency connectors (Parquet, Excel, SFTP, FTP) are imported inside a
guard, so a slim installation still gets a working platform and only fails - with
an actionable message - if a pipeline actually asks for one of them.
"""

from __future__ import annotations

import logging

from ironflow.connectors.base import (
    SINK_REGISTRY,
    SOURCE_REGISTRY,
    BaseConnector,
    BaseSink,
    BaseSource,
    ConnectorRuntime,
    sink,
    source,
)
from ironflow.connectors.factory import ConnectorFactory, describe_connectors

logger = logging.getLogger(__name__)

# -- always available ------------------------------------------------------- #
from ironflow.connectors import files as _files  # noqa: E402,F401
from ironflow.connectors import http as _http  # noqa: E402,F401
from ironflow.connectors import memory as _memory  # noqa: E402,F401
from ironflow.connectors import sql as _sql  # noqa: E402,F401

# -- optional extras -------------------------------------------------------- #
try:  # pragma: no cover - exercised by the extras matrix in CI
    from ironflow.connectors import columnar as _columnar  # noqa: F401
except ImportError:  # pragma: no cover
    logger.debug("columnar connectors unavailable (install the 'columnar'/'excel' extras)")

try:  # pragma: no cover
    from ironflow.connectors import remote as _remote  # noqa: F401
except ImportError:  # pragma: no cover
    logger.debug("remote connectors unavailable (install the 'remote' extra)")

__all__ = [
    "SINK_REGISTRY",
    "SOURCE_REGISTRY",
    "BaseConnector",
    "BaseSink",
    "BaseSource",
    "ConnectorFactory",
    "ConnectorRuntime",
    "describe_connectors",
    "sink",
    "source",
]
