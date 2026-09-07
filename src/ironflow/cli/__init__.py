"""Command-line interface package.

Only ``app`` is re-exported here.  A ``main`` re-export would shadow the
``ironflow.cli.main`` submodule of the same name, so ``import
ironflow.cli.main`` would bind the *function* rather than the module - a subtle
trap for anything that introspects or patches the module.  The console script
targets ``ironflow.cli.main:main`` directly and does not need the shortcut.
"""

from __future__ import annotations

from ironflow.cli.main import app

__all__ = ["app"]
