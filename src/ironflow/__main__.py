"""Allow ``python -m ironflow`` as well as the ``ironflow`` console script."""

from __future__ import annotations

from ironflow.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
