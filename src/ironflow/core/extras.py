"""What each optional extra installs, for messages that say how to get one.

The advice names an extra's own packages and never ``ironflow[extra]``.
IronFlow is not published on PyPI, and the ``ironflow`` distribution there is
an unrelated project, so installing ``ironflow[columnar]`` by that name - where
IronFlow was not installed yet - installs someone else's code.
"""

from __future__ import annotations

#: The optional extras declared in ``pyproject.toml``, which a test keeps in step.
EXTRAS: dict[str, tuple[str, ...]] = {
    "columnar": ("pyarrow>=15", "pandas>=2.2"),
    "excel": ("openpyxl>=3.1",),
    "remote": ("paramiko>=3.4",),
    "api": ("fastapi>=0.111", "uvicorn[standard]>=0.29"),
    "postgres": ("psycopg[binary]>=3.1",),
    "mysql": ("PyMySQL>=1.1",),
}


def install_hint(extra: str) -> str:
    """The ``pip install`` command for the packages ``extra`` adds."""
    return "pip install " + " ".join(f"'{requirement}'" for requirement in EXTRAS[extra])


__all__ = ["EXTRAS", "install_hint"]
