"""The configuration reference must document every setting that exists.

docs/configuration.md calls itself the full reference, and it had quietly
fallen behind: four settings existed that it never mentioned.  An operator
reading it could not know that ``IRONFLOW_HTTP_MAX_RESPONSE_BYTES`` bounded
anything, or that ``IRONFLOW_PIPELINE_ENV`` was needed to start in production.
"""

from __future__ import annotations

from pathlib import Path

from ironflow.config.settings import Settings

REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "configuration.md"


def test_every_setting_is_documented():
    text = REFERENCE.read_text(encoding="utf-8")
    missing = [
        f"IRONFLOW_{name.upper()}"
        for name in Settings.model_fields
        if f"`IRONFLOW_{name.upper()}`" not in text
    ]
    assert missing == [], f"undocumented settings: {missing}"
