"""Transformation package.

Importing it registers every built-in transformation with
:data:`TRANSFORM_REGISTRY`, which is what makes ``type: mask_pii`` resolvable
from a pipeline definition.
"""

from __future__ import annotations

# Registration side effects - required, not incidental.
from ironflow.transformation import blocking as _blocking  # noqa: F401
from ironflow.transformation import ops as _ops  # noqa: F401
from ironflow.transformation.base import (
    TRANSFORM_REGISTRY,
    BaseTransformation,
    RecordTransformation,
    StreamTransformation,
    Transformation,
    build_transformation,
    transformation,
)
from ironflow.transformation.engine import StepStats, TransformationPipeline

__all__ = [
    "TRANSFORM_REGISTRY",
    "BaseTransformation",
    "RecordTransformation",
    "StepStats",
    "StreamTransformation",
    "Transformation",
    "TransformationPipeline",
    "build_transformation",
    "transformation",
]
