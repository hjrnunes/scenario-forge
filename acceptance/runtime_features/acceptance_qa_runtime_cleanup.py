"""Registration facade for the QA runtime cleanup feature."""

from __future__ import annotations

from .acceptance_qa_runtime_cleanup_checks import register_runtime_handlers
from .acceptance_qa_runtime_cleanup_harness import register_harness_handlers

FEATURE_ID = "acceptance_qa_runtime_cleanup"


def register(api: object) -> None:
    """Register the QA characterization handlers without a second identity."""
    api.set_feature(None)
    register_harness_handlers(api)
    register_runtime_handlers(api)
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
