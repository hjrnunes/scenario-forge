"""Scenario-example lifecycle for the acceptance runtime.

The lifecycle owns only per-example state and process-environment restoration.
Registry resolution and feature-module loading are separate concerns.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from runtime_world import World

StepExecutor = Callable[[World, dict[str, Any], Mapping[str, Any]], tuple[bool, str]]


def restore_environment(saved: Mapping[str, str]) -> None:
    """Restore the complete process environment captured before an example."""
    os.environ.clear()
    os.environ.update(saved)


@dataclass
class ScenarioContext:
    """State and environment boundary for one scenario example."""

    world: World
    original_environment: dict[str, str]

    @classmethod
    def create(cls) -> "ScenarioContext":
        return cls(world=World(), original_environment=dict(os.environ))

    def restore(self) -> None:
        restore_environment(self.original_environment)


@contextmanager
def scenario_context() -> Any:
    """Yield a fresh world and restore process state on every exit path."""
    context = ScenarioContext.create()
    try:
        yield context
    finally:
        context.restore()


@dataclass(frozen=True)
class StepRunResult:
    """Result of running one background or scenario step sequence."""

    passed: bool
    error: str = ""
    failed_kind: str | None = None


def run_steps(
    world: World,
    steps: Iterable[dict[str, Any]],
    examples: Mapping[str, Any],
    execute_step: StepExecutor,
    *,
    kind: str,
) -> StepRunResult:
    """Run a step sequence and stop at its first failure."""
    for step in steps:
        passed, error = execute_step(world, step, examples)
        if not passed:
            return StepRunResult(False, error, kind)
    return StepRunResult(True)


__all__ = [
    "ScenarioContext",
    "StepRunResult",
    "restore_environment",
    "run_steps",
    "scenario_context",
]
