"""Deterministic, validated manifest for acceptance runtime features."""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

MODULES = (
    'foundation',
    'infrastructure',
    'models',
    'sp1',
    'sp1_revision',
    'parallel_llm',
    'stage2',
    'sp2',
    'sp3',
    'report',
    'stage1_split',
    'acceptance_refresh',
    'critic_revision_fix',
    'shadow_cleanup',
)


def load_modules() -> tuple[ModuleType, ...]:
    """Load and validate the complete feature manifest before registration."""
    if len(MODULES) != len(set(MODULES)):
        raise RuntimeError("runtime feature manifest contains duplicate modules")
    expected = set(__import__("runtime_features").__all__)
    if set(MODULES) != expected:
        missing = sorted(expected - set(MODULES))
        omitted = sorted(set(MODULES) - expected)
        raise RuntimeError(f"runtime feature manifest mismatch: missing={missing}, omitted={omitted}")
    modules = tuple(importlib.import_module(f"runtime_features.{name}") for name in MODULES)
    for name, module in zip(MODULES, modules):
        if getattr(module, "FEATURE_ID", None) != name:
            raise RuntimeError(f"runtime feature {name} has invalid FEATURE_ID")
        register = getattr(module, "register", None)
        if not callable(register):
            raise RuntimeError(f"runtime feature {name} does not expose register(api)")
    return modules


def register_all(api: Any, modules: tuple[ModuleType, ...] | None = None) -> None:
    """Invoke each validated feature registration exactly once."""
    selected = load_modules() if modules is None else modules
    if len(selected) != len(MODULES):
        raise RuntimeError("runtime feature registration set is incomplete")
    for name, module in zip(MODULES, selected):
        if getattr(module, "FEATURE_ID", None) != name:
            raise RuntimeError(f"runtime feature order mismatch at {name}")
        try:
            module.register(api)
        except Exception as exc:
            raise RuntimeError(
                f"runtime feature {name} registration failed: {exc}"
            ) from exc
