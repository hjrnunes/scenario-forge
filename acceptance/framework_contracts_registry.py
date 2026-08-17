"""Registry publication and scoped resolution contract handlers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from registry import PatternRegistry, RegistrationAPI, RegistrationStage
from runtime_world import World

from framework_contracts_common import (
    _AFR_ATOMIC_STAGED_PATTERN,
    _AFR_PRIORITY_PATTERN,
)


def _h_afr_registry_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    registry = PatternRegistry()
    registry.register("acceptance framework published witness", _afr_noop_handler)
    world.afr_registry = registry
    world.afr_registry_patterns = [
        (pattern.pattern, id(handler), tag)
        for pattern, handler, tag in registry.patterns
    ]
    world.afr_registry_keys = set(registry.keys)
    return bool(world.afr_registry_patterns), "the acceptance registry is empty"


def _h_afr_registry_replacement(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    import runtime_manifest

    def valid_register(api: Any) -> None:
        api.register(_AFR_ATOMIC_STAGED_PATTERN, _afr_noop_handler)

    def failing_register(api: Any) -> None:
        api.register(
            "acceptance framework failing replacement witness", _afr_noop_handler
        )
        raise ValueError("injected registration failure")

    valid = SimpleNamespace(FEATURE_ID="replacement-valid", register=valid_register)
    failing = SimpleNamespace(
        FEATURE_ID="replacement-failing", register=failing_register
    )
    registry = world.afr_registry
    before_patterns = list(registry.patterns)
    before_keys = set(registry.keys)
    stage = RegistrationStage()
    api = RegistrationAPI(stage)
    try:
        runtime_manifest.register_one(api, valid.FEATURE_ID, valid)
        runtime_manifest.register_one(api, failing.FEATURE_ID, failing)
    except RuntimeError as exc:
        world.afr_registry_failure = str(exc)
    else:
        return False, "replacement registration unexpectedly succeeded"
    world.afr_registry_unchanged = (
        registry.patterns == before_patterns and registry.keys == before_keys
    )
    world.afr_staged_executable = any(
        pattern.pattern == _AFR_ATOMIC_STAGED_PATTERN
        for pattern, _, _ in registry.patterns
    )
    return True, ""


def _h_afr_registry_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    failure = getattr(world, "afr_registry_failure", "")
    return (
        "replacement-failing" in failure,
        f"failure did not identify runtime feature: {failure}",
    )


def _h_afr_registry_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        bool(getattr(world, "afr_registry_unchanged", False)),
        "published registry changed after failed replacement",
    )


def _h_afr_registry_not_executable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        not bool(getattr(world, "afr_staged_executable", True)),
        "staged replacement pattern was published",
    )


def _afr_noop_handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


def _h_afr_scoped_registry(world: World, text: str, examples: dict) -> tuple[bool, str]:
    counts = {"global": 0, "first": 0, "other": 0}

    def make_handler(name: str):
        def handler(inner_world: World, inner_text: str, inner_examples: dict):
            counts[name] += 1
            return True, ""

        return handler

    stage = RegistrationStage()
    api = RegistrationAPI(stage)
    api.register(_AFR_PRIORITY_PATTERN, make_handler("global"), source_order=30)
    api.set_feature("first-feature")
    api.register_first(_AFR_PRIORITY_PATTERN, make_handler("first"), source_order=10)
    api.set_feature("other-feature")
    api.register_first(_AFR_PRIORITY_PATTERN, make_handler("other"), source_order=20)
    api.set_feature(None)
    registry = PatternRegistry()
    registry.publish(stage)
    first_handler = registry.resolve(_AFR_PRIORITY_PATTERN, "first-feature")
    unscoped_handler = registry.resolve(_AFR_PRIORITY_PATTERN, None)
    first_success, first_error = first_handler(World(), _AFR_PRIORITY_PATTERN, {})
    unscoped_success, unscoped_error = unscoped_handler(
        World(), _AFR_PRIORITY_PATTERN, {}
    )

    world.afr_scope_counts = counts
    world.afr_scope_results = (
        first_success,
        first_error,
        unscoped_success,
        unscoped_error,
    )
    return True, ""


def _h_afr_other_scope_ineligible(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        world.afr_scope_counts["other"] == 0,
        f"other feature handler executed: {world.afr_scope_counts}",
    )


def _h_afr_first_scope_priority(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    counts = world.afr_scope_counts
    return (
        counts == {"global": 1, "first": 1, "other": 0},
        f"unexpected scoped resolution counts: {counts}",
    )


def _h_afr_unscoped_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    success, error = world.afr_scope_results[2:]
    counts = world.afr_scope_counts
    return (
        success and not error and counts == {"global": 1, "first": 1, "other": 0},
        f"unscoped resolution selected a scoped handler: {counts}, {error}",
    )
