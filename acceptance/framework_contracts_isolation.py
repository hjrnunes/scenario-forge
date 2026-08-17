"""Scenario and process isolation contract handlers."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_world import World

from framework_contracts_common import (
    _AFR_BACKGROUND_STEP,
    _AFR_MUTATION_STEP,
    _AFR_SCENARIO_STEP,
    _AFR_ENVIRONMENT_VARIABLE,
    _ISOLATION_STATE_STACK,
    _fixture_state,
    _feature_ir,
)


def _h_afr_isolation_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"before it (passes|fails)$", text)
    if match is None:
        return False, f"Could not parse isolation result: {text}"
    state = {
        "requested_result": match.group(1),
        "original_environment": dict(os.environ),
        "before_feature": None,
        "observations": {},
    }
    _ISOLATION_STATE_STACK.append(state)
    world.afr_isolation_state = state
    return True, ""


def _h_afr_isolation_mutation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _fixture_state()
    row = examples.get("row", "")
    record = state["observations"].setdefault(row, {})
    record["mutation_world"] = getattr(world, "afr_world_token", None)
    if row == "first":
        world.afr_mutated = True
        os.environ[_AFR_ENVIRONMENT_VARIABLE] = "changed-by-first-example"
        record["changed_environment"] = True
    else:
        record["changed_environment"] = False
    return True, ""


def _h_afr_isolation_background(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _fixture_state()
    row = examples.get("row", "")
    record = state["observations"].setdefault(row, {})
    world.afr_world_token = object()
    record["background_world"] = world.afr_world_token
    record["background_environment"] = dict(os.environ)
    return True, ""


def _h_afr_isolation_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _fixture_state()
    row = examples.get("row", "")
    record = state["observations"].setdefault(row, {})
    record["scenario_world"] = getattr(world, "afr_world_token", None)
    record["scenario_environment"] = dict(os.environ)
    record["same_world"] = record.get("background_world") == record.get(
        "scenario_world"
    )
    if row == "first" and state["requested_result"] == "fails":
        return False, "injected first-example failure"
    return True, ""


def _h_afr_isolation_ir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import acceptance_runtime

    state = _fixture_state()
    state["before_feature"] = acceptance_runtime._CURRENT_EXECUTION_FEATURE
    root = Path(tempfile.mkdtemp(prefix="acceptance-refresh-nested-"))
    ir_path = root / "acceptance-refresh" / "nested.json"
    ir_path.parent.mkdir(parents=True)
    ir_path.write_text(
        json.dumps(
            _feature_ir(
                name="nested isolation",
                background=[_AFR_BACKGROUND_STEP],
                steps=[_AFR_MUTATION_STEP, _AFR_SCENARIO_STEP],
                examples=[{"row": "first"}, {"row": "second"}],
            )
        ),
        encoding="utf-8",
    )
    try:
        state["result"], state["output"] = acceptance_runtime.execute_ir(str(ir_path))
        state["after_environment"] = dict(os.environ)
        state["after_feature"] = acceptance_runtime._CURRENT_EXECUTION_FEATURE
    finally:
        _ISOLATION_STATE_STACK.pop()
    world.afr_isolation_observations = state["observations"]
    world.afr_isolation_state = state
    return True, ""


def _h_afr_isolation_observers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = world.afr_isolation_state
    for passed, error in _isolation_checks(state):
        if not passed:
            return False, error
    return True, ""


def _isolation_checks(state: dict[str, Any]) -> list[tuple[bool, str]]:
    observations = state["observations"]
    first = observations.get("first", {})
    second = observations.get("second", {})
    original = state["original_environment"]
    return [
        (
            bool(second.get("same_world")),
            f"second example did not share its world: {observations}",
        ),
        (
            first.get("background_world") != second.get("background_world"),
            f"examples reused a world: {observations}",
        ),
        (
            second.get("background_environment") == original,
            "second example inherited process environment changes",
        ),
        (
            second.get("scenario_environment") == original,
            "second scenario inherited process environment changes",
        ),
        (
            state.get("requested_result") != "passes" or bool(first.get("same_world")),
            f"passing example did not share its world: {observations}",
        ),
    ]


def _h_afr_isolation_environment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = world.afr_isolation_state
    return (
        state.get("after_environment") == state.get("original_environment"),
        "process environment was not restored after IR execution",
    )


def _h_afr_isolation_feature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = world.afr_isolation_state
    return (
        state.get("after_feature") == state.get("before_feature"),
        "enclosing feature context was not restored",
    )
