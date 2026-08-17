"""Execution outcome contract handlers."""

from __future__ import annotations

import os
import re

from live_llm_opt_in import LIVE_LLM_ACCEPTANCE_MARKER
from runtime_world import World

from framework_contracts_common import (
    _AFR_SUPPORTED_STEP,
    _feature_ir,
    _write_ir,
)


def _h_afr_contract_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r'an isolated IR scenario named "contract" has the (.+)', text)
    if match is None:
        return False, f"Could not parse contract condition: {text}"
    world.afr_contract_condition = match.group(1)
    return True, ""


def _h_afr_contract_supported(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_afr_contract_execute(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    import acceptance_runtime

    condition = world.afr_contract_condition
    if condition == "supported passing step":
        steps = [_AFR_SUPPORTED_STEP]
    elif condition == "exact live-LLM marker":
        steps = [LIVE_LLM_ACCEPTANCE_MARKER]
    else:
        steps = ["acceptance framework unsupported contract step"]
    ir_path = _write_ir(_feature_ir(name="contract", steps=steps))
    saved = os.environ.pop("SCENARIO_FORGE_QA_PIPELINE", None)
    try:
        world.afr_contract_result, world.afr_contract_output = (
            acceptance_runtime.execute_ir(str(ir_path))
        )
    finally:
        if saved is not None:
            os.environ["SCENARIO_FORGE_QA_PIPELINE"] = saved
    return True, ""


def _h_afr_contract_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r"its result is (true|false)", text.strip(), re.IGNORECASE)
    if match is None:
        return False, f"Could not parse contract result: {text}"
    expected = match.group(1).casefold() == "true"
    actual = bool(world.afr_contract_result)
    return actual == expected, f"expected result {expected}, got {actual}"


def _h_afr_contract_output(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r'its output begins with "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse output assertion: {text}"
    expected = match.group(1)
    actual = (
        world.afr_contract_output.splitlines()[0] if world.afr_contract_output else ""
    )
    return actual.startswith(expected), f"unexpected output: {actual}"
