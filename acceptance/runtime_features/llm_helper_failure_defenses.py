"""Acceptance handlers for deterministic LLM-helper failure behavior."""

from __future__ import annotations

import inspect
import json
import re
import tempfile
from pathlib import Path

from pydantic import BaseModel

from scenario_forge.stpa.infra.llm import LLMResult
from scenario_forge.stpa.infra.llm_helpers import (
    log_llm_call_failure,
    safe_llm_call,
)
from runtime_shared import World

_ERRORS = {
    "unexpected keyword argument 'allow_unvalidated'",
    "response_format is the wrong type",
}


class _FailureDefenseResponse(BaseModel):
    """Minimal structured response used by the failure-defense scenarios."""

    value: str


class _FailureDefenseClient:
    """Client double whose first completion can fail predictably."""

    model = "failure-defense-model"

    def __init__(
        self,
        *,
        first_error: str | None = None,
        result: LLMResult | None = None,
    ) -> None:
        self.first_error = first_error
        self.result = result or LLMResult(
            content={"value": "recovered"},
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
        )
        self.attempt_count = 0

    def complete(self, **kwargs: object) -> LLMResult:
        """Return the configured result after the optional first failure."""
        self.attempt_count += 1
        if self.attempt_count == 1 and self.first_error is not None:
            raise TypeError(self.first_error)
        return self.result


def _run_dir(world: World) -> Path:
    """Return the scenario's isolated call-log directory."""
    run_dir = getattr(world, "llm_failure_run_dir", None)
    if run_dir is None:
        run_dir = Path(tempfile.mkdtemp(prefix="llm_failure_defenses_"))
        world.llm_failure_run_dir = run_dir
    return run_dir


def _call_log_entry(world: World) -> dict:
    """Read the single call-log entry produced by a scenario."""
    path = _run_dir(world) / "calls.jsonl"
    if not path.is_file():
        raise AssertionError(f"Missing call log: {path}")
    entries = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    if not entries:
        raise AssertionError("Call log is empty")
    return entries[-1]


def _h_llm_failure_run_dir(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a temporary directory is available for LLM call logging."""
    _run_dir(world)
    return True, ""


def _h_llm_failure_log_without_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: log a failure without explicitly supplied usage telemetry."""
    log_llm_call_failure(
        "failure-defense-model",
        _run_dir(world),
        "stage_test",
        "step_test",
        "expected failure",
    )
    return True, ""


def _h_llm_failure_zero_telemetry(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a missing failure-telemetry field defaults to zero."""
    match = re.search(r"for (\w+)$", text)
    if match is None:
        return False, f"Could not parse telemetry field from: {text}"
    field = match.group(1)
    entry = _call_log_entry(world)
    if entry.get(field) != 0:
        return False, f"Expected {field}=0, got {entry.get(field)!r}"
    return True, ""


def _h_llm_failure_client_type_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: configure the first completion attempt's TypeError."""
    match = re.search(r'TypeError "([^"]+)" on its first completion attempt$', text)
    if match is None:
        return False, f"Could not parse client error from: {text}"
    error = match.group(1)
    if error not in _ERRORS:
        return False, f"Unsupported client error: {error}"
    world.llm_failure_client_error = error
    return True, ""


def _h_llm_failure_safe_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: make a safe structured call with requested tolerance."""
    match = re.search(r"tolerant decoding (true|false)$", text)
    if match is None:
        return False, f"Could not parse tolerant decoding from: {text}"
    tolerant = match.group(1) == "true"
    client = _FailureDefenseClient(
        first_error=getattr(world, "llm_failure_client_error", None)
    )
    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        allow_unvalidated=tolerant,
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


def _h_llm_failure_attempt_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert the number of completion attempts."""
    match = re.search(r"count is (-?\d+)$", text)
    if match is None:
        return False, f"Could not parse attempt count from: {text}"
    expected = int(match.group(1))
    actual = getattr(getattr(world, "llm_failure_client", None), "attempt_count", 0)
    if actual != expected:
        return False, f"Expected {expected} completion attempts, got {actual}"
    return True, ""


def _h_llm_failure_outcome(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert whether compatibility recovery succeeded."""
    match = re.search(r"outcome is (\w+)$", text)
    if match is None:
        return False, f"Could not parse outcome from: {text}"
    expected = match.group(1)
    actual = getattr(world, "llm_failure_outcome", None)
    if actual != expected:
        return False, f"Expected outcome {expected}, got {actual}"
    return True, ""


def _h_llm_failure_signature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: inspect safe_llm_call's tolerant-decoding default."""
    parameter = inspect.signature(safe_llm_call).parameters.get("allow_unvalidated")
    if parameter is None:
        return False, "safe_llm_call has no allow_unvalidated parameter"
    if parameter.default is not False:
        return False, f"Expected default False, got {parameter.default!r}"
    return True, ""


def _h_llm_failure_result_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: configure a result carrying usage telemetry."""
    match = re.search(
        r"reports (-?\d+) prompt tokens, (-?\d+) completion tokens, "
        r"and (-?\d+) milliseconds$",
        text,
    )
    if match is None:
        return False, f"Could not parse result usage from: {text}"
    world.llm_failure_result = LLMResult(
        content="not valid JSON",
        prompt_tokens=int(match.group(1)),
        completion_tokens=int(match.group(2)),
        duration_ms=int(match.group(3)),
    )
    return True, ""


def _h_llm_failure_unparseable_content(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: mark the configured result as intentionally unparseable."""
    if not hasattr(world, "llm_failure_result"):
        return False, "No LLM result configured"
    return True, ""


def _h_llm_failure_process_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: process the result through safe_llm_call."""
    client = _FailureDefenseClient(result=world.llm_failure_result)
    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    if error is None:
        return False, "Expected response parsing to fail"
    return True, ""


def _h_llm_failure_usage_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: usage telemetry survives response parsing failure."""
    match = re.search(
        r"records prompt_tokens (-?\d+), completion_tokens (-?\d+), "
        r"and duration_ms (-?\d+)$",
        text,
    )
    if match is None:
        return False, f"Could not parse expected usage from: {text}"
    entry = _call_log_entry(world)
    expected = {
        "prompt_tokens": int(match.group(1)),
        "completion_tokens": int(match.group(2)),
        "duration_ms": int(match.group(3)),
    }
    actual = {field: entry.get(field) for field in expected}
    if actual != expected:
        return False, f"Expected usage {expected}, got {actual}"
    return True, ""


FEATURE_ID = "llm_helper_failure_defenses"


def register(api: object) -> None:
    """Register failure-defense acceptance handlers."""
    api.set_feature(None)
    api.register(
        "a temporary run directory for LLM call logging$",
        _h_llm_failure_run_dir,
        source_order=24001,
    )
    api.register(
        "an LLM call failure is logged without usage telemetry$",
        _h_llm_failure_log_without_usage,
        source_order=24002,
    )
    api.register(
        "the failure log entry records zero for",
        _h_llm_failure_zero_telemetry,
        source_order=24003,
    )
    api.register(
        "an LLM client raises TypeError .* on its first completion attempt$",
        _h_llm_failure_client_type_error,
        source_order=24004,
    )
    api.register(
        "a safe structured LLM call is made with tolerant decoding",
        _h_llm_failure_safe_call,
        source_order=24005,
    )
    api.register(
        "the completion attempt count is",
        _h_llm_failure_attempt_count,
        source_order=24006,
    )
    api.register(
        "the safe call outcome is",
        _h_llm_failure_outcome,
        source_order=24007,
    )
    api.register(
        "the safe structured LLM call signature is inspected$",
        _h_llm_failure_signature,
        source_order=24008,
    )
    api.register(
        "the tolerant-decoding argument defaults to false$",
        _h_llm_failure_signature,
        source_order=24009,
    )
    api.register(
        "an LLM result reports .* prompt tokens, .* completion tokens, and .* milliseconds$",
        _h_llm_failure_result_usage,
        source_order=24010,
    )
    api.register(
        "its content cannot be parsed as the response model$",
        _h_llm_failure_unparseable_content,
        source_order=24011,
    )
    api.register(
        "the result is processed by a safe structured LLM call$",
        _h_llm_failure_process_result,
        source_order=24012,
    )
    api.register(
        "the failure log entry records prompt_tokens .* completion_tokens .* and duration_ms",
        _h_llm_failure_usage_retained,
        source_order=24013,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
