"""Shared helpers for LLM result parsing and call logging.

Eliminates duplication of the ``_parse_*`` and ``_log_call`` patterns
that would otherwise be copy-pasted in every stage module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from typing import TypeVar

from pydantic import BaseModel

from scenario_forge.stpa.infra.call_log import append_call_log, make_call_log_entry
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult

_T = TypeVar("_T", bound=BaseModel)


class StageError(Exception):
    """Exception carrying stage and step context for a failed LLM call.

    Attributes:
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
        message: Human-readable error description.
    """

    def __init__(self, *, stage: str, step: str, message: str) -> None:
        self.stage = stage
        self.step = step
        self.message = message
        super().__init__(f"{stage}/{step}: {message}")


def _stringify_response_content(content: Any) -> str:
    """Convert LLM response content to a string for logging.

    Handles Pydantic models, dicts, and raw strings.
    """
    if content is None:
        return ""
    if isinstance(content, BaseModel):
        return content.model_dump_json()
    if isinstance(content, dict):
        return json.dumps(content)
    return str(content)


def parse_llm_result(result: LLMResult, model_class: type[_T]) -> _T:
    """Parse and validate an LLM result into the specified Pydantic model.

    Handles three content types the LLM client may return:
    - An already-parsed model instance (returned as-is).
    - A plain dict (validated via ``model_validate``).
    - A JSON string (parsed then validated).

    Args:
        result: The LLM result wrapper.
        model_class: The target Pydantic model class.

    Returns:
        A validated instance of *model_class*.

    Raises:
        ValidationError: If the content cannot be parsed into *model_class*.
    """
    content = result.content
    if isinstance(content, model_class):
        return content
    if isinstance(content, dict):
        return model_class.model_validate(content)
    if isinstance(content, str):
        return model_class.model_validate(json.loads(content))
    raise TypeError(
        f"Unexpected LLM result content type: {type(content).__name__}, "
        f"expected {model_class.__name__}, dict, or str."
    )


def log_llm_call(
    result: LLMResult,
    model: str,
    run_dir: Path,
    stage: str,
    step: str,
) -> None:
    """Append a call-log entry for a single LLM call.

    Args:
        result: The LLM result wrapper (provides prompts and token counts).
        model: The model name used for the call.
        run_dir: Directory where ``calls.jsonl`` is appended.
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
    """
    _success = True
    _response_content = _stringify_response_content(result.content)
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=result.system_prompt,
        user_prompt=result.user_prompt,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        duration_ms=result.duration_ms,
        success=_success,
        response_content=_response_content,
    )
    append_call_log([entry], run_dir)


def log_llm_call_failure(
    model: str,
    run_dir: Path,
    stage: str,
    step: str,
    error: str,
    *,
    system_prompt: str = "",
    user_prompt: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    duration_ms: int = 0,
) -> None:
    """Append a call-log entry for a failed LLM call.

    Args:
        model: The model name used for the call.
        run_dir: Directory where ``calls.jsonl`` is appended.
        stage: Pipeline stage identifier (e.g. ``"stage_1a"``).
        step: Sub-step within the stage (e.g. ``"loss_analysis"``).
        error: Error message describing the failure.
        system_prompt: System prompt text (hashed in the entry).
        user_prompt: User prompt text (hashed in the entry).
        prompt_tokens: Prompt tokens consumed (0 if call failed before completion).
        completion_tokens: Completion tokens generated (0 if call failed before completion).
        duration_ms: Wall-clock duration in milliseconds (0 if not measured).
    """
    _success = False
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        duration_ms=duration_ms,
        success=_success,
        error=error,
    )
    append_call_log([entry], run_dir)


def safe_llm_call(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_format: type[_T],
    run_dir: Path,
    stage: str,
    step: str,
    temperature: float = 0.4,
    max_completion_tokens: int | None = None,
) -> tuple[_T | None, LLMResult | None, str | None]:
    """Wrap complete() + parse_llm_result() in a try/except.

    On success, logs the call and returns ``(model, result, None)``.
    On failure, logs the failure and returns ``(None, result_or_none, error_msg)``.

    Args:
        llm_client: LLM client for making the completion call.
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        response_format: Target Pydantic model class for validation.
        run_dir: Directory for call logging.
        stage: Pipeline stage identifier.
        step: Sub-step within the stage.
        temperature: LLM temperature.

    Returns:
        A tuple of (validated_model_or_None, llm_result_or_None, error_or_None).
    """
    result: LLMResult | None = None
    try:
        completion_kwargs: dict[str, Any] = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "response_format": response_format,
            "temperature": temperature,
        }
        if max_completion_tokens is not None:
            completion_kwargs["max_completion_tokens"] = max_completion_tokens
        result = llm_client.complete(**completion_kwargs)
        model = parse_llm_result(result, response_format)
        log_llm_call(result, llm_client.model, run_dir, stage, step)
        return model, result, None
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        _prompt_tokens = result.prompt_tokens if result else 0
        _completion_tokens = result.completion_tokens if result else 0
        _duration_ms = result.duration_ms if result else 0
        log_llm_call_failure(
            llm_client.model,
            run_dir,
            stage,
            step,
            error_msg,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            prompt_tokens=_prompt_tokens,
            completion_tokens=_completion_tokens,
            duration_ms=_duration_ms,
        )
        return None, result, error_msg


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T17:33:19Z","module_hash":"a9545fefb6074e131851a42e118d754b7c5377a7d6b16917d358347553b80136","functions":[{"id":"func/StageError.__init__","name":"__init__","line":31,"end_line":35,"hash":"4177d4e5e3c335fffd74f73fc638a1c010bb0f05f4b7e84916530ad1645c17d1"},{"id":"func/_stringify_response_content","name":"_stringify_response_content","line":38,"end_line":49,"hash":"30a802977ac66248fc75381524437bf35ae060be960a6a1419ba85619bab2749"},{"id":"func/parse_llm_result","name":"parse_llm_result","line":52,"end_line":80,"hash":"f964028962706a4a0bac14d30116ce175f98f2d2aef982ba8ef8e645c97007e9"},{"id":"func/log_llm_call","name":"log_llm_call","line":83,"end_line":113,"hash":"fd1b0e43e50c09a009cc79191121c7382e9b9410f143dabb277bb2d73c0d5d28"},{"id":"func/log_llm_call_failure","name":"log_llm_call_failure","line":116,"end_line":156,"hash":"632647e67fc23888061cf77c9b9883892d59b9b33e1807a4b8cb535580329751"},{"id":"func/safe_llm_call","name":"safe_llm_call","line":159,"end_line":216,"hash":"ab6564f555f4b0c4238f11e716965aeb20123bd254f0236e603b75ac6219a932"}]}
# mutate4py-manifest-end
