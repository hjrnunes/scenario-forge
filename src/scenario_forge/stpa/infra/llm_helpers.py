"""Shared helpers for LLM result parsing and call logging.

Eliminates duplication of the ``_parse_*`` and ``_log_call`` patterns
that would otherwise be copy-pasted in every stage module.
"""

from __future__ import annotations

import json
from pathlib import Path
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
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=result.system_prompt,
        user_prompt=result.user_prompt,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        duration_ms=result.duration_ms,
        success=True,
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
    entry = make_call_log_entry(
        stage=stage,
        step=step,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        duration_ms=duration_ms,
        success=False,
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
        result = llm_client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            temperature=temperature,
        )
        model = parse_llm_result(result, response_format)
        log_llm_call(result, llm_client.model, run_dir, stage, step)
        return model, result, None
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log_llm_call_failure(
            llm_client.model,
            run_dir,
            stage,
            step,
            error_msg,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            prompt_tokens=result.prompt_tokens if result else 0,
            completion_tokens=result.completion_tokens if result else 0,
            duration_ms=result.duration_ms if result else 0,
        )
        return None, result, error_msg
# {"version":1,"tested_at":"2026-08-08T14:46:09Z","module_hash":"a1b7aad0a3fe2a93a11eabd799102851a999caea1bbf1117a7d368018839c121","functions":[{"id":"func/parse_llm_result","name":"parse_llm_result","line":18,"end_line":46,"hash":"e4d2fe9b6dad2e2b56503eba252efc1fba9a47d4641ba96ea4f03e42348869e6"},{"id":"func/log_llm_call","name":"log_llm_call","line":49,"end_line":76,"hash":"adb889755e90f94601e1524f9499750950888cfa3e5d708ea65462d1aeb96c7c"}]}
# mutate4py-manifest-end
