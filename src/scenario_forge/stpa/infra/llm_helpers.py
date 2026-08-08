"""Shared helpers for LLM result parsing and call logging.

Eliminates duplication of the ``_parse_*`` and ``_log_call`` patterns
that would otherwise be copy-pasted in every stage module.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from scenario_forge.stpa.infra.call_log import append_call_log, make_call_log_entry
from scenario_forge.stpa.infra.llm import LLMResult


def parse_llm_result(result: LLMResult, model_class: type[BaseModel]) -> BaseModel:
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:46:09Z","module_hash":"a1b7aad0a3fe2a93a11eabd799102851a999caea1bbf1117a7d368018839c121","functions":[{"id":"func/parse_llm_result","name":"parse_llm_result","line":18,"end_line":46,"hash":"e4d2fe9b6dad2e2b56503eba252efc1fba9a47d4641ba96ea4f03e42348869e6"},{"id":"func/log_llm_call","name":"log_llm_call","line":49,"end_line":76,"hash":"adb889755e90f94601e1524f9499750950888cfa3e5d708ea65462d1aeb96c7c"}]}
# mutate4py-manifest-end
