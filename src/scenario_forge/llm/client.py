"""OpenAI-compatible LLM client for scenario-forge."""

from __future__ import annotations

import os
import time
from typing import Any

from openai import OpenAI
from pydantic import BaseModel, Field


class LLMResult(BaseModel):
    """Wrapper carrying the LLM response plus usage telemetry."""

    content: Any = Field(description="Parsed model instance or raw text string.")
    prompt_tokens: int = Field(description="Prompt tokens consumed.")
    completion_tokens: int = Field(description="Completion tokens generated.")
    duration_ms: int = Field(description="Wall-clock duration in milliseconds.")


class LLMClient:
    """Thin wrapper around the OpenAI SDK for structured and unstructured completions."""

    # Previous default of 16384 caused truncation failures on complex
    # scenarios (e.g. T7-S1 hit the cap exactly). 32768 doubles headroom
    # and can be tuned per-deployment via SCENARIO_FORGE_MAX_COMPLETION_TOKENS.
    _DEFAULT_MAX_COMPLETION_TOKENS = 32768

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        max_completion_tokens: int | None = None,
    ) -> None:
        self.base_url = base_url or os.environ.get("SCENARIO_FORGE_MODEL_BASE_URL", "")
        self.api_key = api_key or os.environ.get("SCENARIO_FORGE_API_KEY", "unused")
        self.model = model or os.environ.get("SCENARIO_FORGE_MODEL_NAME", "gemma-3n-e4b-it")
        self.max_completion_tokens = max_completion_tokens or int(
            os.environ.get(
                "SCENARIO_FORGE_MAX_COMPLETION_TOKENS",
                str(self._DEFAULT_MAX_COMPLETION_TOKENS),
            )
        )
        self._client = OpenAI(base_url=self.base_url, api_key=self.api_key)

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel] | None = None,
        max_completion_tokens: int | None = None,
    ) -> LLMResult:
        effective_max = max_completion_tokens or self.max_completion_tokens

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        t0 = time.perf_counter_ns()

        if response_format is not None:
            response = self._client.beta.chat.completions.parse(
                model=self.model,
                messages=messages,
                response_format=response_format,
                max_completion_tokens=effective_max,
            )
            content = response.choices[0].message.parsed
        else:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_completion_tokens=effective_max,
            )
            content = response.choices[0].message.content

        duration_ms = (time.perf_counter_ns() - t0) // 1_000_000
        usage = response.usage or type("U", (), {"prompt_tokens": 0, "completion_tokens": 0})()

        return LLMResult(
            content=content,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            duration_ms=duration_ms,
        )
