"""OpenAI-compatible LLM client — clean copy for the STPA pipeline.

This is a clean copy of the LLM client from ``scenario_forge.llm.client``
with zero coupling to the existing pipeline. Same OpenAI-compatible
interface.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from openai import OpenAI
from pydantic import BaseModel, Field

DEFAULT_TEMPERATURE: float = 0.4

_OPENROUTER_DEFAULT_HEADERS: dict[str, str] = {
    "HTTP-Referer": "https://github.com/hjrnunes/scenario-forge",
    "X-Title": "scenario-forge",
}


def _resolve_temperature(
    explicit: float | None,
    env_var: str | None,
) -> float:
    """Resolve the effective temperature from explicit arg or env var."""
    if explicit is not None:
        return explicit
    if env_var is not None:
        return float(env_var)
    return DEFAULT_TEMPERATURE


def _resolve_max_tokens(
    explicit: int | None,
    env_var: str | None,
) -> int | None:
    """Resolve the effective max_completion_tokens from explicit arg or env var."""
    if explicit is not None:
        return explicit
    return int(env_var) if env_var else None


def _resolve_base_url(explicit: str | None) -> str | None:
    """Resolve base_url from explicit arg or environment."""
    return explicit or os.environ.get("SCENARIO_FORGE_MODEL_BASE_URL") or None


def _resolve_api_key(explicit: str | None) -> str:
    """Resolve API key from explicit arg or environment."""
    return explicit or os.environ.get("SCENARIO_FORGE_API_KEY", "unused")


def _resolve_model(explicit: str | None) -> str:
    """Resolve model name from explicit arg or environment."""
    return explicit or os.environ.get(
        "SCENARIO_FORGE_MODEL_NAME", "gemma-3n-e4b-it"
    )


def _resolve_extra_headers(
    base_url: str | None,
    explicit: dict[str, str] | None,
    env_raw: str | None,
) -> dict[str, str] | None:
    """Merge explicit headers, env-var headers, and OpenRouter defaults."""
    env_headers: dict[str, str] = json.loads(env_raw) if env_raw else {}
    merged: dict[str, str] = {**env_headers, **(explicit or {})}
    _inject_openrouter_headers(merged, base_url)
    return merged if merged else None


def _inject_openrouter_headers(
    merged: dict[str, str], base_url: str | None
) -> None:
    """Inject OpenRouter default headers if the base URL points to OpenRouter."""
    if base_url and "openrouter.ai" in base_url:
        for key, default in _OPENROUTER_DEFAULT_HEADERS.items():
            merged.setdefault(key, default)


class LLMResult(BaseModel):
    """Wrapper carrying the LLM response plus usage telemetry."""

    content: Any = Field(description="Parsed model instance or raw text string.")
    prompt_tokens: int = Field(description="Prompt tokens consumed.")
    completion_tokens: int = Field(description="Completion tokens generated.")
    duration_ms: int = Field(description="Wall-clock duration in milliseconds.")
    system_prompt: str = Field(default="", description="System prompt sent to the LLM.")
    user_prompt: str = Field(default="", description="User prompt sent to the LLM.")


class LLMClient:
    """Thin wrapper around the OpenAI SDK for structured and unstructured completions."""

    DEFAULT_TEMPERATURE: float = DEFAULT_TEMPERATURE

    _OPENROUTER_DEFAULT_HEADERS: dict[str, str] = _OPENROUTER_DEFAULT_HEADERS

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.base_url = _resolve_base_url(base_url)
        self.api_key = _resolve_api_key(api_key)
        self.model = _resolve_model(model)
        self.max_completion_tokens = _resolve_max_tokens(
            max_completion_tokens,
            os.environ.get("SCENARIO_FORGE_MAX_COMPLETION_TOKENS"),
        )
        self.temperature = _resolve_temperature(
            temperature, os.environ.get("SCENARIO_FORGE_TEMPERATURE")
        )
        self.extra_headers = _resolve_extra_headers(
            self.base_url,
            extra_headers,
            os.environ.get("SCENARIO_FORGE_EXTRA_HEADERS"),
        )

        if not self.base_url:
            raise ValueError(
                "No LLM endpoint configured."
                " Set SCENARIO_FORGE_MODEL_BASE_URL or pass --base-url."
            )
        self._client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            default_headers=self.extra_headers or None,
        )

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type[BaseModel] | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        effective_max = max_completion_tokens or self.max_completion_tokens
        effective_temp = temperature if temperature is not None else self.temperature

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        extra_kwargs: dict[str, Any] = {"temperature": effective_temp}
        if effective_max is not None:
            extra_kwargs["max_completion_tokens"] = effective_max

        t0 = time.perf_counter_ns()

        if response_format is not None:
            response = self._client.beta.chat.completions.parse(
                model=self.model,
                messages=messages,
                response_format=response_format,
                **extra_kwargs,
            )
            content = response.choices[0].message.parsed
        else:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                **extra_kwargs,
            )
            content = response.choices[0].message.content

        duration_ms = (time.perf_counter_ns() - t0) // 1_000_000
        usage = (
            response.usage
            or type("U", (), {"prompt_tokens": 0, "completion_tokens": 0})()
        )

        return LLMResult(
            content=content,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            duration_ms=duration_ms,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
