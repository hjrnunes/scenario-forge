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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T12:26:55Z","module_hash":"7c73ed1b6c6b80e6e2dd573bcd436c2b305ef194e1cf39f0cd0754b36ec568da","functions":[{"id":"func/_resolve_temperature","name":"_resolve_temperature","line":26,"end_line":35,"hash":"998ed6ac410ac249f9323306689e281049387bb4cdb7b40473aa70e8a12d5218"},{"id":"func/_resolve_max_tokens","name":"_resolve_max_tokens","line":38,"end_line":45,"hash":"cb0fddfec270db0947c9e4c4641ca1ab14a3a0840697f7b1d186b3f95bd4492c"},{"id":"func/_resolve_base_url","name":"_resolve_base_url","line":48,"end_line":50,"hash":"f49d568278a6d26ac457df37e5df8d5ec67f8e3fbf717ab6139b0868093eff26"},{"id":"func/_resolve_api_key","name":"_resolve_api_key","line":53,"end_line":55,"hash":"9d252c6a2c4627645193dc1d414b204a9fb0ae3ca6fbec47157ea6929db89a2e"},{"id":"func/_resolve_model","name":"_resolve_model","line":58,"end_line":62,"hash":"702c4a307f67d7519b9926c7cd7bcff24dd960c8d96239b4793cf9d1e670e506"},{"id":"func/_resolve_extra_headers","name":"_resolve_extra_headers","line":65,"end_line":74,"hash":"e60982eb84b4e3e6c180960e7bedb1b8fb5c8f4cf6c98d0632e8c673e10d0708"},{"id":"func/_inject_openrouter_headers","name":"_inject_openrouter_headers","line":77,"end_line":83,"hash":"7a170937e63ad4d1e269ef89e011e3003b8a7c8d66fe519abff1ab75995ac6eb"},{"id":"func/LLMClient.__init__","name":"__init__","line":104,"end_line":138,"hash":"130cf69fd18ba8aec2179e1162cf86cb42758c36793f6f9e7ef9ce96fb52c734"},{"id":"func/LLMClient.complete","name":"complete","line":140,"end_line":191,"hash":"62f6e29fb5c1757f3939fcf206ceabf3ab75a240ea94e62b87aed8955e485694"}]}
# mutate4py-manifest-end
