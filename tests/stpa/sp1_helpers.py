"""Shared test helpers for SP1 system model tests.

Provides a mock LLM client that returns canned responses for different
stages and records call metadata (prompts, temperature, call count).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from scenario_forge.stpa.infra.llm import LLMResult


@dataclass
class MockCall:
    """A recorded LLM call."""

    system_prompt: str
    user_prompt: str
    response_format: type | None
    temperature: float | None
    max_completion_tokens: int | None


class MockLLMClient:
    """A mock LLM client for SP1 tests.

    Returns canned responses based on a queue or a response map keyed
    by response_format. Records all calls for inspection.
    """

    def __init__(
        self,
        base_url: str = "http://test:8080",
        model: str = "test-model",
        temperature: float = 0.4,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_completion_tokens = None
        self.calls: list[MockCall] = []
        self._response_queue: list[Any] = []
        self._response_map: dict[type, Any] = {}

    @property
    def _client(self) -> Any:
        return MagicMock()

    def set_response_queue(self, responses: list[Any]) -> None:
        """Set a FIFO queue of responses to return in order."""
        self._response_queue = list(responses)

    def set_response_for(self, model_class: type, response: Any) -> None:
        """Set a response for a specific response_format type."""
        self._response_map[model_class] = response

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        call = MockCall(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
        )
        self.calls.append(call)

        # Determine which response to return
        if self._response_queue:
            content = self._response_queue.pop(0)
        elif response_format is not None and response_format in self._response_map:
            content = self._response_map[response_format]
        elif response_format is None and None in self._response_map:
            content = self._response_map[None]
        else:
            content = None

        return LLMResult(
            content=content,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def find_call_by_step_prompt(self, substring: str) -> MockCall | None:
        """Find a call whose user_prompt contains the given substring."""
        for call in self.calls:
            if substring in call.user_prompt:
                return call
        return None
