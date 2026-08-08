"""Shared test helpers for SP1 system model tests.

Provides a mock LLM client that returns canned responses for different
stages and records call metadata (prompts, temperature, call count).
Also provides shared fixture data builders used across multiple test modules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.llm import LLMResult


def valid_empty_connection_set_dict() -> dict:
    """Minimal ConnectionSet with no links, processes, or assignments.

    Used by tests that only need Call 3 to produce a valid (but empty)
    ConnectionSet so the merge produces a ControlStructure matching
    the Call 2 ResponsibilitySet.
    """
    return {
        "coordination_links": [],
        "controlled_processes": [],
        "connection_assignments": [],
    }


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
        self._invalid_response_types: set[type] = set()
        self._exception_response_types: dict[type, Exception] = {}

    def set_invalid_response_for(self, model_class: type) -> None:
        """Configure the mock to return an invalid response for a type.

        The mock returns a dict with an obviously invalid field that
        will fail Pydantic validation for the target model_class.
        """
        self._invalid_response_types.add(model_class)

    def set_exception_for(self, model_class: type, exc: Exception) -> None:
        """Configure the mock to raise *exc* when called for *model_class*."""
        self._exception_response_types[model_class] = exc

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

        # Raise exception if configured for this response_format
        if response_format is not None and response_format in self._exception_response_types:
            raise self._exception_response_types[response_format]

        # Determine which response to return
        if self._response_queue:
            content = self._response_queue.pop(0)
        elif response_format is not None and response_format in self._invalid_response_types:
            # Return a non-JSON string that will fail parsing/validation
            content = "THIS_IS_NOT_VALID_JSON{{{"
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


# ---------------------------------------------------------------------------
# Shared fixture data builders (used by multiple test modules)
# ---------------------------------------------------------------------------


def make_risk_cards() -> list[RiskCard]:
    """Return a minimal list of RiskCards for SP1 pipeline tests."""
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


def read_calls_jsonl(run_dir: Path) -> list[dict]:
    """Read calls.jsonl and return parsed entries."""
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return []
    return [json.loads(line) for line in calls_file.read_text().splitlines()]


def valid_stage1_profile_dict() -> dict:
    """Return a valid Stage1Profile dict for tests that need Stage 1b."""
    return {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [{"name": "tool1", "description": "A tool"}],
    }


def valid_critic_findings_dict_no_gaps() -> dict:
    """Return a CriticFindings dict with no gaps (all checklist items present)."""
    return {
        "gaps": [],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
        },
        "taxonomy_probe_results": {},
    }
