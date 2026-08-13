"""Tests for shared LLM helpers (parse_llm_result, log_llm_call).

These improve coverage of the infra helpers extracted during cleanup.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, field_validator

from scenario_forge.stpa.infra.llm import LLMResult
from scenario_forge.stpa.infra.llm_helpers import (
    log_llm_call,
    parse_llm_result,
    parse_llm_result_unvalidated,
    safe_llm_call,
)


class _SampleModel(BaseModel):
    name: str
    value: int = 0


class _NestedModel(BaseModel):
    """Nested model with a validator that rejects one source ID."""

    item_id: str

    @field_validator("item_id")
    @classmethod
    def reject_malformed(cls, value: str) -> str:
        if value == "malformed":
            raise ValueError("malformed source ID")
        return value


class _ContainerModel(BaseModel):
    """Container used to verify tolerant nested construction."""

    items: list[_NestedModel]


class _TolerantClient:
    """Minimal client exposing the raw structured-response escape hatch."""

    model = "test-model"

    def __init__(self) -> None:
        self.allow_unvalidated = False

    def complete(
        self,
        *,
        system_prompt,
        user_prompt,
        response_format,
        temperature,
        max_completion_tokens=None,
        allow_unvalidated=False,
    ):
        self.allow_unvalidated = allow_unvalidated
        return LLMResult(
            content={"items": [{"item_id": "malformed"}]},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )


class TestParseLlmResult:
    """parse_llm_result handles all content types."""

    def test_content_is_already_model_instance(self):
        """When content is already the target type, it is returned as-is."""
        model = _SampleModel(name="direct")
        result = LLMResult(content=model, prompt_tokens=0, completion_tokens=0, duration_ms=0)
        parsed = parse_llm_result(result, _SampleModel)
        assert parsed is model

    def test_content_is_dict(self):
        """When content is a dict, it is validated into the model."""
        result = LLMResult(
            content={"name": "from_dict", "value": 42},
            prompt_tokens=0, completion_tokens=0, duration_ms=0,
        )
        parsed = parse_llm_result(result, _SampleModel)
        assert parsed.name == "from_dict"
        assert parsed.value == 42

    def test_content_is_json_string(self):
        """When content is a JSON string, it is parsed and validated."""
        result = LLMResult(
            content=json.dumps({"name": "from_string"}),
            prompt_tokens=0, completion_tokens=0, duration_ms=0,
        )
        parsed = parse_llm_result(result, _SampleModel)
        assert parsed.name == "from_string"
        assert parsed.value == 0

    def test_content_is_unexpected_type_raises(self):
        """When content is an unexpected type, TypeError is raised."""
        result = LLMResult(
            content=12345,
            prompt_tokens=0, completion_tokens=0, duration_ms=0,
        )
        with pytest.raises(TypeError, match="Unexpected LLM result content type"):
            parse_llm_result(result, _SampleModel)

    def test_unvalidated_parser_preserves_nested_invalid_source_id(self):
        """Tolerant decoding defers nested validation to post-processing."""
        result = LLMResult(
            content={"items": [{"item_id": "malformed"}]},
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )

        parsed = parse_llm_result_unvalidated(result, _ContainerModel)

        assert parsed.items[0].item_id == "malformed"

    def test_safe_call_passes_tolerant_mode_and_defers_validation(self, tmp_path):
        """safe_llm_call exposes malformed nested IDs to post-processing."""
        client = _TolerantClient()

        parsed, _, error = safe_llm_call(
            llm_client=client,
            system_prompt="system",
            user_prompt="user",
            response_format=_ContainerModel,
            run_dir=tmp_path,
            stage="stage_test",
            step="step_test",
            allow_unvalidated=True,
        )

        assert error is None
        assert client.allow_unvalidated is True
        assert parsed.items[0].item_id == "malformed"


class TestLogLlmCall:
    """log_llm_call writes a call-log entry to calls.jsonl."""

    def test_entry_written_with_stage_and_step(self, tmp_path: Path):
        """A call-log entry is appended with the given stage and step."""
        result = LLMResult(
            content=None,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt="sys",
            user_prompt="usr",
        )
        log_llm_call(result, "test-model", tmp_path, "stage_test", "step_test")

        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_test"
        assert entries[0]["step"] == "step_test"
        assert entries[0]["model"] == "test-model"
        assert entries[0]["prompt_tokens"] == 100
        assert entries[0]["completion_tokens"] == 50
        assert entries[0]["success"] is True
