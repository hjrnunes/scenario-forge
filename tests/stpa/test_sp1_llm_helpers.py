"""Tests for shared LLM helpers (parse_llm_result, log_llm_call).

These improve coverage of the infra helpers extracted during cleanup.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from scenario_forge.stpa.infra.llm import LLMResult
from scenario_forge.stpa.infra.llm_helpers import log_llm_call, parse_llm_result


class _SampleModel(BaseModel):
    name: str
    value: int = 0


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
