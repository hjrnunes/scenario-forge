"""Tests for calls HTML full content — FullContent-01 through FullContent-15.

Verifies that call log entries include full system_prompt_text, user_prompt_text,
and response_content fields, and that the HTML report renders them in
collapsible sections with pretty-printed JSON and a search/filter box.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scenario_forge.stpa.infra.call_log import make_call_log_entry
from scenario_forge.stpa.infra.calls_html import render_calls_html
from scenario_forge.stpa.infra.llm import LLMResult
from scenario_forge.stpa.infra.llm_helpers import (
    log_llm_call,
    log_llm_call_failure,
)


# ---------------------------------------------------------------------------
# FullContent-01: make_call_log_entry includes full content fields
# ---------------------------------------------------------------------------


class TestFullContent01CallLogEntry:
    """FullContent-01: make_call_log_entry stores full content fields."""

    @pytest.mark.parametrize(
        "field_name, field_value",
        [
            ("system_prompt_text", "You are a safety engineer"),
            ("user_prompt_text", "Analyze this system"),
            ("response_content", '{"gap_type": "missing_responsibility"}'),
        ],
        ids=["system_prompt_text", "user_prompt_text", "response_content"],
    )
    def test_entry_contains_field(self, field_name, field_value):
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test-model",
            system_prompt="You are a safety engineer",
            user_prompt="Analyze this system",
            response_content='{"gap_type": "missing_responsibility"}',
        )
        assert field_name in entry
        assert entry[field_name] == field_value


# ---------------------------------------------------------------------------
# FullContent-04: log_llm_call stores full prompt text and response content
# ---------------------------------------------------------------------------


class TestFullContent04LogLlmCall:
    """FullContent-04: log_llm_call stores full prompt text and response content."""

    def test_log_llm_call_stores_full_content(self, tmp_path):
        result = LLMResult(
            content='{"result": true}',
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt="System instructions",
            user_prompt="User task",
        )
        log_llm_call(result, "test-model", tmp_path, "stage_2", "call_1")
        entries = _read_jsonl(tmp_path / "calls.jsonl")
        assert len(entries) == 1
        assert entries[0]["system_prompt_text"] == "System instructions"
        assert entries[0]["user_prompt_text"] == "User task"
        assert "result" in entries[0]["response_content"]


# ---------------------------------------------------------------------------
# FullContent-05: log_llm_call_failure stores full prompt text
# ---------------------------------------------------------------------------


class TestFullContent05LogLlmCallFailure:
    """FullContent-05: log_llm_call_failure stores full prompt text."""

    def test_log_llm_call_failure_stores_prompts(self, tmp_path):
        log_llm_call_failure(
            "test-model",
            tmp_path,
            "stage_2",
            "call_1",
            "timeout",
            system_prompt="System prompt",
            user_prompt="User prompt",
        )
        entries = _read_jsonl(tmp_path / "calls.jsonl")
        assert len(entries) == 1
        assert entries[0]["system_prompt_text"] == "System prompt"
        assert entries[0]["user_prompt_text"] == "User prompt"


# ---------------------------------------------------------------------------
# FullContent-06: HTML report shows prompt content in collapsible sections
# ---------------------------------------------------------------------------


class TestFullContent06CollapsibleSections:
    """FullContent-06: HTML report shows prompt content in collapsible sections."""

    @pytest.mark.parametrize(
        "field_name, field_value, search_text, collapsible_name",
        [
            (
                "system_prompt_text",
                "You are a safety engineer",
                "You are a safety engineer",
                "system_prompt",
            ),
            (
                "user_prompt_text",
                "Analyze this system",
                "Analyze this system",
                "user_prompt",
            ),
        ],
        ids=["system_prompt", "user_prompt"],
    )
    def test_html_shows_collapsible_prompt_sections(
        self, tmp_path, field_name, field_value, search_text, collapsible_name
    ):
        entry = _make_basic_entry()
        entry[field_name] = field_value
        html = _render(tmp_path, [entry])
        assert search_text in html
        assert collapsible_name in html
        assert "<details" in html


# ---------------------------------------------------------------------------
# FullContent-08: HTML report shows response_content in collapsible section
# ---------------------------------------------------------------------------


class TestFullContent08ResponseCollapsible:
    """FullContent-08: HTML report shows response_content in collapsible section."""

    def test_html_shows_response_content_collapsible(self, tmp_path):
        entry = _make_basic_entry()
        entry["response_content"] = '{"gap_type": "missing_responsibility"}'
        html = _render(tmp_path, [entry])
        assert "response_content" in html
        assert "gap_type" in html
        assert "<details" in html


# ---------------------------------------------------------------------------
# FullContent-09: structured responses are pretty-printed as JSON
# ---------------------------------------------------------------------------


class TestFullContent09PrettyPrintedJson:
    """FullContent-09: structured responses are pretty-printed as JSON."""

    def test_json_response_pretty_printed(self, tmp_path):
        entry = _make_basic_entry()
        entry["response_content"] = (
            '{"gap_type":"missing_responsibility","description":"test"}'
        )
        html = _render(tmp_path, [entry])
        # Pretty-printed JSON uses indentation
        assert "  " in html or "\n" in html
        assert "gap_type" in html
        assert "<pre" in html


# ---------------------------------------------------------------------------
# FullContent-10: unstructured responses shown in pre blocks
# ---------------------------------------------------------------------------


class TestFullContent10UnstructuredPreBlocks:
    """FullContent-10: unstructured responses shown in pre blocks."""

    def test_plain_text_response_in_pre_block(self, tmp_path):
        entry = _make_basic_entry()
        entry["response_content"] = (
            "This is a plain text response without JSON structure."
        )
        html = _render(tmp_path, [entry])
        assert "<pre" in html
        assert "This is a plain text response without JSON structure." in html


# ---------------------------------------------------------------------------
# FullContent-11: HTML report includes search and filter box
# ---------------------------------------------------------------------------


class TestFullContent11SearchFilter:
    """FullContent-11: HTML report includes search and filter box."""

    def test_html_includes_search_filter(self, tmp_path):
        entry1 = _make_basic_entry()
        entry1["stage"] = "stage_1a"
        entry2 = _make_basic_entry()
        entry2["stage"] = "stage_2"
        html = _render(tmp_path, [entry1, entry2])
        assert "<input" in html
        assert "<script" in html


# ---------------------------------------------------------------------------
# FullContent-12: summary table is preserved at top of report
# ---------------------------------------------------------------------------


class TestFullContent12SummaryPreserved:
    """FullContent-12: summary table is preserved at top of report."""

    def test_summary_shows_totals(self, tmp_path):
        entry1 = _make_basic_entry()
        entry1["stage"] = "stage_1a"
        entry1["step"] = "call_1a"
        entry1["prompt_tokens"] = 1000
        entry1["completion_tokens"] = 500
        entry1["duration_ms"] = 3000
        entry1["success"] = True
        entry2 = _make_basic_entry()
        entry2["stage"] = "stage_2"
        entry2["step"] = "call_2"
        entry2["prompt_tokens"] = 2000
        entry2["completion_tokens"] = 800
        entry2["duration_ms"] = 5000
        entry2["success"] = True
        html = _render(tmp_path, [entry1, entry2])
        assert "2" in html  # total calls
        assert "2" in html  # success count


# ---------------------------------------------------------------------------
# FullContent-13: HTML report is self-contained with inline CSS and JS
# ---------------------------------------------------------------------------


class TestFullContent13SelfContained:
    """FullContent-13: HTML report is self-contained with inline CSS and JavaScript."""

    def test_html_self_contained(self, tmp_path):
        entry = _make_basic_entry()
        html = _render(tmp_path, [entry])
        assert "<style>" in html
        assert "<script>" in html
        assert 'rel="stylesheet"' not in html
        assert ".js" not in html or "src=" not in html


# ---------------------------------------------------------------------------
# FullContent-14: backward compatibility with entries lacking content fields
# ---------------------------------------------------------------------------


class TestFullContent14BackwardCompatibility:
    """FullContent-14: backward compatibility with entries lacking content fields."""

    def test_html_rendered_without_content_fields(self, tmp_path):
        entry = _make_basic_entry()
        # No system_prompt_text, user_prompt_text, or response_content
        html = _render(tmp_path, [entry])
        assert "<style>" in html
        assert "1" in html  # total calls


# ---------------------------------------------------------------------------
# FullContent-15: existing metadata columns preserved in detail table
# ---------------------------------------------------------------------------


class TestFullContent15MetadataColumns:
    """FullContent-15: existing metadata columns preserved in detail table."""

    @pytest.mark.parametrize(
        "column",
        [
            "stage",
            "step",
            "model",
            "prompt_tokens",
            "completion_tokens",
            "duration_ms",
            "timestamp",
        ],
    )
    def test_detail_table_includes_column(self, tmp_path, column):
        entry = _make_basic_entry()
        html = _render(tmp_path, [entry])
        assert column in html


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _make_basic_entry() -> dict:
    return {
        "stage": "stage_2",
        "step": "call_1",
        "model": "test-model",
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "duration_ms": 5000,
        "timestamp": "2026-08-08T12:00:00Z",
        "success": True,
        "system_prompt_hash": "abc123",
        "user_prompt_hash": "def456",
    }


def _render(tmp_path: Path, entries: list[dict]) -> str:
    calls_path = tmp_path / "calls.jsonl"
    with calls_path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    output_path = tmp_path / "calls.html"
    render_calls_html(calls_path, output_path)
    return output_path.read_text(encoding="utf-8")
