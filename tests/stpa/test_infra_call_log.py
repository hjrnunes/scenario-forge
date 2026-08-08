"""Tests for STPA infra call log (InfraCallLog-01 through InfraCallLog-04)."""

from __future__ import annotations

import json

from scenario_forge.stpa.infra.call_log import append_call_log, make_call_log_entry


class TestInfraCallLog:
    """JSONL call logging."""

    def test_call_log_01_entry_written_as_jsonl(self, tmp_path):
        """InfraCallLog-01: entry written as JSONL with stage and step."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test-model",
            slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            scenario_id=None,
        )
        append_call_log([entry], tmp_path)
        lines = (tmp_path / "calls.jsonl").read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["stage"] == "stage_2"
        assert parsed["step"] == "call_1"
        assert parsed["slot_id"] == "RESP-1:CA-1-1:NOT_PROVIDED"
        assert parsed["scenario_id"] is None

    def test_call_log_02_entry_with_scenario_id(self, tmp_path):
        """InfraCallLog-02: entry with scenario_id set."""
        entry = make_call_log_entry(
            stage="stage_6_narrative",
            step="call_a",
            model="test-model",
            slot_id=None,
            scenario_id="SCN-001",
        )
        append_call_log([entry], tmp_path)
        parsed = json.loads(
            (tmp_path / "calls.jsonl").read_text().strip()
        )
        assert parsed["scenario_id"] == "SCN-001"

    def test_call_log_03_multiple_entries_appended_sequentially(self, tmp_path):
        """InfraCallLog-03: multiple entries appended in order."""
        entries = [
            make_call_log_entry(stage="stage_2", step="call_1", model="m"),
            make_call_log_entry(stage="stage_3", step="call_1", model="m"),
            make_call_log_entry(stage="stage_5", step="call_1", model="m"),
        ]
        append_call_log(entries, tmp_path)
        lines = (tmp_path / "calls.jsonl").read_text().strip().split("\n")
        assert len(lines) == 3
        stages = [json.loads(line)["stage"] for line in lines]
        assert stages == ["stage_2", "stage_3", "stage_5"]

    def test_call_log_04_empty_list_does_not_create_file(self, tmp_path):
        """InfraCallLog-04: empty list does not create calls.jsonl."""
        append_call_log([], tmp_path)
        assert not (tmp_path / "calls.jsonl").exists()
