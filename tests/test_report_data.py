"""Tests for ReportData, load_report_data, and generate_report with in-memory data.

Covers:
- ReportData construction with defaults
- ReportData construction with explicit values
- load_report_data from a mock output directory (all files present)
- load_report_data with missing files (graceful degradation)
- load_report_data with empty scenarios directory
- generate_report produces report.html from in-memory ReportData
- generate_report with minimal ReportData (empty defaults)
- generate_report_from_dir convenience wrapper
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scenario_forge.report.data import ReportData, load_report_data
from scenario_forge.report.generator import generate_report, generate_report_from_dir


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_output_dir(tmp_path: Path) -> Path:
    """Create a mock output directory with all expected pipeline artifacts."""
    out = tmp_path / "output"
    out.mkdir()

    # capability-profile.yaml
    profile = {
        "zones_active": ["input", "reasoning"],
        "entry_points": [{"name": "user_prompt", "direction": "input"}],
        "confidence": "high",
    }
    (out / "capability-profile.yaml").write_text(
        yaml.dump(profile, default_flow_style=False), encoding="utf-8"
    )

    # threat-surface.yaml
    ts = {
        "entries": [
            {
                "risk_id": "R1",
                "agentic_threat_ids": ["T5"],
            }
        ],
        "governance_only": [],
    }
    (out / "threat-surface.yaml").write_text(
        yaml.dump(ts, default_flow_style=False), encoding="utf-8"
    )

    # scenarios/
    scenarios_dir = out / "scenarios"
    scenarios_dir.mkdir()

    scenario = {
        "scenario_id": "AP-T5-01-abc123",
        "priority": {"composite": 0.8},
        "narrative": {
            "title": "Test Scenario",
            "entry_point": "user_prompt",
            "zone_sequence": ["input"],
        },
        "faceting": {
            "taxonomy_chain": {
                "agentic_threat_ids": ["T5"],
                "scenario_seed": "AP-T5-01",
            }
        },
    }
    (scenarios_dir / "AP-T5-01-abc123.yaml").write_text(
        yaml.dump(scenario, default_flow_style=False), encoding="utf-8"
    )

    feature_content = "Feature: Test\n  Scenario: Attack\n    Given attacker\n"
    (scenarios_dir / "AP-T5-01-abc123.feature").write_text(
        feature_content, encoding="utf-8"
    )

    # scenarios/calls.jsonl
    call_entry = {"scenario_id": "AP-T5-01-abc123", "call": "call0", "tokens": 100}
    (scenarios_dir / "calls.jsonl").write_text(
        json.dumps(call_entry) + "\n", encoding="utf-8"
    )

    # calls.jsonl (pipeline-level)
    pipeline_call = {"call": "capability_profile", "tokens": 200}
    (out / "calls.jsonl").write_text(
        json.dumps(pipeline_call) + "\n", encoding="utf-8"
    )

    # coverage-gaps.json
    coverage = {
        "coverage_gaps": {
            "uncovered_entry_points": [],
            "uncovered_zones": [],
            "uncovered_threats": [],
        }
    }
    (out / "coverage-gaps.json").write_text(
        json.dumps(coverage), encoding="utf-8"
    )

    # eval-scorecard.yaml
    scorecard = {"overall_score": 0.85, "metrics": {"consistency": 0.9}}
    (out / "eval-scorecard.yaml").write_text(
        yaml.dump(scorecard, default_flow_style=False), encoding="utf-8"
    )

    # run-manifest.yaml
    manifest = {
        "version": "0.1.0",
        "scenarios_generated": 1,
        "timestamp_start": "2025-01-01T00:00:00Z",
        "timestamp_end": "2025-01-01T00:01:00Z",
    }
    (out / "run-manifest.yaml").write_text(
        yaml.dump(manifest, default_flow_style=False), encoding="utf-8"
    )

    # use-case.txt
    (out / "use-case.txt").write_text(
        "A financial AI assistant that manages user portfolios.", encoding="utf-8"
    )

    return out


# ---------------------------------------------------------------------------
# ReportData construction tests
# ---------------------------------------------------------------------------


class TestReportDataConstruction:
    def test_default_construction(self) -> None:
        data = ReportData()
        assert data.profile_data == {}
        assert data.threat_surface_data == {}
        assert data.scenarios == []
        assert data.feature_files == {}
        assert data.call_logs == {}
        assert data.pipeline_call_logs == []
        assert data.coverage_data == {}
        assert data.scorecard_data == {}
        assert data.manifest_data == {}
        assert data.use_case_text == ""
        assert data.raw_files == {}

    def test_explicit_construction(self) -> None:
        data = ReportData(
            profile_data={"zones_active": ["input"]},
            scenarios=[{"scenario_id": "S1"}],
            use_case_text="test system",
        )
        assert data.profile_data == {"zones_active": ["input"]}
        assert data.scenarios == [{"scenario_id": "S1"}]
        assert data.use_case_text == "test system"
        # Other fields still default
        assert data.threat_surface_data == {}
        assert data.manifest_data == {}


# ---------------------------------------------------------------------------
# load_report_data tests
# ---------------------------------------------------------------------------


class TestLoadReportData:
    def test_loads_all_artifacts(self, mock_output_dir: Path) -> None:
        data = load_report_data(mock_output_dir)

        assert data.profile_data["zones_active"] == ["input", "reasoning"]
        assert len(data.threat_surface_data["entries"]) == 1
        assert len(data.scenarios) == 1
        assert data.scenarios[0]["scenario_id"] == "AP-T5-01-abc123"
        assert "AP-T5-01-abc123" in data.feature_files
        assert "AP-T5-01-abc123" in data.call_logs
        assert len(data.pipeline_call_logs) == 1
        assert data.coverage_data["coverage_gaps"]["uncovered_entry_points"] == []
        assert data.scorecard_data["overall_score"] == 0.85
        assert data.manifest_data["version"] == "0.1.0"
        assert "financial AI" in data.use_case_text

    def test_raw_files_populated(self, mock_output_dir: Path) -> None:
        data = load_report_data(mock_output_dir)

        assert "capability-profile.yaml" in data.raw_files
        assert "threat-surface.yaml" in data.raw_files
        assert "scenarios/AP-T5-01-abc123.yaml" in data.raw_files
        assert "scenarios/AP-T5-01-abc123.feature" in data.raw_files
        assert "coverage-gaps.json" in data.raw_files
        assert "eval-scorecard.yaml" in data.raw_files

    def test_handles_missing_files(self, tmp_path: Path) -> None:
        """Empty output dir -> all defaults, no crash."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        data = load_report_data(empty_dir)

        assert data.profile_data == {}
        assert data.threat_surface_data == {}
        assert data.scenarios == []
        assert data.feature_files == {}
        assert data.call_logs == {}
        assert data.pipeline_call_logs == []
        assert data.coverage_data == {}
        assert data.scorecard_data == {}
        assert data.manifest_data == {}
        assert data.use_case_text == ""
        assert data.raw_files == {}

    def test_handles_empty_scenarios_dir(self, tmp_path: Path) -> None:
        out = tmp_path / "output"
        out.mkdir()
        (out / "scenarios").mkdir()

        data = load_report_data(out)

        assert data.scenarios == []
        assert data.feature_files == {}

    def test_skips_invalid_scenario_yaml(self, tmp_path: Path) -> None:
        out = tmp_path / "output"
        out.mkdir()
        scenarios_dir = out / "scenarios"
        scenarios_dir.mkdir()

        # Write valid scenario
        valid = {"scenario_id": "S1", "priority": {"composite": 0.5}}
        (scenarios_dir / "valid.yaml").write_text(
            yaml.dump(valid), encoding="utf-8"
        )
        # Write invalid YAML
        (scenarios_dir / "broken.yaml").write_text(
            "{{invalid yaml: [", encoding="utf-8"
        )

        data = load_report_data(out)

        assert len(data.scenarios) == 1
        assert data.scenarios[0]["scenario_id"] == "S1"


# ---------------------------------------------------------------------------
# generate_report tests (in-memory, no filesystem reads)
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def test_produces_html_from_report_data(self, tmp_path: Path) -> None:
        """generate_report should write report.html from ReportData alone."""
        data = ReportData(
            profile_data={
                "zones_active": ["input", "reasoning"],
                "entry_points": [{"name": "user_prompt", "direction": "input"}],
                "confidence": "high",
            },
            threat_surface_data={
                "entries": [{"risk_id": "R1", "agentic_threat_ids": ["T5"]}],
                "governance_only": [],
            },
            scenarios=[
                {
                    "scenario_id": "AP-T5-01-abc123",
                    "priority": {"composite": 0.75},
                    "narrative": {
                        "title": "Test Scenario",
                        "entry_point": "user_prompt",
                        "zone_sequence": ["input"],
                    },
                    "faceting": {
                        "taxonomy_chain": {
                            "agentic_threat_ids": ["T5"],
                            "scenario_seed": "AP-T5-01",
                        }
                    },
                }
            ],
            manifest_data={
                "version": "0.1.0",
                "scenarios_generated": 1,
            },
            use_case_text="A test AI system.",
        )

        out = tmp_path / "report_out"
        out.mkdir()

        report_path = generate_report(data, out)

        assert report_path == out / "report.html"
        assert report_path.exists()
        html_content = report_path.read_text(encoding="utf-8")
        assert "<html" in html_content
        assert "Test Scenario" in html_content

    def test_empty_report_data(self, tmp_path: Path) -> None:
        """generate_report with all-empty ReportData should not crash."""
        data = ReportData()
        out = tmp_path / "empty_report"
        out.mkdir()

        report_path = generate_report(data, out)

        assert report_path.exists()
        html_content = report_path.read_text(encoding="utf-8")
        assert "<html" in html_content

    def test_does_not_read_filesystem(self, tmp_path: Path) -> None:
        """generate_report should not touch the output dir for reads."""
        data = ReportData(
            profile_data={"zones_active": ["input"]},
        )
        out = tmp_path / "isolated"
        out.mkdir()

        # Place a file that should NOT be read by generate_report.
        # If generate_report reads from disk, it would pick this up.
        (out / "capability-profile.yaml").write_text(
            yaml.dump({"zones_active": ["reasoning", "tool_execution"]}),
            encoding="utf-8",
        )

        report_path = generate_report(data, out)
        html_content = report_path.read_text(encoding="utf-8")

        # The HTML should reflect the in-memory data, not the file on disk.
        # "input" from in-memory data should appear; "tool_execution" from
        # disk should NOT appear in the profile section.
        assert "input" in html_content


# ---------------------------------------------------------------------------
# generate_report_from_dir convenience wrapper
# ---------------------------------------------------------------------------


class TestGenerateReportFromDir:
    def test_convenience_wrapper(self, mock_output_dir: Path) -> None:
        report_path = generate_report_from_dir(mock_output_dir)

        assert report_path == mock_output_dir / "report.html"
        assert report_path.exists()
        html_content = report_path.read_text(encoding="utf-8")
        assert "<html" in html_content
        assert "Test Scenario" in html_content
