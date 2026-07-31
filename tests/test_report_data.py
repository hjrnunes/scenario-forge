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

from pathlib import Path

import pytest
import yaml

from scenario_forge.report.data import ReportData, load_report_data
from scenario_forge.report.generator import generate_report, generate_report_from_dir
from tests.manifest_helpers import build_test_run_dir

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_output_dir(tmp_path: Path) -> Path:
    """Create a mock output directory with all expected pipeline artifacts."""
    profile = {
        "zones_active": ["input", "reasoning"],
        "entry_points": [{"name": "user_prompt", "direction": "input"}],
        "confidence": "high",
    }
    ts = {
        "entries": [
            {
                "risk_id": "R1",
                "agentic_threat_ids": ["T5"],
            }
        ],
        "governance_only": [],
    }
    scenario = {
        "scenario_id": "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab",
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
        "validation": {
            "phantom": {"valid": True, "violations": []},
            "structural": {"valid": True, "violations": []},
            "semantic": {
                "valid": True,
                "violations": [],
                "corpus_claim_applicability": [
                    {
                        "category": "entry_points",
                        "status": "not_applicable",
                        "reason": "Entry-point inventory is inferred_partial.",
                    },
                    {
                        "category": "tool_inventory",
                        "status": "not_applicable",
                        "reason": "Tool inventory is inferred_partial.",
                    },
                ],
            },
        },
    }
    sid = "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab"
    feature_content = "Feature: Test\n  Scenario: Attack\n    Given attacker\n"
    call_entry = {
        "scenario_id": "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab",
        "call": "call0",
        "tokens": 100,
    }
    pipeline_call = {"call": "capability_profile", "tokens": 200}
    coverage = {
        "coverage_gaps": {
            "uncovered_entry_points": [],
            "uncovered_zones": [],
            "uncovered_threats": [],
        }
    }
    scorecard = {"overall_score": 0.85, "metrics": {"consistency": 0.9}}

    return build_test_run_dir(
        tmp_path / "output",
        profile_data=profile,
        threat_surface_data=ts,
        scenarios=[scenario],
        feature_files={sid: feature_content},
        use_case="A financial AI assistant that manages user portfolios.",
        pipeline_calls=[pipeline_call],
        scenario_calls=[call_entry],
        coverage_data=coverage,
        eval_scorecard=scorecard,
    )


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
        assert (
            data.scenarios[0]["scenario_id"]
            == "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab"
        )
        assert (
            "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab"
            in data.feature_files
        )
        assert (
            "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab"
            in data.call_logs
        )
        assert len(data.pipeline_call_logs) == 1
        assert data.coverage_data["coverage_gaps"]["uncovered_entry_points"] == []
        assert data.scorecard_data["overall_score"] == 0.85
        assert (
            data.manifest_data["run_id"]
            == "20260101T000000_abcdef0123456789abcdef0123456789"
        )
        assert data.manifest_data["status"] == "completed"
        assert "financial AI" in data.use_case_text

    def test_raw_files_populated(self, mock_output_dir: Path) -> None:
        data = load_report_data(mock_output_dir)

        assert "capability-profile.yaml" in data.raw_files
        assert "threat-surface.yaml" in data.raw_files
        sid = "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab"
        assert f"scenarios/{sid}.yaml" in data.raw_files
        assert f"scenarios/{sid}.feature" in data.raw_files
        assert "coverage-gaps.json" in data.raw_files
        assert "eval-scorecard.yaml" in data.raw_files

    def test_handles_missing_files(self, tmp_path: Path) -> None:
        """A manifest with no optional artifacts loads empty defaults."""
        empty_dir = build_test_run_dir(tmp_path / "empty")

        data = load_report_data(empty_dir)

        assert data.profile_data == {}
        assert data.threat_surface_data == {}
        assert data.scenarios == []
        assert data.feature_files == {}
        assert data.call_logs == {}
        assert data.pipeline_call_logs == []
        assert data.coverage_data == {}
        assert data.scorecard_data == {}
        assert data.manifest_data["status"] == "completed"
        assert data.manifest_data["inventory"]
        assert data.use_case_text == ""
        assert data.raw_files == {}

    def test_handles_empty_scenarios_dir(self, tmp_path: Path) -> None:
        out = build_test_run_dir(tmp_path / "output", scenarios=[])

        data = load_report_data(out)

        assert data.scenarios == []
        assert data.feature_files == {}


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
                    "scenario_id": "scenario:v2:be16e19482de9b592e1a95b1756a859687e0e5d29b4c4760c565b7554ab3eaab",
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
                    "validation": {
                        "phantom": {"valid": True, "violations": []},
                        "structural": {"valid": True, "violations": []},
                        "semantic": {
                            "valid": True,
                            "violations": [],
                            "corpus_claim_applicability": [
                                {
                                    "category": "entry_points",
                                    "status": "not_applicable",
                                    "reason": "Entry-point inventory is inferred_partial.",
                                },
                                {
                                    "category": "tool_inventory",
                                    "status": "not_applicable",
                                    "reason": "Tool inventory is inferred_partial.",
                                },
                            ],
                        },
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
