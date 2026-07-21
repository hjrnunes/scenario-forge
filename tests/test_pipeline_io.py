"""Tests for the pipeline I/O boundary layer (``scenario_forge.pipeline.io``)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scenario_forge.pipeline.io import (
    get_scenarios_dir,
    setup_pipeline_output,
    write_capability_profile,
    write_eval_scorecard,
    write_final_manifest,
    write_pipeline_call_log,
    write_threat_surface,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "pipeline-output"


@pytest.fixture
def minimal_profile():
    """Return a minimal valid CapabilityProfile."""
    from scenario_forge.models.capability_profile import CapabilityProfile

    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["chat input"],
        confidence="high",
        kc_subcodes=["KC1.1"],
    )


@pytest.fixture
def minimal_threat_surface():
    """Return a minimal ThreatSurface with no entries."""
    from scenario_forge.pipeline.threats import ThreatSurface

    return ThreatSurface(entries=[], governance_only=[])


# ---------------------------------------------------------------------------
# setup_pipeline_output
# ---------------------------------------------------------------------------


class TestSetupPipelineOutput:
    def test_creates_output_dir(self, output_dir: Path) -> None:
        setup_pipeline_output(output_dir, "test use case")
        assert output_dir.is_dir()

    def test_writes_use_case_txt(self, output_dir: Path) -> None:
        use_case = "An AI chatbot for billing inquiries"
        setup_pipeline_output(output_dir, use_case)

        use_case_path = output_dir / "use-case.txt"
        assert use_case_path.exists()
        assert use_case_path.read_text() == use_case

    def test_writes_manifest_sentinel(self, output_dir: Path) -> None:
        setup_pipeline_output(output_dir, "test")

        manifest_path = output_dir / "run-manifest.yaml"
        assert manifest_path.exists()
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        assert manifest["status"] == "started"
        assert "timestamp_start" in manifest
        assert "version" in manifest

    def test_returns_timestamp(self, output_dir: Path) -> None:
        ts = setup_pipeline_output(output_dir, "test")
        assert isinstance(ts, str)
        # ISO format includes 'T'
        assert "T" in ts

    def test_idempotent_on_existing_dir(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        # Should not raise when dir already exists
        setup_pipeline_output(output_dir, "test")
        assert (output_dir / "use-case.txt").exists()


# ---------------------------------------------------------------------------
# write_capability_profile
# ---------------------------------------------------------------------------


class TestWriteCapabilityProfile:
    def test_writes_yaml_file(self, output_dir: Path, minimal_profile) -> None:
        output_dir.mkdir(parents=True)
        path = write_capability_profile(minimal_profile, output_dir)

        assert path == output_dir / "capability-profile.yaml"
        assert path.exists()

    def test_yaml_content_matches_profile(
        self, output_dir: Path, minimal_profile
    ) -> None:
        output_dir.mkdir(parents=True)
        write_capability_profile(minimal_profile, output_dir)

        written = yaml.safe_load(
            (output_dir / "capability-profile.yaml").read_text(encoding="utf-8")
        )
        assert written["zones_active"] == ["input", "reasoning"]
        assert written["confidence"] == "high"

    def test_returns_correct_path(self, output_dir: Path, minimal_profile) -> None:
        output_dir.mkdir(parents=True)
        path = write_capability_profile(minimal_profile, output_dir)
        assert path.name == "capability-profile.yaml"
        assert path.parent == output_dir


# ---------------------------------------------------------------------------
# write_threat_surface
# ---------------------------------------------------------------------------


class TestWriteThreatSurface:
    def test_writes_yaml_file(
        self, output_dir: Path, minimal_threat_surface
    ) -> None:
        output_dir.mkdir(parents=True)
        path = write_threat_surface(minimal_threat_surface, output_dir)

        assert path == output_dir / "threat-surface.yaml"
        assert path.exists()

    def test_yaml_content_matches_surface(
        self, output_dir: Path, minimal_threat_surface
    ) -> None:
        output_dir.mkdir(parents=True)
        write_threat_surface(minimal_threat_surface, output_dir)

        written = yaml.safe_load(
            (output_dir / "threat-surface.yaml").read_text(encoding="utf-8")
        )
        assert written["entries"] == []
        assert written["governance_only"] == []


# ---------------------------------------------------------------------------
# write_pipeline_call_log
# ---------------------------------------------------------------------------


class TestWritePipelineCallLog:
    def test_writes_jsonl_file(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        entries = [{"call": "test", "tokens": 42}]
        write_pipeline_call_log(entries, output_dir)

        calls_path = output_dir / "calls.jsonl"
        assert calls_path.exists()
        lines = calls_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

    def test_appends_to_existing_file(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        write_pipeline_call_log([{"call": "first"}], output_dir)
        write_pipeline_call_log([{"call": "second"}], output_dir)

        calls_path = output_dir / "calls.jsonl"
        lines = calls_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_noop_on_empty_entries(self, output_dir: Path) -> None:
        # Should not create directory or file when entries are empty
        write_pipeline_call_log([], output_dir)
        assert not output_dir.exists()

    def test_creates_dir_if_missing(self, output_dir: Path) -> None:
        write_pipeline_call_log([{"call": "test"}], output_dir)
        assert output_dir.is_dir()


# ---------------------------------------------------------------------------
# get_scenarios_dir
# ---------------------------------------------------------------------------


class TestGetScenariosDir:
    def test_returns_scenarios_subdirectory(self, output_dir: Path) -> None:
        result = get_scenarios_dir(output_dir)
        assert result == output_dir / "scenarios"

    def test_does_not_create_directory(self, output_dir: Path) -> None:
        get_scenarios_dir(output_dir)
        assert not output_dir.exists()


# ---------------------------------------------------------------------------
# write_final_manifest
# ---------------------------------------------------------------------------


class TestWriteFinalManifest:
    def test_writes_yaml_file(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        manifest = {
            "version": "0.1.0",
            "timestamp_start": "2025-01-01T00:00:00+00:00",
            "timestamp_end": "2025-01-01T00:01:00+00:00",
            "scenarios_generated": 5,
        }
        path = write_final_manifest(manifest, output_dir)

        assert path == output_dir / "run-manifest.yaml"
        assert path.exists()

    def test_overwrites_sentinel(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        # Write sentinel first
        sentinel_path = output_dir / "run-manifest.yaml"
        sentinel_path.write_text(
            yaml.dump({"status": "started"}), encoding="utf-8"
        )

        # Final manifest should overwrite
        manifest = {"version": "0.1.0", "scenarios_generated": 10}
        write_final_manifest(manifest, output_dir)

        written = yaml.safe_load(sentinel_path.read_text(encoding="utf-8"))
        assert "status" not in written
        assert written["scenarios_generated"] == 10

    def test_yaml_content_matches_input(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        manifest = {"version": "1.0", "seeds_generated": 3}
        write_final_manifest(manifest, output_dir)

        written = yaml.safe_load(
            (output_dir / "run-manifest.yaml").read_text(encoding="utf-8")
        )
        assert written == manifest


# ---------------------------------------------------------------------------
# write_eval_scorecard
# ---------------------------------------------------------------------------


class TestWriteEvalScorecard:
    def test_writes_yaml_file(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        scorecard = {"overall_score": 0.85, "metrics": {"consistency": 0.9}}
        path = write_eval_scorecard(scorecard, output_dir)

        assert path == output_dir / "eval-scorecard.yaml"
        assert path.exists()

    def test_yaml_content_matches_input(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True)
        scorecard = {"overall_score": 0.85, "metrics": {"diversity": 0.7}}
        write_eval_scorecard(scorecard, output_dir)

        written = yaml.safe_load(
            (output_dir / "eval-scorecard.yaml").read_text(encoding="utf-8")
        )
        assert written == scorecard


# ---------------------------------------------------------------------------
# Integration: runner uses I/O boundary instead of inline writes
# ---------------------------------------------------------------------------


class TestRunnerUsesIOBoundary:
    """Verify that runner.run_pipeline delegates writes to the I/O module."""

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.write_coverage_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_setup_writes_via_io_module(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_coverage_report,
        mock_report,
        output_dir: Path,
        tmp_path: Path,
        minimal_profile,
    ) -> None:
        """run_pipeline should produce the same output files via the I/O boundary."""
        from unittest.mock import MagicMock

        from scenario_forge.llm.client import LLMResult
        from scenario_forge.pipeline.runner import run_pipeline
        from scenario_forge.pipeline.threats import ThreatSurface

        llm_result = LLMResult(
            content="mock",
            prompt_tokens=10,
            completion_tokens=20,
            duration_ms=100,
            system_prompt="system",
            user_prompt="user",
        )
        mock_profile.return_value = (minimal_profile, llm_result)

        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence

        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

        gaps = MagicMock()
        gaps.uncovered_entry_points = []
        mock_gaps.return_value = gaps

        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        run_pipeline(
            use_case="A test chatbot",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=output_dir,
            eval=False,
        )

        # All expected output files must exist
        assert (output_dir / "use-case.txt").exists()
        assert (output_dir / "use-case.txt").read_text() == "A test chatbot"
        assert (output_dir / "capability-profile.yaml").exists()
        assert (output_dir / "threat-surface.yaml").exists()
        assert (output_dir / "run-manifest.yaml").exists()

        # Final manifest should not have "started" status
        manifest = yaml.safe_load(
            (output_dir / "run-manifest.yaml").read_text(encoding="utf-8")
        )
        assert "status" not in manifest
        assert "version" in manifest
        assert "timestamp_start" in manifest
        assert "timestamp_end" in manifest

    @patch("scenario_forge.report.generator.generate_report")
    @patch("scenario_forge.pipeline.runner.write_coverage_report")
    @patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
    @patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
    @patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
    @patch("scenario_forge.pipeline.runner.determine_threat_surface")
    @patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
    @patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
    @patch("scenario_forge.pipeline.runner.infer_capability_profile")
    def test_io_functions_are_mockable(
        self,
        mock_profile,
        mock_load,
        mock_coherence,
        mock_threats,
        mock_seeds,
        mock_gaps,
        mock_diversity,
        mock_coverage_report,
        mock_report,
        output_dir: Path,
        tmp_path: Path,
        minimal_profile,
    ) -> None:
        """The I/O boundary functions can be mocked to test pipeline logic without filesystem."""
        from unittest.mock import MagicMock

        from scenario_forge.llm.client import LLMResult
        from scenario_forge.pipeline.threats import ThreatSurface

        llm_result = LLMResult(
            content="mock",
            prompt_tokens=10,
            completion_tokens=20,
            duration_ms=100,
            system_prompt="system",
            user_prompt="user",
        )
        mock_profile.return_value = (minimal_profile, llm_result)

        coherence = MagicMock()
        coherence.has_warnings = False
        mock_coherence.return_value = coherence

        mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

        gaps = MagicMock()
        gaps.uncovered_entry_points = []
        mock_gaps.return_value = gaps

        risk_path = tmp_path / "risk.json"
        risk_path.write_text("[]")
        sssom_path = tmp_path / "sssom.tsv"
        sssom_path.write_text("")

        with (
            patch(
                "scenario_forge.pipeline.runner.setup_pipeline_output",
                return_value="2025-01-01T00:00:00+00:00",
            ) as mock_setup,
            patch(
                "scenario_forge.pipeline.runner.write_capability_profile",
                return_value=output_dir / "capability-profile.yaml",
            ) as mock_write_profile,
            patch(
                "scenario_forge.pipeline.runner.write_threat_surface",
                return_value=output_dir / "threat-surface.yaml",
            ) as mock_write_ts,
            patch(
                "scenario_forge.pipeline.runner.write_final_manifest",
                return_value=output_dir / "run-manifest.yaml",
            ) as mock_write_manifest,
        ):
            from scenario_forge.pipeline.runner import run_pipeline

            run_pipeline(
                use_case="A test chatbot",
                risk_extraction_path=risk_path,
                sssom_path=sssom_path,
                output_dir=output_dir,
                eval=False,
            )

            # All I/O boundary functions should have been called
            mock_setup.assert_called_once_with(output_dir, "A test chatbot")
            mock_write_profile.assert_called_once()
            mock_write_ts.assert_called_once()
            mock_write_manifest.assert_called_once()
