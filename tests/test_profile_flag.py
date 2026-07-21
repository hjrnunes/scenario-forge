"""Tests for the --profile flag that supplies a pre-built capability profile."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "pipeline-output"


@pytest.fixture
def valid_profile_data() -> dict:
    """Minimal valid CapabilityProfile payload."""
    return {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "entry_points": ["chat input [input]", "file upload [input]"],
        "confidence": "high",
        "kc_subcodes": ["KC1.1", "KC6.1.1"],
    }


@pytest.fixture
def valid_profile_path(tmp_path: Path, valid_profile_data: dict) -> Path:
    p = tmp_path / "capability-profile.yaml"
    p.write_text(yaml.dump(valid_profile_data), encoding="utf-8")
    return p


@pytest.fixture
def dummy_inputs(tmp_path: Path) -> tuple[Path, Path]:
    """Create dummy risk-extraction and SSSOM files."""
    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]")
    sssom_path = tmp_path / "sssom.tsv"
    sssom_path.write_text("")
    return risk_path, sssom_path


# ---------------------------------------------------------------------------
# Test: valid profile skips inference
# ---------------------------------------------------------------------------


@patch("scenario_forge.report.generator.generate_report")
@patch("scenario_forge.pipeline.runner.write_coverage_report")
@patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
@patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
@patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
@patch("scenario_forge.pipeline.runner.determine_threat_surface")
@patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
@patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
@patch("scenario_forge.pipeline.runner.infer_capability_profile")
def test_profile_flag_skips_inference(
    mock_infer,
    mock_load,
    mock_coherence,
    mock_threats,
    mock_seeds,
    mock_gaps,
    mock_diversity,
    mock_coverage_report,
    mock_report,
    valid_profile_path: Path,
    valid_profile_data: dict,
    output_dir: Path,
    dummy_inputs: tuple[Path, Path],
) -> None:
    """Supplying a valid profile YAML should skip LLM inference entirely."""
    from scenario_forge.pipeline.runner import run_pipeline
    from scenario_forge.pipeline.threats import ThreatSurface

    coherence = MagicMock()
    coherence.has_warnings = False
    mock_coherence.return_value = coherence

    mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

    gaps = MagicMock()
    gaps.uncovered_entry_points = []
    mock_gaps.return_value = gaps

    risk_path, sssom_path = dummy_inputs

    result = run_pipeline(
        use_case="A billing chatbot",
        risk_extraction_path=risk_path,
        sssom_path=sssom_path,
        output_dir=output_dir,
        profile_path=valid_profile_path,
    )

    # infer_capability_profile must NOT have been called
    mock_infer.assert_not_called()

    # Profile values must match the supplied YAML
    assert result.capability_profile.zones_active == valid_profile_data["zones_active"]
    # entry_points are coerced from plain strings to EntryPoint objects
    assert [ep.name for ep in result.capability_profile.entry_points] == valid_profile_data["entry_points"]
    assert result.capability_profile.confidence.value == valid_profile_data["confidence"]


# ---------------------------------------------------------------------------
# Test: invalid profile YAML raises a validation error
# ---------------------------------------------------------------------------


def test_invalid_profile_raises_validation_error(tmp_path: Path) -> None:
    """A profile YAML missing required fields should fail with a Pydantic error."""
    from pydantic import ValidationError

    from scenario_forge.models.capability_profile import CapabilityProfile

    bad_data = {"zones_active": ["input", "reasoning"]}  # missing required fields
    bad_path = tmp_path / "bad-profile.yaml"
    bad_path.write_text(yaml.dump(bad_data), encoding="utf-8")

    loaded = yaml.safe_load(bad_path.read_text(encoding="utf-8"))
    with pytest.raises(ValidationError):
        CapabilityProfile(**loaded)


# ---------------------------------------------------------------------------
# Test: profile is written to output dir even when supplied externally
# ---------------------------------------------------------------------------


@patch("scenario_forge.report.generator.generate_report")
@patch("scenario_forge.pipeline.runner.write_coverage_report")
@patch("scenario_forge.pipeline.runner.analyze_attacker_diversity")
@patch("scenario_forge.pipeline.runner.analyze_coverage_gaps")
@patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[])
@patch("scenario_forge.pipeline.runner.determine_threat_surface")
@patch("scenario_forge.pipeline.runner.validate_risk_card_coherence")
@patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[])
@patch("scenario_forge.pipeline.runner.infer_capability_profile")
def test_profile_written_to_output_dir(
    mock_infer,
    mock_load,
    mock_coherence,
    mock_threats,
    mock_seeds,
    mock_gaps,
    mock_diversity,
    mock_coverage_report,
    mock_report,
    valid_profile_path: Path,
    valid_profile_data: dict,
    output_dir: Path,
    dummy_inputs: tuple[Path, Path],
) -> None:
    """The profile must be written to output_dir even when supplied via --profile."""
    from scenario_forge.pipeline.runner import run_pipeline
    from scenario_forge.pipeline.threats import ThreatSurface

    coherence = MagicMock()
    coherence.has_warnings = False
    mock_coherence.return_value = coherence

    mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

    gaps = MagicMock()
    gaps.uncovered_entry_points = []
    mock_gaps.return_value = gaps

    risk_path, sssom_path = dummy_inputs

    run_pipeline(
        use_case="A billing chatbot",
        risk_extraction_path=risk_path,
        sssom_path=sssom_path,
        output_dir=output_dir,
        profile_path=valid_profile_path,
    )

    output_profile = output_dir / "capability-profile.yaml"
    assert output_profile.exists(), "capability-profile.yaml should be written to output_dir"

    written = yaml.safe_load(output_profile.read_text(encoding="utf-8"))
    assert written["zones_active"] == valid_profile_data["zones_active"]
    # Serialized entry_points are now dicts with name and direction keys
    written_ep_names = [ep["name"] for ep in written["entry_points"]]
    assert written_ep_names == valid_profile_data["entry_points"]
