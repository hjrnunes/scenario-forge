"""Tests for STPA fixture validation.

Covers Fixtures-01 through Fixtures-06 from the Gherkin feature file.
Every fixture YAML file must load and validate against its corresponding
boundary schema without errors. Each fixture must contain a header
comment documenting its provenance.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.loss_analysis import LossAnalysis

FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "scenario_forge"
    / "stpa"
    / "fixtures"
)

REQUIRED_FIXTURES = [
    "loss_analysis_klarna.yaml",
    "capability_profile_klarna.yaml",
    "control_structure_klarna.yaml",
    "ica_enumeration_klarna.yaml",
    "enriched_threats_klarna.yaml",
]


class TestFixturesExist:
    """Fixtures-06: all five required fixture files are present."""

    def test_fixtures_directory_exists(self):
        """The fixtures directory exists."""
        assert FIXTURES_DIR.exists(), f"Fixtures directory not found: {FIXTURES_DIR}"
        assert FIXTURES_DIR.is_dir()

    @pytest.mark.parametrize("fixture_name", REQUIRED_FIXTURES)
    def test_required_fixture_file_present(self, fixture_name):
        """Each required fixture file is present."""
        path = FIXTURES_DIR / fixture_name
        assert path.exists(), f"Required fixture not found: {fixture_name}"


def _has_header_comment(path: Path) -> bool:
    """Check if a YAML file starts with a comment line."""
    text = path.read_text(encoding="utf-8")
    for line in text.strip().split("\n"):
        stripped = line.strip()
        if stripped:
            return stripped.startswith("#")
    return False


class TestFixtureValidation:
    """Each fixture validates against its schema and has a provenance comment."""

    def test_fixture_01_loss_analysis_validates(self):
        """Fixtures-01: loss_analysis_klarna.yaml validates as LossAnalysis."""
        path = FIXTURES_DIR / "loss_analysis_klarna.yaml"
        model = read_yaml(path, LossAnalysis)
        assert isinstance(model, LossAnalysis)
        assert _has_header_comment(path)

    def test_fixture_02_capability_profile_validates(self):
        """Fixtures-02: capability_profile_klarna.yaml validates as CapabilityProfile."""
        path = FIXTURES_DIR / "capability_profile_klarna.yaml"
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        model = CapabilityProfile.model_validate(raw)
        assert isinstance(model, CapabilityProfile)
        assert _has_header_comment(path)

    def test_fixture_03_control_structure_validates(self):
        """Fixtures-03: control_structure_klarna.yaml validates as ControlStructure."""
        path = FIXTURES_DIR / "control_structure_klarna.yaml"
        model = read_yaml(path, ControlStructure)
        assert isinstance(model, ControlStructure)
        assert _has_header_comment(path)

    def test_fixture_04_ica_enumeration_validates(self):
        """Fixtures-04: ica_enumeration_klarna.yaml validates as ICAEnumeration."""
        path = FIXTURES_DIR / "ica_enumeration_klarna.yaml"
        model = read_yaml(path, ICAEnumeration)
        assert isinstance(model, ICAEnumeration)
        assert _has_header_comment(path)
        # Also validate against the loss analysis and control structure fixtures
        la = read_yaml(FIXTURES_DIR / "loss_analysis_klarna.yaml", LossAnalysis)
        cs = read_yaml(
            FIXTURES_DIR / "control_structure_klarna.yaml", ControlStructure
        )
        model.validate_against(la, cs)

    def test_fixture_05_enriched_threats_validates(self):
        """Fixtures-05: enriched_threats_klarna.yaml validates as EnrichedThreatSet."""
        path = FIXTURES_DIR / "enriched_threats_klarna.yaml"
        model = read_yaml(path, EnrichedThreatSet)
        assert isinstance(model, EnrichedThreatSet)
        assert _has_header_comment(path)
