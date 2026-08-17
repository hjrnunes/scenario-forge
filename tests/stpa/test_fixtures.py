"""Tests for STPA fixture validation.

Covers Fixtures-01 through Fixtures-06 from the Gherkin feature file.
Every fixture YAML file must load and validate against its corresponding
boundary schema without errors. Each fixture must contain a header
comment documenting its provenance.

SP1 fixtures (loss_analysis, capability_profile, control_structure) are
validated for all three use-cases: klarna, airbnb, occiai.
SP2 fixtures (ica_enumeration, enriched_threats) are validated for klarna
only — they will be added for airbnb and occiai after SP2 implementation.
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

# Use-cases with SP1 fixture coverage (Stages 1–2 outputs).
SP1_USE_CASES = ["klarna", "airbnb", "occiai"]

# Use-cases with SP2 fixture coverage (Stages 3–4 outputs).
# Only klarna has SP2 fixtures so far; airbnb and occiai will be added
# after SP2 implementation.
SP2_USE_CASES = ["klarna"]

# SP1 fixture types produced by Stages 1–2.
SP1_FIXTURE_TYPES = ["loss_analysis", "capability_profile", "control_structure"]

# SP2 fixture types produced by Stages 3–4.
SP2_FIXTURE_TYPES = ["ica_enumeration", "enriched_threats"]


def _fixture_filename(fixture_type: str, use_case: str) -> str:
    """Build the fixture filename from type and use-case."""
    return f"{fixture_type}_{use_case}.yaml"


def _all_sp1_fixtures() -> list[str]:
    """All expected SP1 fixture filenames across all use-cases."""
    return [
        _fixture_filename(ft, uc)
        for ft in SP1_FIXTURE_TYPES
        for uc in SP1_USE_CASES
    ]


def _all_sp2_fixtures() -> list[str]:
    """All expected SP2 fixture filenames."""
    return [
        _fixture_filename(ft, uc)
        for ft in SP2_FIXTURE_TYPES
        for uc in SP2_USE_CASES
    ]


REQUIRED_FIXTURES = _all_sp1_fixtures() + _all_sp2_fixtures()


class TestFixturesExist:
    """Fixtures-06: all required fixture files are present."""

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


class TestSP1FixtureValidation:
    """SP1 fixtures validate against their schemas and have provenance comments.

    Covers loss_analysis, capability_profile, and control_structure for
    all three use-cases (klarna, airbnb, occiai).
    """

    @pytest.mark.parametrize("use_case", SP1_USE_CASES)
    def test_loss_analysis_validates(self, use_case):
        """loss_analysis_{uc}.yaml validates as LossAnalysis."""
        path = FIXTURES_DIR / _fixture_filename("loss_analysis", use_case)
        model = read_yaml(path, LossAnalysis)
        assert isinstance(model, LossAnalysis)
        assert _has_header_comment(path)

    @pytest.mark.parametrize("use_case", SP1_USE_CASES)
    def test_capability_profile_validates(self, use_case):
        """capability_profile_{uc}.yaml validates as CapabilityProfile."""
        path = FIXTURES_DIR / _fixture_filename("capability_profile", use_case)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        model = CapabilityProfile.model_validate(raw)
        assert isinstance(model, CapabilityProfile)
        assert _has_header_comment(path)

    @pytest.mark.parametrize("use_case", SP1_USE_CASES)
    def test_control_structure_validates(self, use_case):
        """control_structure_{uc}.yaml validates as ControlStructure."""
        path = FIXTURES_DIR / _fixture_filename("control_structure", use_case)
        model = read_yaml(path, ControlStructure)
        assert isinstance(model, ControlStructure)
        assert _has_header_comment(path)


class TestSP2FixtureValidation:
    """SP2 fixtures validate against their schemas and have provenance comments.

    Covers ica_enumeration and enriched_threats. Currently only klarna
    has SP2 fixtures; airbnb and occiai will be added after SP2.
    """

    @pytest.mark.parametrize("use_case", SP2_USE_CASES)
    def test_ica_enumeration_validates(self, use_case):
        """ica_enumeration_{uc}.yaml validates as ICAEnumeration."""
        path = FIXTURES_DIR / _fixture_filename("ica_enumeration", use_case)
        model = read_yaml(path, ICAEnumeration)
        assert isinstance(model, ICAEnumeration)
        assert _has_header_comment(path)
        # Also validate against the loss analysis and control structure fixtures
        la = read_yaml(
            FIXTURES_DIR / _fixture_filename("loss_analysis", use_case), LossAnalysis
        )
        cs = read_yaml(
            FIXTURES_DIR / _fixture_filename("control_structure", use_case),
            ControlStructure,
        )
        model.validate_against(la, cs)

    @pytest.mark.parametrize("use_case", SP2_USE_CASES)
    def test_enriched_threats_validates(self, use_case):
        """enriched_threats_{uc}.yaml validates as EnrichedThreatSet."""
        path = FIXTURES_DIR / _fixture_filename("enriched_threats", use_case)
        model = read_yaml(path, EnrichedThreatSet)
        assert isinstance(model, EnrichedThreatSet)
        assert _has_header_comment(path)
