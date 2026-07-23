"""Tests for kill chain enrichments added to 5 existing patterns (bead 3vw9).

Validates that:
- All 5 enriched patterns load from real YAML files
- kill_chain and evidence fields pass Pydantic validation
- Kill chain steps have valid ATLAS tactic/technique IDs
- Evidence links use the correct 'enrichment' type
- Existing fields remain unchanged (backward compatibility)
"""

from __future__ import annotations

import pytest

from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.models.attack_pattern import validate_attack_pattern

ENRICHED_PATTERN_IDS = [
    "AP-T1-01",
    "AP-T17-01",
    "AP-T17-02",
    "AP-T11-01",
    "AP-T11-02",
]

# Expected evidence sources for each pattern
EXPECTED_EVIDENCE = {
    "AP-T1-01": "AML.CS0040",
    "AP-T17-01": "AML.CS0041",
    "AP-T17-02": "AML.CS0049",
    "AP-T11-01": "AML.CS0052",
    "AP-T11-02": "AML.CS0062",
}

# Minimum expected kill chain lengths for each pattern
MIN_KILL_CHAIN_STEPS = {
    "AP-T1-01": 5,
    "AP-T17-01": 5,
    "AP-T17-02": 5,
    "AP-T11-01": 5,
    "AP-T11-02": 4,
}


@pytest.fixture(scope="module")
def all_patterns():
    """Load all attack patterns once for the module."""
    return load_attack_patterns()


class TestEnrichedPatternsLoad:
    """Verify enriched patterns load correctly from real YAML files."""

    def test_all_enriched_patterns_present(self, all_patterns):
        """All 5 enriched pattern IDs exist in loaded patterns."""
        for pid in ENRICHED_PATTERN_IDS:
            assert pid in all_patterns, f"{pid} missing from loaded patterns"

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_enriched_pattern_has_kill_chain(self, all_patterns, pid):
        """Each enriched pattern has a non-empty kill_chain field."""
        pattern = all_patterns[pid]
        assert "kill_chain" in pattern, f"{pid} missing kill_chain"
        assert len(pattern["kill_chain"]) > 0, f"{pid} has empty kill_chain"

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_enriched_pattern_has_evidence(self, all_patterns, pid):
        """Each enriched pattern has an evidence field."""
        pattern = all_patterns[pid]
        assert "evidence" in pattern, f"{pid} missing evidence"
        assert len(pattern["evidence"]) > 0, f"{pid} has empty evidence"


class TestEnrichedPatternsValidate:
    """Verify enriched patterns pass full Pydantic validation."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_pattern_validates(self, all_patterns, pid):
        """Each enriched pattern passes validate_attack_pattern()."""
        validated = validate_attack_pattern(all_patterns[pid])
        assert validated.id == pid
        assert validated.kill_chain is not None
        assert validated.evidence is not None

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_kill_chain_minimum_steps(self, all_patterns, pid):
        """Each enriched pattern has at least the expected number of steps."""
        validated = validate_attack_pattern(all_patterns[pid])
        expected_min = MIN_KILL_CHAIN_STEPS[pid]
        actual = len(validated.kill_chain)
        assert actual >= expected_min, (
            f"{pid}: expected >= {expected_min} kill chain steps, got {actual}"
        )


class TestKillChainContent:
    """Verify kill chain content is well-formed."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_all_steps_have_valid_tactics(self, all_patterns, pid):
        """All kill chain steps use valid AML.TAxxxx tactic IDs."""
        validated = validate_attack_pattern(all_patterns[pid])
        for step in validated.kill_chain:
            assert step.tactic.startswith("AML.TA"), (
                f"{pid} step '{step.step}' has invalid tactic: {step.tactic}"
            )

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_all_steps_have_valid_techniques(self, all_patterns, pid):
        """All kill chain steps use valid AML.Txxxx technique IDs."""
        validated = validate_attack_pattern(all_patterns[pid])
        for step in validated.kill_chain:
            for tech in step.techniques:
                assert tech.startswith("AML.T"), (
                    f"{pid} step '{step.step}' has invalid technique: {tech}"
                )

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_all_steps_have_abstract_actions(self, all_patterns, pid):
        """All kill chain steps have non-empty abstract_action descriptions."""
        validated = validate_attack_pattern(all_patterns[pid])
        for step in validated.kill_chain:
            assert step.abstract_action.strip(), (
                f"{pid} step '{step.step}' has empty abstract_action"
            )

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_step_names_are_unique(self, all_patterns, pid):
        """Kill chain step names are unique within each pattern."""
        validated = validate_attack_pattern(all_patterns[pid])
        names = [s.step for s in validated.kill_chain]
        assert len(names) == len(set(names)), (
            f"{pid} has duplicate step names: {names}"
        )


class TestEvidenceContent:
    """Verify evidence links are correctly configured."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_evidence_source_matches_expected(self, all_patterns, pid):
        """Each pattern's evidence links to the expected ATLAS case study."""
        validated = validate_attack_pattern(all_patterns[pid])
        sources = [e.source for e in validated.evidence]
        expected = EXPECTED_EVIDENCE[pid]
        assert expected in sources, (
            f"{pid}: expected evidence source '{expected}', got {sources}"
        )

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_evidence_type_is_enrichment(self, all_patterns, pid):
        """All evidence links use type 'enrichment' (not direct_demonstration)."""
        validated = validate_attack_pattern(all_patterns[pid])
        for ev in validated.evidence:
            assert ev.type == "enrichment", (
                f"{pid}: evidence type should be 'enrichment', got '{ev.type}'"
            )


class TestExistingFieldsPreserved:
    """Verify that existing fields were not modified during enrichment."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_core_fields_present(self, all_patterns, pid):
        """Core fields (id, threat_id, name, description) are intact."""
        pattern = all_patterns[pid]
        assert pattern["id"] == pid
        assert "threat_id" in pattern
        assert "name" in pattern
        assert len(pattern["name"]) > 0
        assert "description" in pattern
        assert len(pattern["description"]) > 0

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_prerequisite_capabilities_present(self, all_patterns, pid):
        """prerequisite_capabilities field is preserved."""
        pattern = all_patterns[pid]
        assert "prerequisite_capabilities" in pattern
        assert "min_zones" in pattern["prerequisite_capabilities"]

    def test_non_enriched_patterns_unchanged(self, all_patterns):
        """Patterns not in the enrichment set have no kill_chain or evidence."""
        for pid, pattern in all_patterns.items():
            if pid not in ENRICHED_PATTERN_IDS:
                # These patterns should not have been modified
                validated = validate_attack_pattern(pattern)
                # Non-enriched patterns may or may not have kill_chain in future,
                # but currently none should
                if validated.kill_chain is not None:
                    pytest.fail(
                        f"Non-enriched pattern {pid} unexpectedly has kill_chain"
                    )
