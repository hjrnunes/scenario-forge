"""Tests for ATLAS-derived attack patterns (bead gkmk).

Validates that all 5 P1 patterns from attack-patterns-atlas-derived.yaml
load correctly and pass Pydantic validation including kill_chain and
evidence fields.
"""

from __future__ import annotations

import pytest

from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.models.attack_pattern import (
    AttackPattern,
    validate_attack_pattern,
)

# The 5 P1 ATLAS-derived pattern IDs and their expected properties
ATLAS_PATTERNS = {
    "AP-T6-06": {
        "threat_id": "T6",
        "name": "AI agent as persistent C2 implant via control sequence spoofing",
        "source_cs": "AML.CS0051",
        "min_kill_chain_steps": 8,
    },
    "AP-T11-05": {
        "threat_id": "T11",
        "name": "Computer-use agent exploitation via adversarial web content",
        "source_cs": "AML.CS0055",
        "min_kill_chain_steps": 6,
    },
    "AP-T17-03": {
        "threat_id": "T17",
        "name": "Tool supply chain poisoning via registry namesquatting",
        "source_cs": "AML.CS0053",
        "min_kill_chain_steps": 8,
    },
    "AP-T1-06": {
        "threat_id": "T1",
        "name": "Zero-click RAG poisoning with rendered-output exfiltration",
        "source_cs": "AML.CS0059",
        "min_kill_chain_steps": 7,
    },
    "AP-T3-04": {
        "threat_id": "T3",
        "name": "Exposed agent control interface exploitation",
        "source_cs": "AML.CS0048",
        "min_kill_chain_steps": 7,
    },
}


@pytest.fixture(scope="module")
def all_patterns() -> dict[str, dict]:
    """Load all attack patterns (includes ATLAS-derived via glob)."""
    return load_attack_patterns()


class TestAtlasDerivedPatternsLoad:
    """All 5 ATLAS-derived patterns load via the glob loader."""

    def test_all_five_present(self, all_patterns: dict[str, dict]):
        """All 5 P1 pattern IDs are present in the merged pattern set."""
        for pid in ATLAS_PATTERNS:
            assert pid in all_patterns, f"Pattern {pid} not found in loaded patterns"

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_pattern_has_required_fields(
        self, all_patterns: dict[str, dict], pid: str
    ):
        """Each pattern has id, threat_id, name, description, prerequisite_capabilities."""
        pattern = all_patterns[pid]
        assert pattern["id"] == pid
        assert pattern["threat_id"] == ATLAS_PATTERNS[pid]["threat_id"]
        assert "name" in pattern
        assert "description" in pattern
        assert "prerequisite_capabilities" in pattern


class TestAtlasDerivedPatternsValidate:
    """All 5 ATLAS-derived patterns pass Pydantic validation."""

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_pydantic_validation(self, all_patterns: dict[str, dict], pid: str):
        """Pattern passes validate_attack_pattern() without error."""
        validated = validate_attack_pattern(all_patterns[pid])
        assert isinstance(validated, AttackPattern)
        assert validated.id == pid
        assert validated.threat_id == ATLAS_PATTERNS[pid]["threat_id"]

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_kill_chain_present_and_valid(
        self, all_patterns: dict[str, dict], pid: str
    ):
        """Each pattern has a non-empty kill_chain with the expected minimum steps."""
        validated = validate_attack_pattern(all_patterns[pid])
        assert validated.kill_chain is not None, f"{pid} missing kill_chain"
        assert len(validated.kill_chain) >= ATLAS_PATTERNS[pid]["min_kill_chain_steps"], (
            f"{pid} has {len(validated.kill_chain)} kill chain steps, "
            f"expected >= {ATLAS_PATTERNS[pid]['min_kill_chain_steps']}"
        )

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_kill_chain_steps_have_valid_tactics(
        self, all_patterns: dict[str, dict], pid: str
    ):
        """Each kill chain step has a valid AML.TAnnnn tactic ID."""
        validated = validate_attack_pattern(all_patterns[pid])
        for step in validated.kill_chain:
            assert step.tactic.startswith("AML.TA"), (
                f"{pid} step '{step.step}' has invalid tactic: {step.tactic}"
            )

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_kill_chain_steps_have_valid_techniques(
        self, all_patterns: dict[str, dict], pid: str
    ):
        """Each kill chain step has at least one AML.T technique."""
        validated = validate_attack_pattern(all_patterns[pid])
        for step in validated.kill_chain:
            assert len(step.techniques) >= 1, (
                f"{pid} step '{step.step}' has no techniques"
            )
            for tid in step.techniques:
                assert tid.startswith("AML.T"), (
                    f"{pid} step '{step.step}' has invalid technique: {tid}"
                )

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_evidence_links(self, all_patterns: dict[str, dict], pid: str):
        """Each pattern has evidence linking to its source case study."""
        validated = validate_attack_pattern(all_patterns[pid])
        assert validated.evidence is not None, f"{pid} missing evidence"
        assert len(validated.evidence) >= 1

        expected_cs = ATLAS_PATTERNS[pid]["source_cs"]
        sources = [e.source for e in validated.evidence]
        assert expected_cs in sources, (
            f"{pid} evidence does not reference {expected_cs}, got: {sources}"
        )

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_evidence_type_is_direct_demonstration(
        self, all_patterns: dict[str, dict], pid: str
    ):
        """All P1 patterns use direct_demonstration evidence type."""
        validated = validate_attack_pattern(all_patterns[pid])
        for ev in validated.evidence:
            assert ev.type == "direct_demonstration", (
                f"{pid} evidence type is {ev.type}, expected direct_demonstration"
            )


class TestAtlasDerivedPrerequisites:
    """Prerequisite capabilities are well-formed."""

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_min_zones_non_empty(self, all_patterns: dict[str, dict], pid: str):
        """Each pattern has at least one required zone."""
        validated = validate_attack_pattern(all_patterns[pid])
        assert len(validated.prerequisite_capabilities.min_zones) >= 1

    @pytest.mark.parametrize("pid", list(ATLAS_PATTERNS.keys()))
    def test_kc_requires_has_any(self, all_patterns: dict[str, dict], pid: str):
        """Each pattern has at least an 'any' list in kc_requires."""
        validated = validate_attack_pattern(all_patterns[pid])
        kc = validated.prerequisite_capabilities.kc_requires
        assert kc is not None, f"{pid} missing kc_requires"
        assert "any" in kc or "all" in kc, (
            f"{pid} kc_requires has neither 'any' nor 'all'"
        )


class TestNoIdCollisions:
    """ATLAS-derived patterns do not collide with existing pattern IDs."""

    def test_no_duplicate_ids(self, all_patterns: dict[str, dict]):
        """Pattern IDs are unique across all loaded files."""
        # If there were duplicates, later entries would overwrite earlier ones
        # in the merged dict. We verify each ATLAS pattern's threat_id matches
        # expectations (would fail if overwritten by a different pattern).
        for pid, expected in ATLAS_PATTERNS.items():
            assert all_patterns[pid]["threat_id"] == expected["threat_id"]
            assert expected["name"] in all_patterns[pid]["name"]
