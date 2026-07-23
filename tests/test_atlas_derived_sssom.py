"""Tests for ATLAS-derived SSSOM provenance entries (bead r446).

Validates that:
- All 5 ATLAS-derived patterns have SSSOM entries that parse correctly
- Each pattern has at least 2 entries (distinctive techniques)
- No duplicate entries exist across the file
- All entries reference techniques from their pattern's kill chain
- Generic techniques (AML.T0065, AML.T0051) are excluded
"""

from __future__ import annotations

from collections import Counter

import pytest

from scenario_forge.data.loaders import (
    load_attack_pattern_provenance,
    load_attack_patterns,
)
from scenario_forge.data.sssom import SSSOMMapping, load_sssom

# Path to the new SSSOM file
_SSSOM_PATH = (
    "data/taxonomies/attack-patterns/attack-patterns-atlas-derived.sssom.tsv"
)

# The 5 ATLAS-derived pattern IDs
ATLAS_DERIVED_IDS = ["AP-T6-06", "AP-T11-05", "AP-T17-03", "AP-T1-06", "AP-T3-04"]

# Expected distinctive technique mappings per pattern
EXPECTED_TECHNIQUES: dict[str, list[str]] = {
    "AP-T6-06": ["AML.T0095", "AML.T0069", "AML.T0081", "AML.T0108"],
    "AP-T11-05": ["AML.T0017", "AML.T0100", "AML.T0053"],
    "AP-T17-03": ["AML.T0073", "AML.T0104", "AML.T0109", "AML.T0086"],
    "AP-T1-06": ["AML.T0093", "AML.T0070", "AML.T0085", "AML.T0077"],
    "AP-T3-04": ["AML.T0000", "AML.T0049", "AML.T0083"],
}

# Generic techniques that should NOT appear (per abstraction strategy 7.5)
GENERIC_TECHNIQUES = {"AML.T0065", "AML.T0051"}


@pytest.fixture(scope="module")
def sssom_mappings() -> list[SSSOMMapping]:
    """Load SSSOM mappings from the new ATLAS-derived file."""
    return load_sssom(_SSSOM_PATH)


@pytest.fixture(scope="module")
def all_provenance() -> list[SSSOMMapping]:
    """Load all SSSOM provenance via the glob loader."""
    return load_attack_pattern_provenance()


@pytest.fixture(scope="module")
def all_patterns() -> dict[str, dict]:
    """Load all attack patterns."""
    return load_attack_patterns()


class TestAtlasDerivedSSSOMParsing:
    """All entries in the new SSSOM file parse correctly."""

    def test_file_loads_without_error(self, sssom_mappings: list[SSSOMMapping]):
        """The SSSOM file parses without exceptions."""
        assert len(sssom_mappings) > 0

    def test_total_entry_count(self, sssom_mappings: list[SSSOMMapping]):
        """File contains exactly 18 entries (4+3+4+4+3)."""
        assert len(sssom_mappings) == 18

    def test_all_entries_are_sssom_mappings(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """Every parsed entry is a valid SSSOMMapping instance."""
        for m in sssom_mappings:
            assert isinstance(m, SSSOMMapping)

    def test_all_entries_have_correct_subject_source(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'scenario-forge' as subject_source."""
        for m in sssom_mappings:
            assert m.subject_source == "scenario-forge", (
                f"Entry {m.subject_id}->{m.object_id} has wrong subject_source: "
                f"{m.subject_source}"
            )

    def test_all_entries_have_correct_object_source(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'mitre-atlas' as object_source."""
        for m in sssom_mappings:
            assert m.object_source == "mitre-atlas", (
                f"Entry {m.subject_id}->{m.object_id} has wrong object_source: "
                f"{m.object_source}"
            )

    def test_all_entries_have_correct_predicate(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'skos:relatedMatch' predicate."""
        for m in sssom_mappings:
            assert m.predicate_id == "skos:relatedMatch"

    def test_all_entries_have_correct_justification(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'semapv:ManualMappingCuration' justification."""
        for m in sssom_mappings:
            assert m.mapping_justification == "semapv:ManualMappingCuration"


class TestAtlasDerivedSSSOMCoverage:
    """Each ATLAS-derived pattern has sufficient SSSOM entries."""

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_pattern_has_at_least_two_entries(
        self, sssom_mappings: list[SSSOMMapping], pid: str
    ):
        """Each pattern has at least 2 SSSOM entries."""
        entries = [m for m in sssom_mappings if m.subject_id == pid]
        assert len(entries) >= 2, (
            f"{pid} has only {len(entries)} SSSOM entries, expected >= 2"
        )

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_pattern_has_at_most_four_entries(
        self, sssom_mappings: list[SSSOMMapping], pid: str
    ):
        """Each pattern has at most 4 SSSOM entries (per strategy)."""
        entries = [m for m in sssom_mappings if m.subject_id == pid]
        assert len(entries) <= 4, (
            f"{pid} has {len(entries)} SSSOM entries, expected <= 4"
        )

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_expected_techniques_present(
        self, sssom_mappings: list[SSSOMMapping], pid: str
    ):
        """Each pattern maps to the expected distinctive techniques."""
        mapped_techniques = {
            m.object_id for m in sssom_mappings if m.subject_id == pid
        }
        expected = set(EXPECTED_TECHNIQUES[pid])
        assert mapped_techniques == expected, (
            f"{pid}: expected techniques {expected}, got {mapped_techniques}"
        )


class TestNoGenericTechniques:
    """Generic techniques should not appear in the ATLAS-derived SSSOM."""

    def test_no_prompt_crafting(self, sssom_mappings: list[SSSOMMapping]):
        """AML.T0065 (Prompt Crafting) should not appear."""
        technique_ids = {m.object_id for m in sssom_mappings}
        assert "AML.T0065" not in technique_ids, (
            "Generic technique AML.T0065 (Prompt Crafting) should not be in "
            "ATLAS-derived SSSOM entries"
        )

    def test_no_prompt_injection(self, sssom_mappings: list[SSSOMMapping]):
        """AML.T0051 (LLM Prompt Injection) should not appear."""
        technique_ids = {m.object_id for m in sssom_mappings}
        assert "AML.T0051" not in technique_ids, (
            "Generic technique AML.T0051 (LLM Prompt Injection) should not "
            "be in ATLAS-derived SSSOM entries"
        )


class TestNoDuplicateEntries:
    """No duplicate entries exist in the file."""

    def test_no_exact_duplicates(self, sssom_mappings: list[SSSOMMapping]):
        """No two entries share the same (subject_id, object_id) pair."""
        pairs = [(m.subject_id, m.object_id) for m in sssom_mappings]
        counter = Counter(pairs)
        duplicates = {pair: count for pair, count in counter.items() if count > 1}
        assert not duplicates, f"Duplicate SSSOM entries found: {duplicates}"

    def test_no_duplicates_across_all_sssom_files(
        self, all_provenance: list[SSSOMMapping]
    ):
        """No duplicate (subject_id, object_id) pairs across all SSSOM files."""
        pairs = [(m.subject_id, m.object_id) for m in all_provenance]
        counter = Counter(pairs)
        duplicates = {pair: count for pair, count in counter.items() if count > 1}
        assert not duplicates, (
            f"Duplicate entries found across SSSOM files: {duplicates}"
        )


class TestTechniquesFromKillChain:
    """All mapped techniques exist in the corresponding pattern's kill chain."""

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_techniques_in_kill_chain(
        self,
        sssom_mappings: list[SSSOMMapping],
        all_patterns: dict[str, dict],
        pid: str,
    ):
        """Each SSSOM technique for a pattern appears in that pattern's kill chain."""
        pattern = all_patterns[pid]
        # Collect all techniques from the kill chain
        kill_chain_techniques: set[str] = set()
        for step in pattern.get("kill_chain", []):
            kill_chain_techniques.update(step.get("techniques", []))

        # Check each SSSOM technique is in the kill chain
        sssom_techniques = {
            m.object_id for m in sssom_mappings if m.subject_id == pid
        }
        missing = sssom_techniques - kill_chain_techniques
        assert not missing, (
            f"{pid}: SSSOM techniques {missing} not found in kill chain "
            f"(available: {kill_chain_techniques})"
        )


class TestGlobLoaderIncludesNewFile:
    """The glob-based loader picks up the new SSSOM file."""

    def test_new_patterns_in_glob_results(
        self, all_provenance: list[SSSOMMapping]
    ):
        """All 5 ATLAS-derived pattern IDs appear in the glob-loaded provenance."""
        subject_ids = {m.subject_id for m in all_provenance}
        for pid in ATLAS_DERIVED_IDS:
            assert pid in subject_ids, (
                f"{pid} not found in glob-loaded provenance"
            )
