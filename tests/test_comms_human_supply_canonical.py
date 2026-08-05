"""Dedicated acceptance tests for bead scenario-forge-422o.2.8.

Covers the migration of
``data/taxonomies/attack-patterns/attack-patterns-comms-human-supply.yaml``
from the legacy kill-chain catalog to the authoritative canonical-chain
contract under the merged ``catalog-lineage.yaml`` dispositions:

- the live record set is exactly the authoritative resulting IDs
  (AP-T12-01, AP-T12-03, AP-T15-01, AP-T15-02, AP-T17-01); deferred
  (AP-T12-02/04/05) and retired (AP-T17-02) records are absent;
- every record parses and qualifies against the production pinned
  taxonomy resolver, and its embedded semantic digest recomputes from
  on-disk content;
- chain/step exact ATLAS mappings match catalog-lineage.yaml exactly —
  no more, no less — and unmapped attacker steps carry rationale;
- every chain is one pure branch-free total-order chain (all steps
  required, no conditions or preconditions) with supported explicit
  consumed/produced links;
- provenance references are honest: pinned ATLAS case-study step
  citations resolve, technique references are resolver members, and
  staging design-record references exist;
- legacy transport (``kill_chain``, ``evidence``) is removed and the
  records no longer parse as legacy records.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from scenario_forge.data.catalog_lineage import (
    _DEFAULT_LINEAGE_PATH,
    load_atlas_case_step_index,
    load_catalog_lineage,
)
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    AttackPattern,
    ExactMapping,
    NotApplicableMapping,
    UnmappedMapping,
    compute_chain_semantic_digest,
    validate_attack_pattern,
    validate_legacy_attack_pattern,
)

OWNER_FILE = "attack-patterns-comms-human-supply.yaml"
OWNER_PATH = _DEFAULT_LINEAGE_PATH.parent / OWNER_FILE
STAGING_DIR = _DEFAULT_LINEAGE_PATH.parent / "staging"

EXPECTED_LIVE_IDS = ["AP-T12-01", "AP-T12-03", "AP-T15-01", "AP-T15-02", "AP-T17-01"]
REMOVED_IDS = ["AP-T12-02", "AP-T12-04", "AP-T12-05", "AP-T17-02"]
EXPECTED_DISPOSITIONS = {"retain": 2, "narrow": 3, "defer": 3, "retire": 1}

_CASE_STEP_REF_RE = re.compile(r"^(AML\.CS\d{4}) S\d{2}$")
_TECHNIQUE_REF_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return yaml.safe_load(OWNER_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def records(document) -> dict[str, Any]:
    return document["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def case_steps():
    return load_atlas_case_step_index()


@pytest.fixture(scope="module")
def qualified(records, resolver) -> dict[str, AttackPattern]:
    return {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in records.items()
    }


@pytest.fixture(scope="module")
def lineage_entries() -> dict[str, dict[str, Any]]:
    artifact = load_catalog_lineage()
    return {
        entry["source_pattern_id"]: entry
        for entry in artifact["sources"]
        if entry["source_file"] == OWNER_FILE
    }


class TestResultingRecordSet:
    def test_live_ids_are_exactly_the_authoritative_resulting_ids(self, records):
        assert sorted(records) == EXPECTED_LIVE_IDS
        for pid in EXPECTED_LIVE_IDS:
            assert records[pid]["id"] == pid

    def test_deferred_and_retired_records_are_not_live(self, records):
        for pid in REMOVED_IDS:
            assert pid not in records

    def test_source_disposition_tally(self, lineage_entries):
        assert len(lineage_entries) == 9
        tally: dict[str, int] = {}
        for entry in lineage_entries.values():
            tally[entry["disposition"]] = tally.get(entry["disposition"], 0) + 1
        assert tally == EXPECTED_DISPOSITIONS

    def test_live_ids_match_lineage_resulting_patterns(self, records, lineage_entries):
        resulting = set()
        for entry in lineage_entries.values():
            for record in entry["resulting_patterns"]:
                resulting.add(record["pattern_id"])
                assert record["source_file"] == OWNER_FILE
        assert resulting == set(EXPECTED_LIVE_IDS)
        for pid in REMOVED_IDS:
            assert lineage_entries[pid]["resulting_patterns"] == []

    def test_merged_catalog_load_includes_the_migrated_records(self):
        merged = load_attack_patterns()
        for pid in EXPECTED_LIVE_IDS:
            assert pid in merged


class TestQualificationAndPins:
    def test_every_record_qualifies_against_the_production_resolver(self, qualified):
        assert sorted(qualified) == EXPECTED_LIVE_IDS

    def test_embedded_taxonomy_context_matches_production_pins(
        self, qualified, resolver
    ):
        for pattern in qualified.values():
            assert pattern.canonical_chain.taxonomy_context == resolver.taxonomy_context
            assert pattern.canonical_chain.taxonomy_context.laaf is None

    def test_semantic_digests_recompute_from_disk(self, records):
        for pid, record in records.items():
            chain = record["canonical_chain"]
            assert compute_chain_semantic_digest(chain) == chain["semantic_digest"], pid

    def test_json_round_trip_stability(self, qualified):
        for pattern in qualified.values():
            assert (
                AttackPattern.model_validate(pattern.model_dump(mode="json")) == pattern
            )

    def test_no_laaf_decisions_anywhere(self, qualified):
        for pattern in qualified.values():
            chain = pattern.canonical_chain
            scopes = [chain.mappings, *(step.mappings for step in chain.steps)]
            for scope in scopes:
                for mapping in scope:
                    assert mapping.taxonomy == "ATLAS"


class TestLineageMappingFidelity:
    def _lineage_resulting(self, lineage_entries, pid: str) -> dict[str, Any]:
        (record,) = lineage_entries[pid]["resulting_patterns"]
        return record

    def test_chain_exact_mappings_match_lineage_exactly(
        self, qualified, lineage_entries
    ):
        for pid, pattern in qualified.items():
            expected = sorted(
                m["id"]
                for m in self._lineage_resulting(lineage_entries, pid)[
                    "atlas_chain_mappings"
                ]
            )
            (mapping,) = pattern.canonical_chain.mappings
            assert isinstance(mapping, ExactMapping)
            assert mapping.taxonomy == "ATLAS"
            assert sorted(mapping.ids) == expected, pid

    def test_step_exact_mappings_match_lineage_exactly(
        self, qualified, lineage_entries
    ):
        for pid, pattern in qualified.items():
            expected = {
                m["step"]: m["id"]
                for m in self._lineage_resulting(lineage_entries, pid)[
                    "atlas_step_mappings"
                ]
            }
            actual = {}
            for step in pattern.canonical_chain.steps:
                for mapping in step.mappings:
                    if isinstance(mapping, ExactMapping):
                        (identifier,) = mapping.ids
                        actual[step.step_id] = identifier
            assert actual == expected, pid

    def test_unmapped_attacker_steps_carry_rationale(self, qualified):
        for pattern in qualified.values():
            for step in pattern.canonical_chain.steps:
                for mapping in step.mappings:
                    if isinstance(mapping, UnmappedMapping):
                        assert mapping.rationale.strip()
                        assert "catalog-lineage" in mapping.rationale


class TestChainStructure:
    def test_pure_branch_free_total_order(self, qualified):
        for pid, pattern in qualified.items():
            steps = pattern.canonical_chain.steps
            assert [s.order for s in steps] == list(range(1, len(steps) + 1)), pid
            for step in steps:
                assert step.requirement == "required", (pid, step.step_id)
                assert step.condition is None, (pid, step.step_id)
                assert step.preconditions == (), (pid, step.step_id)

    def test_attacker_start_and_terminal_outcome_placement(self, qualified):
        for pid, pattern in qualified.items():
            chain = pattern.canonical_chain
            assert chain.steps[0].attacker_controlled, pid
            assert chain.earliest_attacker_controlled_step_id == chain.steps[0].step_id
            for step in chain.steps[:-1]:
                assert not any(
                    o.security_relevant and o.terminal
                    for o in step.observable_postconditions
                ), (pid, step.step_id)
            assert any(
                o.security_relevant and o.terminal
                for o in chain.steps[-1].observable_postconditions
            ), pid

    def test_role_mapping_partition(self, qualified):
        for pid, pattern in qualified.items():
            attacker_exact = 0
            for step in pattern.canonical_chain.steps:
                if step.attacker_controlled:
                    assert step.executor_role == "attacker"
                    assert not any(
                        isinstance(m, NotApplicableMapping) for m in step.mappings
                    )
                    attacker_exact += sum(
                        isinstance(m, ExactMapping) for m in step.mappings
                    )
                else:
                    assert step.executor_role in {"system", "operator"}
                    assert all(
                        isinstance(m, NotApplicableMapping) for m in step.mappings
                    )
            assert attacker_exact >= 1, pid

    def test_resource_slots_match_lineage_slot_plan(self, qualified, lineage_entries):
        for pid, pattern in qualified.items():
            expected = [
                (slot["slot_id"], slot["kind"], slot["purpose"])
                for slot in self._lineage_resulting(lineage_entries, pid)[
                    "resource_slot_plan"
                ]
            ]
            actual = [
                (slot.slot_id, slot.kind, slot.purpose)
                for slot in pattern.canonical_chain.resource_slots
            ]
            assert sorted(actual) == sorted(expected), pid
            ingress = [
                slot
                for slot in pattern.canonical_chain.resource_slots
                if slot.purpose == "initial_ingress"
            ]
            (only,) = ingress
            assert only.kind == "entry_point"
            assert pattern.canonical_chain.initial_ingress_slot_id == only.slot_id

    def _lineage_resulting(self, lineage_entries, pid: str) -> dict[str, Any]:
        (record,) = lineage_entries[pid]["resulting_patterns"]
        return record

    def test_consumed_links_are_supported_by_earlier_production(self, qualified):
        for pid, pattern in qualified.items():
            produced_so_far: dict[tuple[str, str], str] = {}
            for step in pattern.canonical_chain.steps:
                for ref in step.consumed:
                    key = (ref.kind, ref.ref_id)
                    assert key in produced_so_far, (pid, step.step_id, key)
                    assert produced_so_far[key] == ref.value_type, (
                        pid,
                        step.step_id,
                        key,
                    )
                for ref in step.produced:
                    produced_so_far[(ref.kind, ref.ref_id)] = ref.value_type

    def test_every_step_produces_an_effect_or_state_and_observable(self, qualified):
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                assert len(step.produced) >= 1, (pid, step.step_id)
                assert len(step.observable_postconditions) >= 1, (pid, step.step_id)


class TestProvenanceHonesty:
    def test_case_study_step_references_resolve_in_pinned_atlas(
        self, qualified, case_steps
    ):
        checked = 0
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                for reference in step.provenance.references:
                    match = _CASE_STEP_REF_RE.match(reference.reference_id)
                    if match is None:
                        continue
                    assert reference.reference_type == "catalog"
                    case_id = match.group(1)
                    step_id = reference.reference_id.rsplit(" ", 1)[1]
                    assert case_id in case_steps, (pid, reference.reference_id)
                    assert step_id in case_steps[case_id], (pid, reference.reference_id)
                    checked += 1
        assert checked > 0

    def test_technique_references_are_resolver_members(self, qualified, resolver):
        checked = 0
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                for reference in step.provenance.references:
                    if _TECHNIQUE_REF_RE.match(reference.reference_id):
                        assert resolver.contains("ATLAS", reference.reference_id), (
                            pid,
                            reference.reference_id,
                        )
                        checked += 1
        assert checked > 0

    def test_design_record_references_exist_in_staging(self, qualified):
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                for reference in step.provenance.references:
                    if reference.reference_type == "design_record":
                        assert (STAGING_DIR / reference.reference_id).is_file(), (
                            pid,
                            reference.reference_id,
                        )

    def test_provenance_tiers_and_confidence_bounds(self, qualified):
        for pid, pattern in qualified.items():
            for step in pattern.canonical_chain.steps:
                provenance = step.provenance
                assert provenance.references
                assert 0 <= provenance.confidence <= 100
                assert provenance.adaptation_rationale.strip()

    def test_directionality_correction_and_persistence_are_recorded(self, qualified):
        # AP-T15-02: the CS0055 directionality correction must be retained in
        # provenance, and the human-directed line must be grounded in CS0020.
        t15_02_text = yaml.safe_dump(
            qualified["AP-T15-02"].model_dump(mode="json"), sort_keys=True
        )
        assert "directionality" in t15_02_text
        assert "AML.CS0020 S03" in t15_02_text
        assert "AML.T0052.000" in t15_02_text
        # AP-T17-01: the evidence-backed persistence step (CS0041 S04) survives.
        t17_01 = qualified["AP-T17-01"].canonical_chain
        persist = [s for s in t17_01.steps if s.action_kind == "persist"]
        assert [s.step_id for s in persist] == ["persist_via_adoption"]
        references = persist[0].provenance.references
        assert any(r.reference_id == "AML.CS0041 S04" for r in references)


class TestLegacyTransportRemoved:
    def test_no_kill_chain_or_evidence_keys(self, records):
        for pid, record in records.items():
            assert "kill_chain" not in record, pid
            assert "evidence" not in record, pid

    def test_records_no_longer_parse_as_legacy(self, records):
        for pid, record in records.items():
            with pytest.raises(ValidationError):
                validate_legacy_attack_pattern(record)
