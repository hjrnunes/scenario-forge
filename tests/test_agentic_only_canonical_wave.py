"""Wave test for the agentic-only canonical-chain migration (scenario-forge-422o.2.6).

Covers only data/taxonomies/attack-patterns/attack-patterns-agentic-only.yaml:
the T8/T9/T10/T14/T16 records migrated per catalog-lineage.yaml. Shared
catalog-wide contracts (merged loader shape, legacy isolation) are owned by
other tests and are intentionally not re-asserted here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scenario_forge.data.catalog_lineage import load_catalog_lineage
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    AttackPattern,
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

AP_DIR = Path(__file__).resolve().parents[1] / "data" / "taxonomies" / "attack-patterns"
AGENTIC_ONLY_PATH = AP_DIR / "attack-patterns-agentic-only.yaml"
LINEAGE_PATH = AP_DIR / "catalog-lineage.yaml"

RESULTING_IDS = {
    "AP-T10-01",
    "AP-T16-02",
    "AP-T16-03",
    "AP-T8-01",
    "AP-T9-01",
    "AP-T9-02",
    "AP-T9-07",
    "AP-T9-05",
    "AP-T9-06",
}

DEFERRED_SOURCE_IDS = {
    "AP-T8-02",
    "AP-T8-03",
    "AP-T9-03",
    "AP-T9-04",
    "AP-T10-02",
    "AP-T10-03",
    "AP-T14-01",
    "AP-T14-02",
    "AP-T14-03",
    "AP-T14-04",
    "AP-T16-01",
}

EXPECTED_DISPOSITIONS = {
    "AP-T10-01": "retain",
    "AP-T9-01": "retain",
    "AP-T8-01": "narrow",
    "AP-T9-05": "narrow",
    "AP-T9-06": "narrow",
    "AP-T16-02": "narrow",
    "AP-T16-03": "narrow",
    "AP-T9-02": "split",
}

EXPECTED_CHAIN_EXACT = {
    "AP-T10-01": {"AML.T0051.001"},
    "AP-T16-02": {"AML.T0051.001"},
    "AP-T16-03": {"AML.T0110"},
    "AP-T8-01": {"AML.T0092"},
    "AP-T9-01": {"AML.T0053"},
    "AP-T9-02": {"AML.T0091.000"},
    "AP-T9-07": {"AML.T0101", "AML.T0029"},
    "AP-T9-05": {"AML.T0015", "AML.T0088"},
    "AP-T9-06": {"AML.T0091.000", "AML.T0080.000"},
}

EXPECTED_STEP_EXACT = {
    "AP-T10-01": {
        "craft_misleading_context": "AML.T0066",
        "obfuscate_malicious_content": "AML.T0067",
    },
    "AP-T16-02": {
        "stage_on_infrastructure": "AML.T0079",
        "execute_unintended_operations": "AML.T0053",
    },
    "AP-T16-03": {
        "develop_poisoned_tool": "AML.T0104",
        "inflate_registry_reputation": "AML.T0111",
        "invoke_privileged_tools": "AML.T0011.002",
    },
    "AP-T8-01": {"obtain_record_access": "AML.T0055"},
    "AP-T9-01": {"inject_instructions": "AML.T0051.001"},
    "AP-T9-02": {
        "extract_tokens": "AML.T0090",
        "poison_session_context": "AML.T0080.001",
    },
    "AP-T9-07": {"authenticate_as_agent": "AML.T0091.000"},
    "AP-T9-05": {
        "acquire_spoofing_tools": "AML.T0016.001",
        "evade_biometric_auth": "AML.T0015",
    },
    "AP-T9-06": {
        "extract_long_lived_tokens": "AML.T0090",
        "poison_session_context": "AML.T0080.001",
    },
}


@pytest.fixture(scope="module")
def raw_records() -> dict[str, dict]:
    return load_attack_patterns(AGENTIC_ONLY_PATH)


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def validated(raw_records, resolver) -> dict[str, AttackPattern]:
    return {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in raw_records.items()
    }


@pytest.fixture(scope="module")
def lineage():
    return load_catalog_lineage(LINEAGE_PATH)


def test_exact_resulting_id_set_and_no_deferred_live(raw_records) -> None:
    assert set(raw_records) == RESULTING_IDS
    assert DEFERRED_SOURCE_IDS.isdisjoint(raw_records)
    # T14 has no resulting records and no T8/T14 construct was forced beyond
    # the lineage outcomes.
    assert not any(pid.startswith("AP-T14-") for pid in raw_records)


def test_records_are_canonical_not_legacy(raw_records) -> None:
    for pid, record in raw_records.items():
        assert record["id"] == pid
        assert "kill_chain" not in record
        assert "canonical_chain" in record
        chain = record["canonical_chain"]
        assert chain["schema_version"] == "v1"
        assert chain["pattern_id"] == pid


def test_all_records_validate_against_pinned_resolver(validated) -> None:
    assert set(validated) == RESULTING_IDS


def test_chains_are_branch_free_total_order(validated) -> None:
    for pattern in validated.values():
        steps = pattern.canonical_chain.steps
        assert [s.order for s in steps] == list(range(1, len(steps) + 1))
        assert len({s.step_id for s in steps}) == len(steps)
        # Total order: no branching construct exists in the v1 model; the
        # only conditional construct is step-level condition gating.
        assert (
            pattern.canonical_chain.earliest_attacker_controlled_step_id
            == steps[0].step_id
        )
        assert steps[0].attacker_controlled


def test_semantic_digests_match_chain_semantics(validated) -> None:
    for pattern in validated.values():
        chain = pattern.canonical_chain
        assert chain.semantic_digest == compute_chain_semantic_digest(chain)


def test_taxonomy_context_pins_match_production(validated, resolver) -> None:
    pin = resolver.taxonomy_context
    for pattern in validated.values():
        ctx = pattern.canonical_chain.taxonomy_context
        assert ctx.atlas.release == pin.atlas.release
        assert ctx.atlas.digest == pin.atlas.digest
        assert ctx.laaf is None
        assert ctx.mapping_set_digest == pin.mapping_set_digest


def test_chain_and_step_mappings_match_lineage(validated) -> None:
    for pid, pattern in validated.items():
        chain_exact = {
            technique_id
            for mapping in pattern.canonical_chain.mappings
            if mapping.decision == "exact"
            for technique_id in mapping.ids
        }
        assert chain_exact == EXPECTED_CHAIN_EXACT[pid], pid
        step_exact = {}
        for step in pattern.canonical_chain.steps:
            for mapping in step.mappings:
                if mapping.decision == "exact":
                    assert len(mapping.ids) == 1
                    step_exact[step.step_id] = mapping.ids[0]
        assert step_exact == EXPECTED_STEP_EXACT[pid], pid


def test_role_sensitive_mapping_rule(validated) -> None:
    for pattern in validated.values():
        for step in pattern.canonical_chain.steps:
            decisions = [m.decision for m in step.mappings]
            if step.attacker_controlled:
                assert step.executor_role == "attacker"
                assert all(d in ("exact", "unmapped") for d in decisions)
            else:
                assert step.executor_role in ("system", "operator")
                assert all(d == "not_applicable" for d in decisions)


def test_unmapped_decisions_carry_rationale(validated) -> None:
    # Exact mappings derive their rationale from the lineage artifact and the
    # pinned ATLAS definition; rationalized unmapped decisions must justify
    # themselves in-record (model-enforced min_length=1).
    found_unmapped = False
    for pid, pattern in validated.items():
        scopes = [pattern.canonical_chain.mappings] + [
            s.mappings for s in pattern.canonical_chain.steps
        ]
        for mappings in scopes:
            for mapping in mappings:
                if mapping.decision == "unmapped":
                    found_unmapped = True
                    assert mapping.rationale.strip(), pid
    assert found_unmapped


def test_dispositions_and_split_match_lineage(lineage) -> None:
    by_source = {s["source_pattern_id"]: s for s in lineage["sources"]}
    for source_id, disposition in EXPECTED_DISPOSITIONS.items():
        assert by_source[source_id]["disposition"] == disposition
    for deferred_id in DEFERRED_SOURCE_IDS:
        entry = by_source[deferred_id]
        assert entry["disposition"] == "defer"
        assert not entry["resulting_patterns"]
    split = by_source["AP-T9-02"]
    assert [r["pattern_id"] for r in split["resulting_patterns"]] == [
        "AP-T9-02",
        "AP-T9-07",
    ]


def test_split_boundary_is_clean(validated) -> None:
    # AP-T9-02 owns immediate stolen-credential impersonation; AP-T9-07 owns
    # availability disruption (data destruction + rate-limit exhaustion).
    t902 = validated["AP-T9-02"].canonical_chain
    t907 = validated["AP-T9-07"].canonical_chain
    assert t902.steps[-1].step_id == "impersonated_operation_attributed"
    assert {s.step_id for s in t907.steps} == {
        "authenticate_as_agent",
        "destroy_agent_data",
        "exhaust_service_rate_limits",
    }


def test_conditions_actions_resources_are_typed(validated) -> None:
    for pattern in validated.values():
        chain = pattern.canonical_chain
        for step in chain.steps:
            assert step.action_kind in (
                "prepare",
                "deliver",
                "invoke",
                "transform",
                "persist",
                "observe",
                "impact",
            )
            assert (step.requirement == "conditional") == (step.condition is not None)
            for ref in step.consumed:
                assert ref.kind in ("artifact", "state")
            for ref in step.produced:
                assert ref.kind in ("artifact", "state", "effect")
            assert step.observable_postconditions
        assert chain.resource_slots
        ingress = [s for s in chain.resource_slots if s.purpose == "initial_ingress"]
        assert len(ingress) == 1
        assert ingress[0].slot_id == chain.initial_ingress_slot_id
        assert ingress[0].kind == "entry_point"


def test_provenance_is_honest_and_referenced(validated) -> None:
    for pattern in validated.values():
        for step in pattern.canonical_chain.steps:
            prov = step.provenance
            assert prov.tier in ("observed", "variant", "inferred", "designed")
            assert 0 <= prov.confidence <= 100
            assert prov.references
            assert prov.adaptation_rationale.strip()


def test_file_header_metadata_is_canonical() -> None:
    data = yaml.safe_load(AGENTIC_ONLY_PATH.read_text())
    assert data["source"]["lineage"] == "catalog-lineage.yaml v1.0.0"
    assert (
        "MITRE ATLAS 2026.05 (sole v1 mapping authority)"
        in data["source"]["derived_from"]
    )
