"""Wave test for the memory-tool canonical-chain migration (bead 422o.2.4).

Validates data/taxonomies/attack-patterns/attack-patterns-memory-tool.yaml
against the authoritative catalog-lineage.yaml dispositions for the 17
historical memory-tool sources (T1-T4):

- exactly the 14 authoritative resulting records exist, in catalog order;
  deferred sources (AP-T3-01, AP-T4-02, AP-T4-04) produce no live record;
- legacy ``kill_chain``/``evidence`` fields are removed;
- every record parses and qualifies against the production taxonomy resolver
  (ATLAS is the sole v1 authority; LAAF is absent);
- each canonical chain is one branch-free total-order chain whose step mapping
  decisions, chain mapping, resource slots, and description match the lineage
  entry exactly, with a recomputed semantic digest.
"""

from __future__ import annotations

import pytest
import yaml

from scenario_forge.data.catalog_lineage import load_catalog_lineage
from scenario_forge.data.loaders import (
    _DEFAULT_ATTACK_PATTERNS_DIR,
    load_attack_patterns,
)
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

MEMORY_TOOL_FILE = _DEFAULT_ATTACK_PATTERNS_DIR / "attack-patterns-memory-tool.yaml"

EXPECTED_IDS = [
    "AP-T1-01",
    "AP-T1-02",
    "AP-T1-03",
    "AP-T1-04",
    "AP-T2-01",
    "AP-T2-02",
    "AP-T2-03",
    "AP-T2-04",
    "AP-T2-05",
    "AP-T2-06",
    "AP-T3-02",
    "AP-T3-03",
    "AP-T4-01",
    "AP-T4-03",
]

DEFERRED_IDS = ["AP-T3-01", "AP-T4-02", "AP-T4-04"]


@pytest.fixture(scope="module")
def document() -> dict:
    return yaml.safe_load(MEMORY_TOOL_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def patterns(document) -> dict:
    return document["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def lineage() -> dict:
    return {
        entry["source_pattern_id"]: entry for entry in load_catalog_lineage()["sources"]
    }


def resulting(lineage: dict, pid: str) -> dict:
    records = lineage[pid]["resulting_patterns"]
    assert len(records) == 1
    return records[0]


def test_exact_resulting_id_set_and_order(patterns) -> None:
    assert list(patterns) == EXPECTED_IDS


def test_deferred_sources_produce_no_live_record(patterns) -> None:
    for pid in DEFERRED_IDS:
        assert pid not in patterns


def test_legacy_fields_removed(patterns) -> None:
    for pid, record in patterns.items():
        assert "kill_chain" not in record, pid
        assert "evidence" not in record, pid


def test_records_validate_against_production_resolver(patterns, resolver) -> None:
    for record in patterns.values():
        validate_attack_pattern(record, resolver)


def test_envelope_and_threat_context_preserved(patterns, lineage) -> None:
    for pid, record in patterns.items():
        entry = lineage[pid]
        assert record["id"] == pid
        assert record["threat_id"] == entry["threat_id"]
        assert record["name"]
        assert record["prerequisite_capabilities"]["min_zones"]


def test_description_is_lineage_mechanism_boundary(patterns, lineage) -> None:
    for pid, record in patterns.items():
        assert record["description"] == resulting(lineage, pid)["mechanism_boundary"]


def test_chain_mapping_is_exactly_lineage_chain_mapping(patterns, lineage) -> None:
    for pid, record in patterns.items():
        res = resulting(lineage, pid)
        mappings = record["canonical_chain"]["mappings"]
        assert len(mappings) == 1
        (mapping,) = mappings
        assert mapping["decision"] == "exact"
        assert mapping["taxonomy"] == "ATLAS"
        assert list(mapping["ids"]) == [m["id"] for m in res["atlas_chain_mappings"]]


def test_resource_slots_are_lineage_slot_plan_verbatim(patterns, lineage) -> None:
    for pid, record in patterns.items():
        res = resulting(lineage, pid)
        slots = [
            (s["slot_id"], s["kind"], s["purpose"])
            for s in record["canonical_chain"]["resource_slots"]
        ]
        assert slots == [
            (s["slot_id"], s["kind"], s["purpose"]) for s in res["resource_slot_plan"]
        ]
        chain = record["canonical_chain"]
        ingress = [
            s for s in chain["resource_slots"] if s["purpose"] == "initial_ingress"
        ]
        assert len(ingress) == 1
        assert chain["initial_ingress_slot_id"] == ingress[0]["slot_id"]


def test_step_mapping_decisions_match_lineage(patterns, lineage) -> None:
    for pid, record in patterns.items():
        res = resulting(lineage, pid)
        lineage_step_mappings = {
            m["step"]: m["id"] for m in res.get("atlas_step_mappings", [])
        }
        seen = set()
        for step in record["canonical_chain"]["steps"]:
            (decision,) = step["mappings"]
            seen.add(step["step_id"])
            if step["step_id"] in lineage_step_mappings:
                assert decision["decision"] == "exact", (pid, step["step_id"])
                assert decision["ids"] == [lineage_step_mappings[step["step_id"]]]
            elif step["attacker_controlled"]:
                assert decision["decision"] == "unmapped", (pid, step["step_id"])
                assert decision["rationale"].strip(), (pid, step["step_id"])
            else:
                assert decision["decision"] == "not_applicable", (pid, step["step_id"])
        assert set(lineage_step_mappings) <= seen, pid


def test_chain_is_branch_free_total_order(patterns) -> None:
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        assert [s["order"] for s in steps] == list(range(1, len(steps) + 1)), pid
        assert all(s["requirement"] == "required" for s in steps), pid
        assert all(s["condition"] is None for s in steps), pid
        assert len({s["step_id"] for s in steps}) == len(steps), pid


def test_start_semantics(patterns) -> None:
    """The earliest attacker-controlled action is the first chain step."""
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        first = chain["steps"][0]
        assert first["attacker_controlled"], pid
        assert first["executor_role"] == "attacker", pid
        assert chain["earliest_attacker_controlled_step_id"] == first["step_id"], pid


def test_terminal_semantics(patterns) -> None:
    """Exactly the final step carries the security-relevant terminal outcome."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        for step in steps[:-1]:
            assert not any(
                p["security_relevant"] and p["terminal"]
                for p in step["observable_postconditions"]
            ), (pid, step["step_id"])
        assert any(
            p["security_relevant"] and p["terminal"]
            for p in steps[-1]["observable_postconditions"]
        ), pid


def test_consumed_references_are_produced_in_order(patterns) -> None:
    """Every consumed reference is produced by an earlier step (causal order)."""
    for pid, record in patterns.items():
        produced: set[str] = set()
        for step in record["canonical_chain"]["steps"]:
            for ref in step["consumed"]:
                assert ref["ref_id"] in produced, (pid, step["step_id"], ref["ref_id"])
            produced |= {ref["ref_id"] for ref in step["produced"]}


def test_provenance_is_tiered_and_cited(patterns) -> None:
    for pid, record in patterns.items():
        for step in record["canonical_chain"]["steps"]:
            provenance = step["provenance"]
            assert provenance["tier"] in {"observed", "variant", "inferred", "designed"}
            assert 0 <= provenance["confidence"] <= 100
            assert provenance["references"], (pid, step["step_id"])
            assert provenance["adaptation_rationale"].strip(), (pid, step["step_id"])


def test_semantic_digest_recomputes(patterns) -> None:
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["semantic_digest"] == compute_chain_semantic_digest(chain), pid


def test_taxonomy_context_pins_resolver_and_laaf_absent(patterns, resolver) -> None:
    expected = resolver.taxonomy_context.model_dump(mode="json")
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["taxonomy_context"] == expected, pid
        assert chain["taxonomy_context"]["laaf"] is None, pid
        decisions = list(chain["mappings"]) + [
            m for s in chain["steps"] for m in s["mappings"]
        ]
        assert all(m["taxonomy"] == "ATLAS" for m in decisions), pid


def test_catalog_loader_integrates_migrated_records(resolver) -> None:
    loaded = load_attack_patterns()
    for pid in EXPECTED_IDS:
        assert pid in loaded
        validate_attack_pattern(loaded[pid], resolver)
    for pid in DEFERRED_IDS:
        assert pid not in loaded
