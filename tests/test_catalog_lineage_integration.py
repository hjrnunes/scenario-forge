"""Catalog-wide integration tests bridging the lineage artifact and the live catalog.

These tests load both ``catalog-lineage.yaml`` and the live
``load_attack_patterns()`` catalog and assert exact equality of:

- live pattern IDs vs lineage resulting pattern IDs (count 49, unique);
- chain-level exact ATLAS mapping IDs;
- flattened ``(step_id, id)`` step-level exact mappings;
- resource-slot plans.

They also document the mechanism-boundary contract: the lineage
``mechanism_boundary`` is concise authority and the live ``description`` may
elaborate without changing it.  No universal mechanical relation (exact,
prefix, or containment) holds across all 49 records, so no false equality
claim is made here.
"""

from __future__ import annotations

from scenario_forge.data.catalog_lineage import load_catalog_lineage
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _lineage_resulting() -> dict[str, dict]:
    """Return ``{pattern_id: resulting_record}`` from the lineage artifact."""
    artifact = load_catalog_lineage()
    out: dict[str, dict] = {}
    for src in artifact["sources"]:
        for r in src.get("resulting_patterns", []):
            out[r["pattern_id"]] = r
    return out


# ---------------------------------------------------------------------------
# ID equality
# ---------------------------------------------------------------------------


def test_live_ids_equal_lineage_resulting_ids() -> None:
    """Live catalog IDs exactly equal the set of lineage resulting pattern IDs."""
    live = load_attack_patterns()
    resulting = _lineage_resulting()
    assert set(live.keys()) == set(resulting.keys())


def test_resulting_count_is_49_and_unique() -> None:
    """The lineage artifact produces exactly 49 unique resulting pattern IDs."""
    resulting = _lineage_resulting()
    ids = list(resulting.keys())
    assert len(ids) == 49
    assert len(set(ids)) == 49


def test_live_count_is_49_and_unique() -> None:
    """The live catalog carries exactly 49 unique pattern IDs."""
    live = load_attack_patterns()
    assert len(live) == 49
    assert len(set(live.keys())) == 49


# ---------------------------------------------------------------------------
# Chain exact mapping IDs
# ---------------------------------------------------------------------------


def _live_chain_level_exact_ids(pattern: dict) -> set[str]:
    """Extract exact ATLAS IDs from a live pattern's chain-level mappings only
    (not step-level)."""
    cc = pattern["canonical_chain"]
    ids: set[str] = set()
    for m in cc.get("mappings", []):
        if m.get("decision") == "exact":
            ids.update(m["ids"])
    return ids


def _live_exact_chain_ids(pattern: dict) -> set[str]:
    """Extract all exact ATLAS IDs from a live pattern's canonical chain
    (both chain-level and step-level)."""
    cc = pattern["canonical_chain"]
    ids: set[str] = set()
    for m in cc.get("mappings", []):
        if m.get("decision") == "exact":
            ids.update(m["ids"])
    for step in cc.get("steps", []):
        for m in step.get("mappings", []):
            if m.get("decision") == "exact":
                ids.update(m["ids"])
    return ids


def _lineage_chain_ids(resulting: dict) -> set[str]:
    """Extract ATLAS IDs from a lineage resulting record's atlas_chain_mappings."""
    return {m["id"] for m in resulting.get("atlas_chain_mappings", [])}


def test_chain_exact_mapping_ids_match_lineage() -> None:
    """For every record, the live canonical-chain *chain-level* exact ATLAS IDs
    equal the lineage atlas_chain_mappings IDs.  (Step-level exact mappings
    are compared separately in ``test_step_exact_mappings_match_lineage``.)"""
    live = load_attack_patterns()
    resulting = _lineage_resulting()
    for pid in sorted(resulting):
        live_ids = _live_chain_level_exact_ids(live[pid])
        lin_ids = _lineage_chain_ids(resulting[pid])
        assert live_ids == lin_ids, (
            f"{pid}: live chain-level ids {sorted(live_ids)} != lineage {sorted(lin_ids)}"
        )


# ---------------------------------------------------------------------------
# Flattened (step_id, id) exact mappings
# ---------------------------------------------------------------------------


def _live_step_mappings(pattern: dict) -> dict[str, str]:
    """Return ``{step_id: atlas_id}`` for exact step mappings in a live pattern."""
    cc = pattern["canonical_chain"]
    out: dict[str, str] = {}
    for step in cc.get("steps", []):
        for m in step.get("mappings", []):
            if m.get("decision") == "exact":
                ids = m.get("ids", [])
                if ids:
                    out[step["step_id"]] = ids[0]
    return out


def _lineage_step_mappings(resulting: dict) -> dict[str, str]:
    """Return ``{step_id: atlas_id}`` from a lineage resulting record's
    atlas_step_mappings."""
    return {m["step"]: m["id"] for m in resulting.get("atlas_step_mappings", [])}


def test_step_exact_mappings_match_lineage() -> None:
    """For every record, the flattened ``(step_id, atlas_id)`` exact mappings
    from the live canonical chain equal the lineage atlas_step_mappings."""
    live = load_attack_patterns()
    resulting = _lineage_resulting()
    for pid in sorted(resulting):
        live_steps = _live_step_mappings(live[pid])
        lin_steps = _lineage_step_mappings(resulting[pid])
        assert live_steps == lin_steps, (
            f"{pid}: live step mappings {live_steps} != lineage {lin_steps}"
        )


# ---------------------------------------------------------------------------
# Resource-slot plans
# ---------------------------------------------------------------------------


def test_resource_slot_plans_match_lineage() -> None:
    """For every record, the live canonical-chain resource_slots equal the
    lineage resource_slot_plan."""
    live = load_attack_patterns()
    resulting = _lineage_resulting()
    for pid in sorted(resulting):
        live_rs = live[pid]["canonical_chain"].get("resource_slots", [])
        lin_rs = resulting[pid].get("resource_slot_plan", [])
        assert live_rs == lin_rs, (
            f"{pid}: live resource_slots {live_rs} != lineage {lin_rs}"
        )


# ---------------------------------------------------------------------------
# Canonical, model-valid, resolver-qualified, digest-valid
# ---------------------------------------------------------------------------


def test_all_live_records_are_canonical() -> None:
    """Every live record has a canonical_chain and no legacy kill_chain."""
    live = load_attack_patterns()
    for pid, record in live.items():
        assert "canonical_chain" in record, f"{pid} missing canonical_chain"
        assert "kill_chain" not in record, f"{pid} still has legacy kill_chain"


def test_all_live_records_are_model_valid() -> None:
    """Every live record parses as a valid AttackPattern and is qualified
    by the production resolver."""
    resolver = load_taxonomy_resolver()
    live = load_attack_patterns()
    for record in live.values():
        validate_attack_pattern(record, resolver)


def test_all_live_records_are_resolver_qualified() -> None:
    """Every exact ATLAS mapping in every live record is a valid pinned
    ATLAS identifier per the production resolver."""
    resolver = load_taxonomy_resolver()
    live = load_attack_patterns()
    for pid, record in live.items():
        for atlas_id in _live_exact_chain_ids(record):
            assert resolver.contains("ATLAS", atlas_id), (
                f"{pid}: exact mapping {atlas_id} not in pinned ATLAS identifiers"
            )


def test_all_live_records_are_digest_valid() -> None:
    """Every live canonical chain's semantic_digest matches the computed
    digest of its semantics."""
    live = load_attack_patterns()
    for pid, record in live.items():
        cc = record["canonical_chain"]
        expected = cc["semantic_digest"]
        actual = compute_chain_semantic_digest(cc)
        assert actual == expected, f"{pid}: semantic_digest mismatch"


# ---------------------------------------------------------------------------
# Mechanism-boundary contract documentation
# ---------------------------------------------------------------------------


def test_mechanism_boundary_contract_is_documented() -> None:
    """Document the mechanism-boundary contract.

    The lineage ``mechanism_boundary`` is concise authority; the live
    ``description`` may elaborate (e.g. prefix with 'An attacker …') without
    changing the boundary.  No universal mechanical relation (exact equality,
    prefix, or containment) holds across all 49 records, so no false equality
    claim is asserted.  This test records the observed distribution and
    ensures the contract is non-vacuous: at least the exact-match subset is
    non-empty and the total is 49.
    """
    live = load_attack_patterns()
    resulting = _lineage_resulting()
    exact = 0
    prefix = 0
    contain = 0
    neither = 0
    for pid in resulting:
        lin_mb = resulting[pid].get("mechanism_boundary", "").strip()
        live_desc = live[pid].get("description", "").strip()
        if lin_mb == live_desc:
            exact += 1
        elif live_desc.startswith(lin_mb):
            prefix += 1
        elif lin_mb in live_desc:
            contain += 1
        else:
            neither += 1
    total = exact + prefix + contain + neither
    assert total == 49
    # The contract is non-vacuous: exact-match subset is non-empty.
    assert exact > 0
    # No universal relation — 'neither' is expected to be non-zero.
    # This documents that the lineage boundary is authority, not a
    # verbatim copy of the live description.
    assert neither > 0
