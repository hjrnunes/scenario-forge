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

import copy
from collections import Counter

import pytest

from scenario_forge.data.catalog_lineage import load_catalog_lineage
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)


def _deep_copy_with_duplicate(artifact: dict, record: dict) -> dict:
    """Return a deep copy of *artifact* with *record* appended as a duplicate
    to the first source's ``resulting_patterns`` list."""
    patched = copy.deepcopy(artifact)
    patched["sources"][0]["resulting_patterns"].append(copy.deepcopy(record))
    return patched


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _lineage_resulting_raw() -> list[dict]:
    """Return the raw list of all resulting records from the lineage artifact.

    The list is returned *before* indexing by ``pattern_id`` so that count and
    uniqueness can be asserted independently (indexing into a dict would make
    the uniqueness check tautological).
    """
    artifact = load_catalog_lineage()
    records: list[dict] = []
    for src in artifact["sources"]:
        records.extend(src.get("resulting_patterns", []))
    return records


def _lineage_resulting_index() -> dict[str, dict]:
    """Return ``{pattern_id: resulting_record}`` from the lineage artifact.

    Callers should use ``_lineage_resulting_raw`` first when count/uniqueness
    matters; this helper is for per-record lookups after uniqueness is
    established.
    """
    return {r["pattern_id"]: r for r in _lineage_resulting_raw()}


# ---------------------------------------------------------------------------
# ID equality
# ---------------------------------------------------------------------------


def test_live_ids_equal_lineage_resulting_ids() -> None:
    """Live catalog IDs exactly equal the set of lineage resulting pattern IDs."""
    live = load_attack_patterns()
    resulting = _lineage_resulting_index()
    assert set(live.keys()) == set(resulting.keys())


def _assert_resulting_count_and_uniqueness(raw: list[dict]) -> None:
    """Assert that a raw resulting-record list has exactly 49 records with
    49 unique pattern IDs.

    Factored out so adversarial tests can call it against patched data
    to prove duplicates are *rejected* by the actual validation path.
    """
    raw_ids = [r["pattern_id"] for r in raw]
    assert len(raw_ids) == 49
    assert len(set(raw_ids)) == 49


def test_resulting_count_is_49_and_unique() -> None:
    """The lineage artifact produces exactly 49 raw resulting records with
    49 unique pattern IDs.

    The raw list is checked *before* indexing so that a duplicate
    ``pattern_id`` would be caught as a count mismatch (raw count > unique
    count), not silently collapsed by dict construction.
    """
    _assert_resulting_count_and_uniqueness(_lineage_resulting_raw())


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
    resulting = _lineage_resulting_index()
    for pid in sorted(resulting):
        live_ids = _live_chain_level_exact_ids(live[pid])
        lin_ids = _lineage_chain_ids(resulting[pid])
        assert live_ids == lin_ids, (
            f"{pid}: live chain-level ids {sorted(live_ids)} != lineage {sorted(lin_ids)}"
        )


# ---------------------------------------------------------------------------
# Flattened (step_id, id) exact mappings
# ---------------------------------------------------------------------------


def _live_step_mappings(pattern: dict) -> Counter[tuple[str, str]]:
    """Return a ``Counter`` of ``(step_id, atlas_id)`` pairs for every exact
    step mapping in a live pattern.

    Every ID in every exact mapping is flattened as a complete pair, so a
    step with multiple exact IDs produces one pair per ID.  A ``Counter`` is
    used so that duplicate ``(step_id, atlas_id)`` rows (if any) are detected
    rather than silently collapsed by a set or dict.
    """
    cc = pattern["canonical_chain"]
    out: Counter[tuple[str, str]] = Counter()
    for step in cc.get("steps", []):
        for m in step.get("mappings", []):
            if m.get("decision") == "exact":
                for atlas_id in m.get("ids", []):
                    out[(step["step_id"], atlas_id)] += 1
    return out


def _lineage_step_mappings(resulting: dict) -> Counter[tuple[str, str]]:
    """Return a ``Counter`` of ``(step, id)`` pairs from a lineage resulting
    record's ``atlas_step_mappings``.

    Every row is preserved as a complete pair.  A ``Counter`` is used so that
    duplicate rows (if any) are detected rather than silently collapsed by a
    dict keyed on ``step``.
    """
    out: Counter[tuple[str, str]] = Counter()
    for m in resulting.get("atlas_step_mappings", []):
        out[(m["step"], m["id"])] += 1
    return out


def test_step_exact_mappings_match_lineage() -> None:
    """For every record, the complete multiset of ``(step_id, atlas_id)``
    exact mappings from the live canonical chain equals the lineage
    ``atlas_step_mappings``.

    Both sides flatten every ID of every exact mapping into complete pairs
    and compare as ``Counter`` (multiset equality), so a second exact ID on
    a step or a duplicate lineage row would be detected.
    """
    live = load_attack_patterns()
    resulting = _lineage_resulting_index()
    for pid in sorted(resulting):
        live_steps = _live_step_mappings(live[pid])
        lin_steps = _lineage_step_mappings(resulting[pid])
        assert live_steps == lin_steps, (
            f"{pid}: live step mappings {dict(live_steps)} != lineage {dict(lin_steps)}"
        )


# ---------------------------------------------------------------------------
# Resource-slot plans
# ---------------------------------------------------------------------------


def test_resource_slot_plans_match_lineage() -> None:
    """For every record, the live canonical-chain resource_slots equal the
    lineage resource_slot_plan."""
    live = load_attack_patterns()
    resulting = _lineage_resulting_index()
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
    resulting = _lineage_resulting_index()
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


# ---------------------------------------------------------------------------
# Adversarial unit coverage for helper exactness
# ---------------------------------------------------------------------------


class TestLiveStepMappingsFlattensAllIds:
    """Prove that ``_live_step_mappings`` flattens every ID of every exact
    mapping, not just ``ids[0]``."""

    def test_single_id_step(self) -> None:
        pattern = {
            "canonical_chain": {
                "steps": [
                    {
                        "step_id": "s1",
                        "mappings": [
                            {"decision": "exact", "ids": ["AML.T0001"]},
                        ],
                    }
                ]
            }
        }
        result = _live_step_mappings(pattern)
        assert result == Counter({("s1", "AML.T0001"): 1})

    def test_multi_id_step_flattens_every_id(self) -> None:
        """A step with two exact IDs produces two complete pairs."""
        pattern = {
            "canonical_chain": {
                "steps": [
                    {
                        "step_id": "s1",
                        "mappings": [
                            {"decision": "exact", "ids": ["AML.T0001", "AML.T0002"]},
                        ],
                    }
                ]
            }
        }
        result = _live_step_mappings(pattern)
        assert result == Counter({("s1", "AML.T0001"): 1, ("s1", "AML.T0002"): 1})

    def test_old_ids0_bug_would_lose_second_id(self) -> None:
        """The old ``ids[0]``-only code would produce one pair; the fixed
        code produces two, and the two Counters are not equal."""
        pattern = {
            "canonical_chain": {
                "steps": [
                    {
                        "step_id": "s1",
                        "mappings": [
                            {"decision": "exact", "ids": ["AML.T0001", "AML.T0002"]},
                        ],
                    }
                ]
            }
        }
        correct = _live_step_mappings(pattern)
        buggy = Counter({("s1", "AML.T0001"): 1})
        assert correct != buggy, "fix must detect a second exact ID lost by ids[0]"


class TestLineageStepMappingsPreservesAllRows:
    """Prove that ``_lineage_step_mappings`` preserves every row as a complete
    pair, not dict-collapsing by ``step``."""

    def test_single_row(self) -> None:
        resulting = {
            "atlas_step_mappings": [
                {"step": "s1", "id": "AML.T0001"},
            ]
        }
        result = _lineage_step_mappings(resulting)
        assert result == Counter({("s1", "AML.T0001"): 1})

    def test_duplicate_step_different_id_preserved(self) -> None:
        """Two rows with the same step but different IDs must both survive."""
        resulting = {
            "atlas_step_mappings": [
                {"step": "s1", "id": "AML.T0001"},
                {"step": "s1", "id": "AML.T0002"},
            ]
        }
        result = _lineage_step_mappings(resulting)
        assert result == Counter({("s1", "AML.T0001"): 1, ("s1", "AML.T0002"): 1})

    def test_old_dict_collapse_bug_would_lose_second_row(self) -> None:
        """The old dict-comprehension code would collapse to one entry; the
        fixed Counter preserves both."""
        resulting = {
            "atlas_step_mappings": [
                {"step": "s1", "id": "AML.T0001"},
                {"step": "s1", "id": "AML.T0002"},
            ]
        }
        correct = _lineage_step_mappings(resulting)
        buggy = Counter({("s1", "AML.T0001"): 1})
        assert correct != buggy, "fix must detect a second row lost by dict collapse"


class TestLineageResultingRawDetectsDuplicates:
    """Prove that ``_lineage_resulting_raw`` returns a raw list (not a dict)
    so that duplicate ``pattern_id`` values are detectable, and that the
    real validation helper rejects them."""

    def test_raw_preserves_duplicate_pattern_ids(self, monkeypatch) -> None:
        """``_lineage_resulting_raw`` must return a raw list that preserves
        duplicate ``pattern_id`` values rather than silently collapsing them
        into a dict."""
        real_artifact = load_catalog_lineage()
        real_raw = _lineage_resulting_raw()
        # Sanity: the real artifact has 49 unique
        assert len(real_raw) == 49

        # Build a patched artifact with a duplicate resulting record
        patched = _deep_copy_with_duplicate(real_artifact, real_raw[0])
        monkeypatch.setattr(
            "tests.test_catalog_lineage_integration.load_catalog_lineage",
            lambda: patched,
        )

        raw = _lineage_resulting_raw()
        raw_ids = [r["pattern_id"] for r in raw]
        # The duplicate survives — raw count > unique count
        assert len(raw_ids) == 50
        assert len(set(raw_ids)) == 49

    def test_validation_rejects_duplicate_pattern_ids(self, monkeypatch) -> None:
        """The real ``_assert_resulting_count_and_uniqueness`` helper must
        reject a patched artifact with a duplicate ``pattern_id``."""
        real_artifact = load_catalog_lineage()
        real_raw = _lineage_resulting_raw()

        patched = _deep_copy_with_duplicate(real_artifact, real_raw[0])
        monkeypatch.setattr(
            "tests.test_catalog_lineage_integration.load_catalog_lineage",
            lambda: patched,
        )

        raw = _lineage_resulting_raw()
        with pytest.raises(AssertionError):
            _assert_resulting_count_and_uniqueness(raw)
