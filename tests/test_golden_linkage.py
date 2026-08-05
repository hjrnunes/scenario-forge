"""Golden linkage authority tests for all 49 canonical attack patterns.

These tests pin every pattern/step's exact ``resource_links`` and
``observable_outcome_links`` against a reviewed static fixture.  The
fixture (``tests/fixtures/golden_linkage.py``) is a non-self-derived
authority: it was generated once from the corrected canonical YAML and
pinned as static values, not derived from production or migration
heuristics at test time.

Tests operate on raw YAML records before indexing so that uniqueness
collapses in the catalog index cannot mask divergent linkage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)
from tests.fixtures.golden_linkage import GOLDEN_LINKAGE

_BASE = (
    Path(__file__).resolve().parent.parent / "data" / "taxonomies" / "attack-patterns"
)
_FILES = [
    "attack-patterns-agentic-only.yaml",
    "attack-patterns-atlas-derived.yaml",
    "attack-patterns-comms-human-supply.yaml",
    "attack-patterns-halluc-intent.yaml",
    "attack-patterns-memory-tool.yaml",
]


def _load_raw_patterns() -> dict[str, dict[str, Any]]:
    """Load raw pattern dicts from YAML before any catalog indexing."""
    patterns: dict[str, dict[str, Any]] = {}
    for fn in _FILES:
        with open(_BASE / fn) as f:
            data = yaml.safe_load(f)
        for pid, p in data["patterns"].items():
            patterns[pid] = p
    return patterns


def test_golden_covers_all_292_steps() -> None:
    """The golden fixture must cover every step in every pattern."""
    raw = _load_raw_patterns()
    total = sum(len(p["canonical_chain"]["steps"]) for p in raw.values())
    assert total == 292
    assert len(GOLDEN_LINKAGE) == 292


def test_every_step_matches_golden() -> None:
    """Every step's resource_links and observable_outcome_links must exactly
    match the reviewed golden fixture — no more, no fewer."""
    raw = _load_raw_patterns()
    for pid, p in raw.items():
        for s in p["canonical_chain"]["steps"]:
            key = f"{pid}/{s['step_id']}"
            assert key in GOLDEN_LINKAGE, f"{key} missing from golden"
            golden = GOLDEN_LINKAGE[key]
            assert s.get("boundary_position") == golden["boundary"], (
                f"{key} boundary mismatch: {s.get('boundary_position')} != {golden['boundary']}"
            )
            rl = s.get("resource_links", [])
            ol = s.get("observable_outcome_links", [])
            assert rl == golden["resource_links"], (
                f"{key} resource_links mismatch:\n  got={rl}\n  expected={golden['resource_links']}"
            )
            assert ol == golden["observable_outcome_links"], (
                f"{key} outcome_links mismatch:\n  got={ol}\n  expected={golden['observable_outcome_links']}"
            )


def test_all_77_outside_steps_have_empty_outcome_links() -> None:
    """Every outside step must have empty observable_outcome_links."""
    raw = _load_raw_patterns()
    outside_count = 0
    for pid, p in raw.items():
        for s in p["canonical_chain"]["steps"]:
            if s.get("boundary_position") == "outside":
                outside_count += 1
                assert s.get("observable_outcome_links", []) == [], (
                    f"{pid}/{s['step_id']} is outside but has outcome links"
                )
    assert outside_count == 77


def test_no_outside_step_has_activation_resource_link() -> None:
    """No outside step may carry an ingress or source_influence link."""
    raw = _load_raw_patterns()
    for pid, p in raw.items():
        for s in p["canonical_chain"]["steps"]:
            if s.get("boundary_position") == "outside":
                for rl in s.get("resource_links", []):
                    assert rl["role"] not in ("ingress", "source_influence"), (
                        f"{pid}/{s['step_id']} is outside but has {rl['role']} link"
                    )


def test_ap_t2_04_craft_payload_has_no_outcome_links() -> None:
    """Regression: AP-T2-04 craft_payload is an outside attacker preparation
    step.  It must not have observable outcome links."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T2-04"]["canonical_chain"]["steps"]
        if s["step_id"] == "craft_payload"
    )
    assert step["boundary_position"] == "outside"
    assert step["observable_outcome_links"] == []
    assert step["resource_links"] == []


def test_ap_t6_07_is_typed_infeasible_no_activation() -> None:
    """Regression: AP-T6-07 config_modification is prerequisite-based inside
    persistence, not direct ingress.  No step may carry an ingress or
    source_influence resource link.  The chain is structurally valid but
    candidate-v2-infeasible."""
    raw = _load_raw_patterns()
    chain = raw["AP-T6-07"]["canonical_chain"]
    for s in chain["steps"]:
        for rl in s.get("resource_links", []):
            assert rl["role"] not in ("ingress", "source_influence"), (
                f"AP-T6-07/{s['step_id']} must not have activation link, got {rl['role']}"
            )
    # The chain must still validate structurally.
    resolver = load_taxonomy_resolver()
    validate_attack_pattern(raw["AP-T6-07"], resolver)


def test_ap_t6_07_config_modification_outcome_is_persistent_state() -> None:
    """AP-T6-07 config_modification persists to agent_config, not to the
    ingress.  Its outcome link must be persistent_state/agent_config."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T6-07"]["canonical_chain"]["steps"]
        if s["step_id"] == "config_modification"
    )
    assert step["boundary_position"] == "inside"
    assert step["resource_links"] == []
    ol = step["observable_outcome_links"]
    assert len(ol) == 1
    assert ol[0]["observation"] == "persistent_state"
    assert ol[0]["binding_slot_id"] == "agent_config"


def test_all_49_patterns_validate_and_digests_match() -> None:
    """All 49 patterns must pass model validation and have matching digests."""
    resolver = load_taxonomy_resolver()
    patterns = load_attack_patterns()
    assert len(patterns) == 49
    for pid, raw in patterns.items():
        validate_attack_pattern(raw, resolver)
        chain = raw["canonical_chain"]
        assert chain["semantic_digest"] == compute_chain_semantic_digest(chain), (
            f"{pid} digest mismatch"
        )


def test_activation_classification_matches_golden() -> None:
    """45 direct-ingress, 3 source-influence, 1 infeasible (AP-T6-07)."""
    raw = _load_raw_patterns()
    ingress = []
    source = []
    none = []
    for pid, p in raw.items():
        chain = p["canonical_chain"]
        slot = chain["initial_ingress_slot_id"]
        has_ingress = any(
            rl["role"] == "ingress" and rl["slot_id"] == slot
            for s in chain["steps"]
            for rl in s.get("resource_links", [])
        )
        has_source = any(
            rl["role"] == "source_influence"
            and rl.get("target_ingress_slot_id") == slot
            for s in chain["steps"]
            for rl in s.get("resource_links", [])
        )
        if has_ingress:
            ingress.append(pid)
        elif has_source:
            source.append(pid)
        else:
            none.append(pid)
    assert len(ingress) == 45
    assert len(source) == 3
    assert none == ["AP-T6-07"]


def test_observation_kind_counts() -> None:
    """Pin the exact observation kind distribution across all non-outside steps."""
    raw = _load_raw_patterns()
    from collections import Counter

    kinds = Counter()
    for p in raw.values():
        for s in p["canonical_chain"]["steps"]:
            for ol in s.get("observable_outcome_links", []):
                kinds[ol["observation"]] += 1
    assert dict(kinds) == {
        "persistent_state": 148,
        "model_context": 46,
        "tool_invocation": 21,
    }


def test_no_duplicate_outcome_link_per_postcondition() -> None:
    """No step may have multiple outcome links for the same postcondition."""
    raw = _load_raw_patterns()
    for pid, p in raw.items():
        for s in p["canonical_chain"]["steps"]:
            pc_ids = [
                ol["postcondition_id"] for ol in s.get("observable_outcome_links", [])
            ]
            assert len(pc_ids) == len(set(pc_ids)), (
                f"{pid}/{s['step_id']} has duplicate outcome links for same postcondition"
            )


def test_every_outcome_link_references_valid_postcondition() -> None:
    """Every outcome link must reference a postcondition on the same step."""
    raw = _load_raw_patterns()
    for pid, p in raw.items():
        for s in p["canonical_chain"]["steps"]:
            pc_ids = {
                pc["postcondition_id"] for pc in s.get("observable_postconditions", [])
            }
            for ol in s.get("observable_outcome_links", []):
                assert ol["postcondition_id"] in pc_ids, (
                    f"{pid}/{s['step_id']} outcome link references absent postcondition "
                    f"{ol['postcondition_id']}"
                )


def test_every_outcome_link_binding_references_valid_slot() -> None:
    """Every outcome link's binding_slot_id must reference a declared slot."""
    raw = _load_raw_patterns()
    for pid, p in raw.items():
        chain = p["canonical_chain"]
        slot_ids = {slot["slot_id"] for slot in chain["resource_slots"]}
        for s in chain["steps"]:
            for ol in s.get("observable_outcome_links", []):
                assert ol["binding_slot_id"] in slot_ids, (
                    f"{pid}/{s['step_id']} outcome link references absent slot "
                    f"{ol['binding_slot_id']}"
                )


def test_71_source_facts_and_49_live_ids_preserved() -> None:
    """The catalog lineage must still have 71 historical source records and
    49 resulting live pattern IDs."""
    with open(_BASE / "catalog-lineage.yaml") as f:
        lineage = yaml.safe_load(f)
    sources = lineage.get("sources", [])
    resulting = []
    for src in sources:
        resulting.extend(src.get("resulting_patterns", []))
    assert len(sources) == 71
    resulting_ids = [r["pattern_id"] for r in resulting]
    assert len(resulting_ids) == 49
    assert len(set(resulting_ids)) == 49
