"""Dedicated acceptance tests for the halluc-intent canonical-chain migration (422o.2.5).

Scope: ``data/taxonomies/attack-patterns/attack-patterns-halluc-intent.yaml`` only.

The file is migrated under the authoritative catalog-lineage dispositions for
its sixteen historical source records (AP-T5-01..04, AP-T6-01..05,
AP-T11-01..03, AP-T13-01..04): 5 retain, 7 narrow, 4 defer.  Deferred records
produce no live catalog record.  Each live record carries exactly one
branch-free, total-order canonical chain with typed artifact/state/effect
linkage, resource slots, per-step provenance tiers, and resolver-backed
ATLAS-only mapping decisions (LAAF absent; SSSOM ``skos:relatedMatch`` rows
are candidate provenance only).

These tests are additive: they never mutate shared fixtures and never edit
other taxonomy files.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from scenario_forge.data.catalog_lineage import load_catalog_lineage
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
    validate_legacy_attack_pattern,
)

AP_DIR = Path(__file__).resolve().parents[1] / "data" / "taxonomies" / "attack-patterns"
HALLUC_INTENT_PATH = AP_DIR / "attack-patterns-halluc-intent.yaml"
SSSOM_PATH = AP_DIR / "attack-patterns-halluc-intent.sssom.tsv"

# The authoritative resulting IDs, exactly.
EXPECTED_IDS = frozenset(
    {
        "AP-T11-01",
        "AP-T11-02",
        "AP-T11-03",
        "AP-T13-04",
        "AP-T5-01",
        "AP-T5-02",
        "AP-T5-04",
        "AP-T6-01",
        "AP-T6-02",
        "AP-T6-03",
        "AP-T6-04",
        "AP-T6-05",
    }
)

# Historical source IDs and their final dispositions (catalog-lineage.yaml).
RETAIN_SOURCES = frozenset(
    {"AP-T6-02", "AP-T6-03", "AP-T6-05", "AP-T11-01", "AP-T11-03"}
)
NARROW_SOURCES = frozenset(
    {
        "AP-T5-01",
        "AP-T5-02",
        "AP-T5-04",
        "AP-T6-01",
        "AP-T6-04",
        "AP-T11-02",
        "AP-T13-04",
    }
)
DEFERRED_SOURCES = frozenset({"AP-T5-03", "AP-T13-01", "AP-T13-02", "AP-T13-03"})
ALL_SOURCES = RETAIN_SOURCES | NARROW_SOURCES | DEFERRED_SOURCES

# Golden semantic digests: recompute-stable pins for the authored chains.
EXPECTED_DIGESTS = {
    "AP-T5-01": "686b5fb65be5914f355a66ffe7f328c88e473a3127db3aa8f731d78c179f47bd",
    "AP-T5-02": "d805bc5a367d606ac3ccbdc3706a5531be75d3ef56cc65d959cffb647b27fa48",
    "AP-T5-04": "f39457afba71866906432cd4431c07a5385be184dea0e2a44626ca993930db24",
    "AP-T6-01": "46950cfd2efda60a9ff2d583b205136f3e57b03f1de85220816db9c384257d2d",
    "AP-T6-02": "6234eeb29dc45fd9c84c1aa6a807b0374b584648b03b5fe9d477eb04e8ab9077",
    "AP-T6-03": "9b8070730f8ff6bc338fb0e199bf1bd92410d2b1fda0b62fd435cf297436c182",
    "AP-T6-04": "ff2c34fdfc5f28917d4b688c471cf1f1f1a5a3acb5b5367bfe84236228850cda",
    "AP-T6-05": "af8d8409ada5649362e5956d42e5561123270264d7a559cb43224d849db6f627",
    "AP-T11-01": "a3f5e927acc62782ac4096274c0de997d2f6a961e5d01e1063618a29afe0f863",
    "AP-T11-02": "3cdb8f807e5782c17ef9ddf2425436927f927b924fe6e68f1fa303d958871f96",
    "AP-T11-03": "d36e511d60897af34254063f4e14a0eecea7a273809aa8637b3f62c2cda13608",
    "AP-T13-04": "f7adaecbf6d6d36343c5c19cd5f35bbba52c7ae97c734f4d27dfe1a0b8555777",
}

LEGACY_KEYS = {"kill_chain", "evidence"}


@pytest.fixture(scope="module")
def raw() -> dict:
    return yaml.safe_load(HALLUC_INTENT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def patterns(raw: dict) -> dict:
    return raw["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def qualified(patterns: dict, resolver) -> dict:
    """Every live record qualified against the production pinned resolver."""
    return {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in patterns.items()
    }


@pytest.fixture(scope="module")
def lineage() -> dict:
    return load_catalog_lineage()


def _walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


# ---------------------------------------------------------------------------
# Resulting ID set and legacy removal
# ---------------------------------------------------------------------------


def test_resulting_id_set_is_exact(patterns: dict) -> None:
    assert set(patterns) == EXPECTED_IDS
    assert DEFERRED_SOURCES.isdisjoint(patterns)


def test_deferred_sources_have_no_resulting_lineage_record(lineage: dict) -> None:
    """The lineage itself records no resulting pattern for deferred sources."""
    for source in lineage["sources"]:
        if source["source_pattern_id"] in DEFERRED_SOURCES:
            assert source["disposition"] == "defer"
            assert not source.get("resulting_patterns")


def test_no_yaml_aliases_in_committed_data() -> None:
    """Anchors/aliases would silently couple records under hand edits."""
    text = HALLUC_INTENT_PATH.read_text(encoding="utf-8")
    data_lines = (
        line for line in text.splitlines() if line and not line.startswith("#")
    )
    assert not any("&id" in line or "*id" in line for line in data_lines)


def test_legacy_kill_chain_and_evidence_removed(patterns: dict) -> None:
    for pid, record in patterns.items():
        found = set(_walk_keys(record)) & LEGACY_KEYS
        assert not found, f"{pid}: legacy keys remain: {found}"
        with pytest.raises(ValidationError):
            validate_legacy_attack_pattern(record)


# ---------------------------------------------------------------------------
# Production qualification, pins, and digests
# ---------------------------------------------------------------------------


def test_all_records_qualify_against_production_resolver(qualified: dict) -> None:
    assert set(qualified) == EXPECTED_IDS


def test_taxonomy_context_matches_production_pins(patterns: dict, resolver) -> None:
    pinned = resolver.taxonomy_context
    assert pinned.atlas.release == "2026.05"
    assert pinned.laaf is None
    for record in patterns.values():
        context = record["canonical_chain"]["taxonomy_context"]
        assert context["atlas"]["release"] == pinned.atlas.release
        assert context["atlas"]["digest"] == pinned.atlas.digest
        assert context["laaf"] is None
        assert context["mapping_set_digest"] == pinned.mapping_set_digest


def test_semantic_digests_are_golden_and_recompute(patterns: dict) -> None:
    assert set(EXPECTED_DIGESTS) == set(patterns)
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["semantic_digest"] == EXPECTED_DIGESTS[pid]
        assert compute_chain_semantic_digest(chain) == EXPECTED_DIGESTS[pid]


def test_exact_mappings_are_atlas_only_and_resolver_backed(
    patterns: dict, resolver
) -> None:
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        scopes = [chain["mappings"], *(step["mappings"] for step in chain["steps"])]
        assert any(m["decision"] == "exact" for m in chain["mappings"]), pid
        for scope in scopes:
            for mapping in scope:
                assert mapping["taxonomy"] == "ATLAS", (
                    f"{pid}: LAAF decision under an absent LAAF pin"
                )
                if mapping["decision"] == "exact":
                    for identifier in mapping["ids"]:
                        assert resolver.contains("ATLAS", identifier), (
                            f"{pid}: unbacked exact id {identifier}"
                        )


# ---------------------------------------------------------------------------
# Chain shape: one branch-free total-order chain with honest typed linkage
# ---------------------------------------------------------------------------


def test_chains_are_branch_free_and_total_order(qualified: dict) -> None:
    for pid, pattern in qualified.items():
        chain = pattern.canonical_chain
        steps = chain.steps
        assert [step.order for step in steps] == list(range(1, len(steps) + 1)), pid
        for step in steps:
            assert step.requirement == "required", f"{pid}.{step.step_id}"
            assert step.condition is None, f"{pid}.{step.step_id}"
        # Exactly one terminal security outcome, on the final step.
        for step in steps[:-1]:
            assert not any(
                out.security_relevant and out.terminal
                for out in step.observable_postconditions
            ), f"{pid}.{step.step_id}"
        terminal = [
            out
            for out in steps[-1].observable_postconditions
            if out.security_relevant and out.terminal
        ]
        assert len(terminal) == 1, pid


def test_consumed_references_are_produced_upstream(qualified: dict) -> None:
    """Every consumed typed reference is produced by an earlier step: the
    chain's dataflow is explicitly linked, never dangling."""
    for pid, pattern in qualified.items():
        available: set[tuple[str, str]] = set()
        for step in pattern.canonical_chain.steps:
            for ref in step.consumed:
                key = (ref.kind, ref.ref_id)
                assert key in available, (
                    f"{pid}.{step.step_id} consumes unproduced {key}"
                )
            for ref in step.produced:
                available.add((ref.kind, ref.ref_id))


def test_resource_slots_and_ingress(qualified: dict) -> None:
    for pid, pattern in qualified.items():
        chain = pattern.canonical_chain
        ingress = [
            slot for slot in chain.resource_slots if slot.purpose == "initial_ingress"
        ]
        assert len(ingress) == 1, pid
        assert ingress[0].slot_id == chain.initial_ingress_slot_id, pid
        assert ingress[0].kind == "entry_point", pid
        # Every record declares at least one target/supporting resource beyond
        # ingress: the lineage slot plans are resource-bearing.
        assert any(
            slot.purpose in {"target", "supporting"} for slot in chain.resource_slots
        ), pid


# ---------------------------------------------------------------------------
# Lineage fidelity
# ---------------------------------------------------------------------------


def test_lineage_disposition_totals_for_owned_sources(lineage: dict) -> None:
    owned = [
        source
        for source in lineage["sources"]
        if source["source_pattern_id"] in ALL_SOURCES
    ]
    assert len(owned) == 16
    by_disposition = {"retain": set(), "narrow": set(), "defer": set()}
    for source in owned:
        by_disposition[source["disposition"]].add(source["source_pattern_id"])
    assert by_disposition["retain"] == RETAIN_SOURCES
    assert by_disposition["narrow"] == NARROW_SOURCES
    assert by_disposition["defer"] == DEFERRED_SOURCES


def test_lineage_resulting_patterns_match_live_records(
    lineage: dict, patterns: dict
) -> None:
    """Live chains honor the lineage's exact mapping identities and slot plans."""
    resulting = {}
    for source in lineage["sources"]:
        if source["source_pattern_id"] in ALL_SOURCES:
            for entry in source.get("resulting_patterns", []):
                resulting[entry["pattern_id"]] = entry
    assert set(resulting) == EXPECTED_IDS

    for pid, entry in resulting.items():
        chain = patterns[pid]["canonical_chain"]

        lineage_chain_ids = sorted(m["id"] for m in entry["atlas_chain_mappings"])
        live_chain_ids = sorted(
            identifier
            for mapping in chain["mappings"]
            if mapping["decision"] == "exact"
            for identifier in mapping["ids"]
        )
        assert live_chain_ids == lineage_chain_ids, pid

        lineage_step_ids = {m["step"]: m["id"] for m in entry["atlas_step_mappings"]}
        live_step_ids = {
            step["step_id"]: mapping["ids"][0]
            for step in chain["steps"]
            for mapping in step["mappings"]
            if mapping["decision"] == "exact"
        }
        # Every lineage step identity is asserted live with the same id.
        for step_id, identifier in lineage_step_ids.items():
            assert live_step_ids.get(step_id) == identifier, (
                f"{pid}.{step_id}: lineage {identifier} != live "
                f"{live_step_ids.get(step_id)}"
            )

        lineage_slots = {
            (slot["slot_id"], slot["kind"], slot["purpose"])
            for slot in entry["resource_slot_plan"]
        }
        live_slots = {
            (slot["slot_id"], slot["kind"], slot["purpose"])
            for slot in chain["resource_slots"]
        }
        assert live_slots == lineage_slots, pid


# ---------------------------------------------------------------------------
# Key semantic decisions
# ---------------------------------------------------------------------------


def test_t5_01_owns_factual_misinformation_not_operational_rules(
    patterns: dict,
) -> None:
    """OG-01 boundary: AP-T5-01 keeps recursive factual-misinformation
    compounding; injected operational-rule override belongs to AP-T1-01."""
    description = patterns["AP-T5-01"]["description"].lower()
    assert "compound" in description
    assert "false factual information" in description
    assert "operational-rule override belongs to ap-t1-01" in description


def test_t11_02_provenance_is_adapted_not_direct(patterns: dict) -> None:
    """AML.CS0047 is an analogue for workflow-generation manipulation: every
    step must carry adapted (non-observed) provenance, never a direct
    demonstration claim."""
    steps = patterns["AP-T11-02"]["canonical_chain"]["steps"]
    assert steps, "AP-T11-02 has no steps"
    for step in steps:
        provenance = step["provenance"]
        assert provenance["tier"] in {"variant", "inferred", "designed"}, (
            f"AP-T11-02.{step['step_id']}: tier {provenance['tier']} "
            "would overclaim direct demonstration"
        )
        reference_ids = {ref["reference_id"] for ref in provenance["references"]}
        if "AML.CS0047" in reference_ids:
            rationale = provenance["adaptation_rationale"].lower()
            assert "adapt" in rationale or "analog" in rationale, (
                f"AP-T11-02.{step['step_id']}: CS0047 cited without adaptation honesty"
            )


def test_sssom_rows_remain_candidate_relatedmatch_only() -> None:
    """The owned SSSOM provenance confers no mapping authority: all predicates
    stay skos:relatedMatch, and exact chain mappings never lean on SSSOM-only
    candidates (resolver backing is asserted separately)."""
    lines = [
        line
        for line in SSSOM_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    header = lines[0].split("\t")
    predicate_column = header.index("predicate_id")
    predicates = {line.split("\t")[predicate_column] for line in lines[1:]}
    assert predicates == {"skos:relatedMatch"}


# ---------------------------------------------------------------------------
# Catalog load integration (read-only)
# ---------------------------------------------------------------------------


def test_merged_catalog_contains_resulting_ids_only() -> None:
    catalog = load_attack_patterns()
    assert EXPECTED_IDS.issubset(catalog)
    assert DEFERRED_SOURCES.isdisjoint(catalog)
