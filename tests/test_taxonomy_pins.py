"""Focused tests for production taxonomy pins and the pinned resolver (422o.2.1)."""

from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path
from typing import Any

import pytest
import yaml

from scenario_forge.data.taxonomy_pins import (
    PinnedTaxonomyResolver,
    compute_mapping_set_digest,
    load_atlas_identifiers,
    load_atlas_pin,
    load_taxonomy_resolver,
)
from scenario_forge.models.attack_pattern import (
    TaxonomyPin,
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

ZERO = "0" * 64

_SSSOM_HEADER = (
    "subject_id",
    "subject_source",
    "predicate_id",
    "object_id",
    "object_source",
    "mapping_justification",
)
_ROW_A = (
    "AP-T1-01",
    "scenario-forge",
    "skos:relatedMatch",
    "AML.T0053",
    "mitre-atlas",
    "semapv:ManualMappingCuration",
)
_ROW_B = (
    "AP-T1-01",
    "scenario-forge",
    "skos:relatedMatch",
    "S1",
    "laaf",
    "semapv:ManualMappingCuration",
)
_ROW_C = (
    "AP-T7-02",
    "scenario-forge",
    "skos:relatedMatch",
    "M3",
    "laaf",
    "semapv:ManualMappingCuration",
)


def _write_sssom(path: Path, rows: list[tuple[str, ...]]) -> Path:
    lines = ["\t".join(_SSSOM_HEADER)]
    lines.extend("\t".join(row) for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def bundled_pin() -> TaxonomyPin:
    return load_atlas_pin()


@pytest.fixture(scope="module")
def bundled_identifiers() -> frozenset[str]:
    return load_atlas_identifiers()


@pytest.fixture(scope="module")
def bundled_resolver() -> PinnedTaxonomyResolver:
    return load_taxonomy_resolver()


# ---------------------------------------------------------------------------
# ATLAS pin
# ---------------------------------------------------------------------------


def test_atlas_pin_is_deterministic_and_covers_exact_file_bytes() -> None:
    pin = load_atlas_pin()
    assert pin == load_atlas_pin()
    assert pin.release == "2026.05"
    bundled = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "taxonomies"
        / "atlas"
        / "ATLAS-2026.05.yaml"
    )
    assert pin.digest == hashlib.sha256(bundled.read_bytes()).hexdigest()


def test_atlas_pin_is_content_sensitive(tmp_path: Path) -> None:
    source = {"collection": {"version": "2099.01"}, "tactics": {}}
    first = tmp_path / "first.yaml"
    first.write_text(yaml.dump(source), encoding="utf-8")
    second = tmp_path / "second.yaml"
    second.write_text(yaml.dump(source) + "\n", encoding="utf-8")
    assert load_atlas_pin(first).digest != load_atlas_pin(second).digest
    assert load_atlas_pin(first).release == "2099.01"


def test_atlas_pin_requires_a_collection_version(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.dump({"tactics": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="collection version"):
        load_atlas_pin(broken)


# ---------------------------------------------------------------------------
# ATLAS identifiers
# ---------------------------------------------------------------------------


def test_atlas_identifiers_cover_tactics_techniques_and_subtechniques(
    bundled_identifiers: frozenset[str],
) -> None:
    identifiers = bundled_identifiers
    assert "AML.TA0000" in identifiers  # tactic
    assert "AML.T0000" in identifiers  # technique
    assert "AML.T0051.000" in identifiers  # sub-technique
    # Mitigations and case studies are never mapping targets.
    assert "AML.CS0000" not in identifiers
    assert all(not identifier.startswith("AML.M") for identifier in identifiers)
    assert len(identifiers) == 186


def test_atlas_identifiers_reject_incoherent_or_empty_sources(tmp_path: Path) -> None:
    incoherent = tmp_path / "incoherent.yaml"
    incoherent.write_text(
        yaml.dump(
            {
                "tactics": {"AML.TA9999": {"id": "AML.TA0000"}},
                "techniques": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="incoherent"):
        load_atlas_identifiers(incoherent)
    empty = tmp_path / "empty.yaml"
    empty.write_text(yaml.dump({"tactics": {}, "techniques": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="no tactic/technique"):
        load_atlas_identifiers(empty)


# ---------------------------------------------------------------------------
# Mapping-set digest
# ---------------------------------------------------------------------------


def test_bundled_mapping_set_digest_is_deterministic() -> None:
    digest = compute_mapping_set_digest()
    assert digest == compute_mapping_set_digest()
    assert len(digest) == 64
    int(digest, 16)


def test_mapping_set_digest_is_path_and_order_independent(tmp_path: Path) -> None:
    f1 = _write_sssom(tmp_path / "one.sssom.tsv", [_ROW_A, _ROW_B])
    f2 = _write_sssom(tmp_path / "two.sssom.tsv", [_ROW_C])
    combined = _write_sssom(tmp_path / "combined.sssom.tsv", [_ROW_C, _ROW_A, _ROW_B])
    baseline = compute_mapping_set_digest([f1, f2])
    # File order and row order do not matter.
    assert compute_mapping_set_digest([f2, f1]) == baseline
    # File layout does not matter: the same rows in one file digest equally.
    assert compute_mapping_set_digest([combined]) == baseline
    # Rows are a set: restating a row in a second file changes nothing.
    repeated = _write_sssom(tmp_path / "repeated.sssom.tsv", [_ROW_B, _ROW_C, _ROW_B])
    assert compute_mapping_set_digest([f1, repeated]) == baseline


def test_mapping_set_digest_is_content_sensitive(tmp_path: Path) -> None:
    baseline = compute_mapping_set_digest(
        [_write_sssom(tmp_path / "base.sssom.tsv", [_ROW_A, _ROW_B])]
    )
    edited = _write_sssom(
        tmp_path / "edited.sssom.tsv",
        [
            _ROW_A,
            (
                "AP-T1-01",
                "scenario-forge",
                "skos:relatedMatch",
                "S2",
                "laaf",
                "semapv:ManualMappingCuration",
            ),
        ],
    )
    assert compute_mapping_set_digest([edited]) != baseline
    added = _write_sssom(tmp_path / "added.sssom.tsv", [_ROW_A, _ROW_B, _ROW_C])
    assert compute_mapping_set_digest([added]) != baseline
    removed = _write_sssom(tmp_path / "removed.sssom.tsv", [_ROW_A])
    assert compute_mapping_set_digest([removed]) != baseline


def test_mapping_set_digest_normalizes_unicode_nfc(tmp_path: Path) -> None:
    composed = _write_sssom(tmp_path / "composed.sssom.tsv", [("café",) + _ROW_A[1:]])
    decomposed = _write_sssom(
        tmp_path / "decomposed.sssom.tsv",
        [(unicodedata.normalize("NFD", "café"),) + _ROW_A[1:]],
    )
    assert compute_mapping_set_digest([composed]) == compute_mapping_set_digest(
        [decomposed]
    )


# ---------------------------------------------------------------------------
# Resolver construction and coherence
# ---------------------------------------------------------------------------


def test_production_resolver_is_atlas_only_and_deterministic(
    bundled_resolver: PinnedTaxonomyResolver,
    bundled_pin: TaxonomyPin,
) -> None:
    resolver = bundled_resolver
    context = resolver.taxonomy_context
    assert context.atlas == bundled_pin
    assert context.laaf is None
    assert context.mapping_set_digest == compute_mapping_set_digest()
    assert resolver.taxonomy_context == load_taxonomy_resolver().taxonomy_context
    # Bundled pinned ATLAS ids resolve; unknown ids fail.
    assert resolver.contains("ATLAS", "AML.T0051.001")
    assert resolver.contains("ATLAS", "AML.TA0000")
    assert not resolver.contains("ATLAS", "AML.T9999")
    assert not resolver.contains("ATLAS", "AML.CS0000")
    # SSSOM skos:relatedMatch rows are provenance content: "S1" is mapped in
    # the bundled SSSOM files yet never becomes LAAF resolver membership.
    assert not resolver.contains("LAAF", "S1")
    assert not resolver.contains("LAAF", "AML.T0051.001")


def test_resolver_is_pure_in_memory_after_construction(
    monkeypatch, bundled_resolver: PinnedTaxonomyResolver
) -> None:
    resolver = bundled_resolver

    def _explode(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("resolver performed I/O after construction")

    monkeypatch.setattr("builtins.open", _explode)
    monkeypatch.setattr(Path, "read_bytes", _explode)
    assert resolver.contains("ATLAS", "AML.T0051.001")
    assert not resolver.contains("LAAF", "S1")
    assert resolver.taxonomy_context.laaf is None


def test_laaf_pin_and_membership_must_be_supplied_together(
    bundled_pin: TaxonomyPin,
    bundled_identifiers: frozenset[str],
) -> None:
    pin = TaxonomyPin(release="laaf-test", digest="a" * 64)
    atlas_pin = bundled_pin
    atlas_ids = bundled_identifiers
    digest = compute_mapping_set_digest()
    with pytest.raises(ValueError, match="together"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_pin=pin,
        )
    with pytest.raises(ValueError, match="together"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_identifiers={"L1"},
        )
    with pytest.raises(ValueError, match="must not be empty"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_pin=pin,
            laaf_identifiers=set(),
        )
    with pytest.raises(ValueError, match="non-empty strings"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=atlas_ids,
            mapping_set_digest=digest,
            laaf_pin=pin,
            laaf_identifiers={""},
        )
    with pytest.raises(ValueError, match="must not be empty"):
        PinnedTaxonomyResolver(
            atlas_pin=atlas_pin,
            atlas_identifiers=set(),
            mapping_set_digest=digest,
        )


def test_explicit_laaf_pin_and_membership_is_strictly_scoped(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    pin = TaxonomyPin(release="laaf-test", digest="b" * 64)
    resolver = load_taxonomy_resolver(laaf_pin=pin, laaf_identifiers={"L1", "M3"})
    assert resolver.taxonomy_context.laaf == pin
    assert resolver.contains("LAAF", "L1")
    assert resolver.contains("LAAF", "M3")
    assert not resolver.contains("LAAF", "S1")
    assert resolver.contains("ATLAS", "AML.T0051.001")
    # taxonomy_context equality stays meaningful across the optional axis.
    assert resolver.taxonomy_context != bundled_resolver.taxonomy_context


# ---------------------------------------------------------------------------
# Qualification through the production resolver
# ---------------------------------------------------------------------------


def _production_step(step_id: str, order: int, *, attacker: bool) -> dict[str, Any]:
    final = order == 3
    return {
        "step_id": step_id,
        "requirement": "required",
        "condition": None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "prepare" if attacker else "impact" if final else "observe",
        "consumed": [],
        "produced": [
            {"kind": "effect", "ref_id": f"effect.{order}", "value_type": "boolean"}
        ],
        "preconditions": [],
        "observable_postconditions": [
            {
                "postcondition_id": f"post.{order}",
                "description": "observable",
                "security_relevant": final,
                "terminal": final,
            }
        ],
        "order": order,
        "attacker_controlled": attacker,
        "provenance": {
            "tier": "observed",
            "references": [
                {"reference_type": "catalog", "reference_id": f"case-{order}"}
            ],
            "confidence": 90,
            "adaptation_rationale": "represented",
        },
        "mappings": (
            [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]}]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    }


def _production_pattern(
    resolver: PinnedTaxonomyResolver,
    *,
    chain_mappings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": resolver.taxonomy_context.model_dump(mode="json"),
        "mappings": chain_mappings
        or [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]}],
        "steps": [
            _production_step("step.1", 1, attacker=True),
            _production_step("step.2", 2, attacker=False),
            _production_step("step.3", 3, attacker=False),
        ],
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "entry_point", "purpose": "initial_ingress"}
        ],
        "initial_ingress_slot_id": "ingress",
    }
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain,
    }


def test_production_resolver_qualifies_atlas_only_chains(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    resolver = bundled_resolver
    pattern = validate_attack_pattern(_production_pattern(resolver), resolver)
    assert pattern.id == "AP-T1-01"
    assert pattern.canonical_chain.taxonomy_context.laaf is None


def test_production_resolver_rejects_unknown_atlas_ids(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    resolver = bundled_resolver
    raw = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T9999"]}
        ],
    )
    with pytest.raises(ValueError, match="unknown ATLAS id"):
        validate_attack_pattern(raw, resolver)


def test_production_resolver_fails_closed_on_any_laaf_decision(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    resolver = bundled_resolver
    raw = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {
                "decision": "unmapped",
                "taxonomy": "LAAF",
                "rationale": "Legacy migration hint only.",
            },
        ],
    )
    with pytest.raises(ValueError, match="LAAF taxonomy pin"):
        validate_attack_pattern(raw, resolver)


def test_explicit_laaf_resolver_qualifies_only_member_ids() -> None:
    pin = TaxonomyPin(release="laaf-test", digest="c" * 64)
    resolver = load_taxonomy_resolver(laaf_pin=pin, laaf_identifiers={"L1"})
    member = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {"decision": "exact", "taxonomy": "LAAF", "ids": ["L1"]},
        ],
    )
    assert validate_attack_pattern(member, resolver)
    outsider = _production_pattern(
        resolver,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {"decision": "exact", "taxonomy": "LAAF", "ids": ["L2"]},
        ],
    )
    with pytest.raises(ValueError, match="unknown LAAF id"):
        validate_attack_pattern(outsider, resolver)


def test_atlas_only_resolver_cannot_accept_a_pinned_laaf_chain(
    bundled_resolver: PinnedTaxonomyResolver,
) -> None:
    pin = TaxonomyPin(release="laaf-test", digest="d" * 64)
    pinned = load_taxonomy_resolver(laaf_pin=pin, laaf_identifiers={"L1"})
    raw = _production_pattern(
        pinned,
        chain_mappings=[
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0051.001"]},
            {"decision": "exact", "taxonomy": "LAAF", "ids": ["L1"]},
        ],
    )
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(raw, bundled_resolver)
