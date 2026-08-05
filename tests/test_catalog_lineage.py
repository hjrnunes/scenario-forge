"""Acceptance and mutation tests for the catalog-lineage decision artifact.

The artifact at ``data/taxonomies/attack-patterns/catalog-lineage.yaml`` is
the final authoritative lineage record for the 71 legacy attack-pattern
source IDs.  These tests pin its contract: exact source coverage, closed
vocabularies, resulting-record completeness, resolver-backed exact mappings,
split/supersede integrity, overlap-group resolution, taxonomy pins, and the
deterministic NFC/order-normalized semantic digest (with a golden value).
"""

from __future__ import annotations

import copy
import random
import unicodedata

import pytest
import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from scenario_forge.data.catalog_lineage import (
    _DEFAULT_LINEAGE_PATH,
    compute_catalog_lineage_digest,
    load_catalog_lineage,
    load_catalog_lineage_schema,
    validate_catalog_lineage,
)
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver

AP_DIR = _DEFAULT_LINEAGE_PATH.parent

GOLDEN_DIGEST = "2e54117e812935d401c76e0d2487c5ff5b8696ea61ff4bb68b3c0032ea4a59db"

# Tokens that would indicate an unfinished decision.  Final language such as
# "split evaluation concluded" is a resolved decision and is not flagged.
_FORBIDDEN_TOKENS = (
    "provisional",
    "unresolved",
    "tbd",
    "to be determined",
    "to be decided",
    "split-eval",
    "supersede-eval",
    "pending decision",
)

_EXPECTED_GROUPS = {
    "OG-01": {"AP-T1-01", "AP-T5-01", "AP-T5-04"},
    "OG-02": {"AP-T1-04", "AP-T12-03"},
    "OG-03": {"AP-T2-05", "AP-T6-03"},
    "OG-04": {"AP-T2-06", "AP-T6-02"},
    "OG-05": {"AP-T4-02", "AP-T13-03", "AP-T14-03"},
    "OG-06": {"AP-T9-01", "AP-T9-05"},
    "OG-07": {"AP-T9-02", "AP-T9-06"},
    "OG-08": {"AP-T8-01", "AP-T8-02", "AP-T8-03"},
    "OG-09": {"AP-T12-01", "AP-T13-04"},
    "OG-10": {"AP-T12-02", "AP-T14-01", "AP-T14-04"},
    "OG-11": {"AP-T13-02", "AP-T14-02"},
}


@pytest.fixture(scope="module")
def patterns() -> dict[str, dict]:
    return load_attack_patterns()


@pytest.fixture(scope="module")
def owners() -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(AP_DIR.glob("attack-patterns*.yaml")):
        for pid in load_attack_patterns(path):
            result[pid] = path.name
    return result


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def artifact(patterns, resolver, owners) -> dict:
    data = load_catalog_lineage()
    # The production artifact must pass the full validation gate unchanged.
    validate_catalog_lineage(data, patterns=patterns, resolver=resolver, owners=owners)
    return data


def _walk_strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, str):
        yield value


def _mutate(artifact: dict, fn) -> dict:
    mutant = copy.deepcopy(artifact)
    fn(mutant)
    return mutant


class TestSourceCoverage:
    def test_exactly_the_71_production_ids_once(self, artifact, patterns):
        ids = [s["source_pattern_id"] for s in artifact["sources"]]
        assert len(ids) == 71
        assert len(set(ids)) == 71
        assert set(ids) == set(patterns)

    def test_source_facts_match_production(self, artifact, patterns, owners):
        by_id = {s["source_pattern_id"]: s for s in artifact["sources"]}
        for pid, record in patterns.items():
            entry = by_id[pid]
            assert entry["source_file"] == owners[pid]
            assert entry["threat_id"] == record["threat_id"]
            evidence = record.get("evidence") or []
            assert entry["evidence_count"] == len(evidence)
            assert entry["legacy_kill_chain_steps"] == len(
                record.get("kill_chain") or []
            )
            tier = (
                "direct_demonstration"
                if any(e.get("type") == "direct_demonstration" for e in evidence)
                else "enrichment"
                if evidence
                else "kill_chain_only"
                if record.get("kill_chain")
                else "none"
            )
            assert entry["evidence_tier"] == tier

    def test_corrected_audit_fact_counts(self, artifact):
        """The corrected audit facts hold: 46/25 kill-chain split, 9
        evidence-bearing records / 11 entries, 4 direct, 5 enrichment."""
        sources = artifact["sources"]
        assert sum(1 for s in sources if s["legacy_kill_chain_steps"] > 0) == 46
        assert sum(1 for s in sources if s["legacy_kill_chain_steps"] == 0) == 25
        evidence_bearing = [s for s in sources if s["evidence_count"] > 0]
        assert len(evidence_bearing) == 9
        assert sum(s["evidence_count"] for s in evidence_bearing) == 11
        direct = {
            s["source_pattern_id"]
            for s in sources
            if s["evidence_tier"] == "direct_demonstration"
        }
        assert direct == {"AP-T3-04", "AP-T6-06", "AP-T11-05", "AP-T17-03"}
        enrichment = {
            s["source_pattern_id"]
            for s in sources
            if s["evidence_tier"] == "enrichment"
        }
        assert enrichment == {
            "AP-T1-01",
            "AP-T1-06",
            "AP-T11-01",
            "AP-T11-02",
            "AP-T17-01",
        }


class TestClosedVocabulary:
    def test_schema_is_valid_draft_2020_12(self):
        schema = load_catalog_lineage_schema()
        Draft202012Validator.check_schema(schema)

    def test_artifact_validates_against_schema(self, artifact):
        schema = load_catalog_lineage_schema()
        Draft202012Validator(schema).validate(artifact)

    def test_dispositions_come_from_closed_vocabulary(self, artifact):
        vocabulary = set(artifact["disposition_vocabulary"])
        assert vocabulary == {
            "retain",
            "narrow",
            "split",
            "supersede",
            "retire",
            "defer",
        }
        for entry in artifact["sources"]:
            assert entry["disposition"] in vocabulary

    def test_no_unresolved_or_provisional_language(self, artifact):
        for text in _walk_strings(artifact):
            lowered = text.lower()
            for token in _FORBIDDEN_TOKENS:
                assert token not in lowered, f"forbidden token {token!r} in {text!r}"


class TestResultingRecords:
    def test_every_result_is_complete(self, artifact):
        for entry in artifact["sources"]:
            if entry["disposition"] in ("retire", "defer"):
                continue
            assert entry["resulting_patterns"], entry["source_pattern_id"]
            for record in entry["resulting_patterns"]:
                assert record["mechanism_boundary"].strip()
                assert record["source_file"] == entry["source_file"]
                assert record["start_semantics"].strip()
                assert record["terminal_semantics"].strip()
                assert record["resource_slot_plan"], record["pattern_id"]
                assert record["provenance_plan"].strip()
                assert record["atlas_chain_mappings"], record["pattern_id"]
                assert record["atlas_step_mappings"], record["pattern_id"]

    def test_every_proposed_exact_id_exists_with_semantics(self, artifact, resolver):
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                mappings = (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                )
                for mapping in mappings:
                    assert resolver.contains("ATLAS", mapping["id"]), (
                        f"{record['pattern_id']} proposes {mapping['id']} "
                        "absent from the production resolver"
                    )
                    # Mere membership is not semantic approval: the identity
                    # rationale and evidence citation must be nonblank.
                    assert mapping["operational_identity_rationale"].strip()
                    assert mapping["evidence"].strip()

    def test_no_proposed_id_is_a_tactic_or_case_study(self, artifact):
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                for mapping in (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                ):
                    assert not mapping["id"].startswith("AML.TA")
                    assert not mapping["id"].startswith("AML.CS")


class TestSplitSupersedeIntegrity:
    def test_retired_and_deferred_have_no_results(self, artifact):
        for entry in artifact["sources"]:
            if entry["disposition"] in ("retire", "defer"):
                assert entry["resulting_patterns"] == []
                assert entry["deficiency"].strip()
                assert entry["reentry_conditions"].strip()

    def test_split_map_is_complete_and_explicit(self, artifact):
        expected = {
            "AP-T3-04": ["AP-T3-04", "AP-T3-05", "AP-T3-06"],
            "AP-T6-06": ["AP-T6-06", "AP-T6-07"],
            "AP-T9-02": ["AP-T9-02", "AP-T9-07"],
            "AP-T17-03": ["AP-T17-03", "AP-T17-04"],
        }
        splits = {
            s["source_pattern_id"]: [r["pattern_id"] for r in s["resulting_patterns"]]
            for s in artifact["sources"]
            if s["disposition"] == "split"
        }
        assert splits == expected

    def test_resulting_ids_unique_and_collision_free(self, artifact, patterns):
        resulting = [
            (entry["source_pattern_id"], record["pattern_id"])
            for entry in artifact["sources"]
            for record in entry["resulting_patterns"]
        ]
        ids = [rid for _, rid in resulting]
        assert len(ids) == len(set(ids))
        for pid, rid in resulting:
            if rid in patterns:
                # Only a source continuing its own id may reuse a catalog id.
                assert rid == pid

    def test_split_derived_ids_follow_deterministic_naming(self, artifact, patterns):
        family_used: dict[str, set[int]] = {}
        for cid in patterns:
            fam, _, nn = cid.removeprefix("AP-T").partition("-")
            family_used.setdefault(fam, set()).add(int(nn))
        for entry in sorted(artifact["sources"], key=lambda e: e["source_pattern_id"]):
            if entry["disposition"] != "split":
                continue
            pid = entry["source_pattern_id"]
            fam = pid.removeprefix("AP-T").partition("-")[0]
            results = entry["resulting_patterns"]
            assert results[0]["pattern_id"] == pid
            used = family_used[fam]
            for record in results[1:]:
                nn = 1
                while nn in used:
                    nn += 1
                assert record["pattern_id"] == f"AP-T{fam}-{nn:02d}"
                used.add(nn)

    def test_resulting_file_ownership_is_non_overlapping(self, artifact):
        """Every resulting record stays with its source file, so later
        authoring waves partition cleanly by file."""
        for entry in artifact["sources"]:
            for record in entry["resulting_patterns"]:
                assert record["source_file"] == entry["source_file"]


class TestOverlapGroups:
    def test_expected_groups_with_one_resolution_each(self, artifact):
        groups = {g["group_id"]: g for g in artifact["overlap_groups"]}
        assert set(groups) == set(_EXPECTED_GROUPS)
        for gid, members in _EXPECTED_GROUPS.items():
            assert set(groups[gid]["members"]) == members
            assert groups[gid]["resolution"].strip()

    def test_membership_consistent_with_entries(self, artifact):
        member_to_group = {
            member: g["group_id"]
            for g in artifact["overlap_groups"]
            for member in g["members"]
        }
        for entry in artifact["sources"]:
            pid = entry["source_pattern_id"]
            assert entry["overlap_group"] == member_to_group.get(pid)


class TestTaxonomyPins:
    def test_pins_match_production_resolver(self, artifact, resolver):
        context = artifact["taxonomy_context"]
        expected = resolver.taxonomy_context
        assert context["atlas"]["release"] == expected.atlas.release
        assert context["atlas"]["digest"] == expected.atlas.digest
        assert context["mapping_set_digest"] == expected.mapping_set_digest
        assert context["laaf"] is None
        assert expected.laaf is None

    def test_sssom_rows_are_provenance_only(self, artifact):
        """SSSOM candidates live exclusively under provenance; mapping fields
        never silently inherit them without an identity rationale."""
        for entry in artifact["sources"]:
            assert "sssom_atlas_candidates" in entry["provenance"]
            for record in entry["resulting_patterns"]:
                for mapping in (
                    record["atlas_chain_mappings"] + record["atlas_step_mappings"]
                ):
                    assert mapping["operational_identity_rationale"].strip()


class TestDigest:
    def test_golden_digest(self, artifact):
        assert artifact["release"]["semantic_digest"] == GOLDEN_DIGEST
        assert compute_catalog_lineage_digest(artifact) == GOLDEN_DIGEST

    def test_digest_is_order_insensitive(self, artifact):
        shuffled = copy.deepcopy(artifact)
        rng = random.Random(20260805)
        shuffled["sources"] = rng.sample(shuffled["sources"], len(shuffled["sources"]))
        shuffled["overlap_groups"] = list(reversed(shuffled["overlap_groups"]))
        reordered = {k: shuffled[k] for k in reversed(list(shuffled.keys()))}
        assert compute_catalog_lineage_digest(reordered) == GOLDEN_DIGEST

    def test_digest_is_nfc_normalized(self, artifact):
        nfd = copy.deepcopy(artifact)
        nfd["release"]["description"] = unicodedata.normalize("NFD", "Café — lineage")
        nfc = copy.deepcopy(artifact)
        nfc["release"]["description"] = unicodedata.normalize("NFC", "Café — lineage")
        assert compute_catalog_lineage_digest(nfd) == compute_catalog_lineage_digest(
            nfc
        )
        assert compute_catalog_lineage_digest(nfc) != GOLDEN_DIGEST

    def test_digest_excludes_only_its_own_field(self, artifact):
        # Mutating the digest field alone must not change the recomputed value.
        mutated = copy.deepcopy(artifact)
        mutated["release"]["semantic_digest"] = "0" * 64
        assert compute_catalog_lineage_digest(mutated) == GOLDEN_DIGEST
        # Mutating anything else must change it.
        for fn in (
            lambda a: a["sources"][0].__setitem__("rationale", "tampered"),
            lambda a: a["overlap_groups"][0].__setitem__("resolution", "tampered"),
            lambda a: a.__setitem__("schema_version", "2"),
        ):
            mutant = _mutate(artifact, fn)
            assert compute_catalog_lineage_digest(mutant) != GOLDEN_DIGEST


class TestMutationRejection:
    def _expect_failure(self, artifact, fn, patterns, resolver, owners):
        mutant = _mutate(artifact, fn)
        # Keep the digest consistent so the mutation under test is what fails.
        mutant["release"]["semantic_digest"] = compute_catalog_lineage_digest(mutant)
        with pytest.raises((ValueError, ValidationError)):
            validate_catalog_lineage(
                mutant, patterns=patterns, resolver=resolver, owners=owners
            )

    def test_missing_source_rejected(self, artifact, patterns, resolver, owners):
        self._expect_failure(
            artifact, lambda a: a["sources"].pop(0), patterns, resolver, owners
        )

    def test_extra_source_rejected(self, artifact, patterns, resolver, owners):
        def add(a):
            dupe = copy.deepcopy(a["sources"][0])
            dupe["source_pattern_id"] = "AP-T99-01"
            a["sources"].append(dupe)

        self._expect_failure(artifact, add, patterns, resolver, owners)

    def test_result_on_retired_source_rejected(
        self, artifact, patterns, resolver, owners
    ):
        def add(a):
            retired = next(s for s in a["sources"] if s["disposition"] == "retire")
            donor = next(
                r
                for s in a["sources"]
                for r in s["resulting_patterns"]
                if r["pattern_id"] == s["source_pattern_id"]
            )
            record = copy.deepcopy(donor)
            record["pattern_id"] = retired["source_pattern_id"]
            record["source_file"] = retired["source_file"]
            retired["resulting_patterns"] = [record]

        self._expect_failure(artifact, add, patterns, resolver, owners)

    def test_unknown_atlas_id_rejected(self, artifact, patterns, resolver, owners):
        def swap(a):
            record = next(r for s in a["sources"] for r in s["resulting_patterns"])
            record["atlas_chain_mappings"][0]["id"] = "AML.T9999"

        self._expect_failure(artifact, swap, patterns, resolver, owners)

    def test_blank_identity_rationale_rejected(
        self, artifact, patterns, resolver, owners
    ):
        def blank(a):
            record = next(r for s in a["sources"] for r in s["resulting_patterns"])
            record["atlas_chain_mappings"][0]["operational_identity_rationale"] = ""

        self._expect_failure(artifact, blank, patterns, resolver, owners)

    def test_colliding_resulting_id_rejected(
        self, artifact, patterns, resolver, owners
    ):
        def collide(a):
            entry = next(
                s
                for s in a["sources"]
                if s["disposition"] == "split" and s["source_pattern_id"] == "AP-T3-04"
            )
            entry["resulting_patterns"][1]["pattern_id"] = "AP-T1-01"

        self._expect_failure(artifact, collide, patterns, resolver, owners)

    def test_pin_mismatch_rejected(self, artifact, patterns, resolver, owners):
        self._expect_failure(
            artifact,
            lambda a: a["taxonomy_context"]["atlas"].__setitem__("digest", "0" * 64),
            patterns,
            resolver,
            owners,
        )

    def test_stale_digest_rejected(self, artifact, patterns, resolver, owners):
        mutant = _mutate(
            artifact, lambda a: a["sources"][0].__setitem__("rationale", "tampered")
        )
        with pytest.raises(ValueError, match="digest mismatch"):
            validate_catalog_lineage(
                mutant, patterns=patterns, resolver=resolver, owners=owners
            )

    def test_unresolved_overlap_member_rejected(
        self, artifact, patterns, resolver, owners
    ):
        def drop(a):
            group = next(g for g in a["overlap_groups"] if g["group_id"] == "OG-02")
            group["members"] = [m for m in group["members"] if m != "AP-T12-03"]

        self._expect_failure(artifact, drop, patterns, resolver, owners)


class TestArtifactFile:
    def test_artifact_is_the_only_added_taxonomy_file(self):
        """The lineage artifact must sit beside the unchanged attack-pattern
        YAML/SSSOM files (whose own pin tests guard their bytes)."""
        names = {p.name for p in AP_DIR.glob("*.yaml")} | {
            p.name for p in AP_DIR.glob("*.sssom.tsv")
        }
        assert names == {
            "attack-patterns.yaml",
            "attack-patterns-agentic-only.yaml",
            "attack-patterns-atlas-derived.yaml",
            "attack-patterns-comms-human-supply.yaml",
            "attack-patterns-halluc-intent.yaml",
            "attack-patterns-memory-tool.yaml",
            "attack-patterns.sssom.tsv",
            "attack-patterns-agentic-only.sssom.tsv",
            "attack-patterns-atlas-derived.sssom.tsv",
            "attack-patterns-comms-human-supply.sssom.tsv",
            "attack-patterns-halluc-intent.sssom.tsv",
            "attack-patterns-memory-tool.sssom.tsv",
            "catalog-lineage.yaml",
        }

    def test_artifact_round_trips_through_yaml(self):
        raw = yaml.safe_load(_DEFAULT_LINEAGE_PATH.read_text())
        assert compute_catalog_lineage_digest(raw) == raw["release"]["semantic_digest"]
