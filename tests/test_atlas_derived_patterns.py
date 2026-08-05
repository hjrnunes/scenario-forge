"""Dedicated tests for the ATLAS-derived canonical chains (bead 422o.2.3).

Wave contract for ``data/taxonomies/attack-patterns/attack-patterns-atlas-derived.yaml``:

- exactly the nine authoritative resulting ids from catalog-lineage.yaml
  (AP-T1-06, AP-T11-05, AP-T17-03, AP-T17-04, AP-T3-04, AP-T3-05, AP-T3-06,
  AP-T6-06, AP-T6-07) migrate to the canonical-chain contract; legacy
  ``kill_chain``/``evidence`` fields are gone and the records fail legacy
  validation (the legacy/catalogue boundary stays explicit);
- every record parses, signs (semantic digest recomputation + golden pin),
  and qualifies through the production pinned resolver (ATLAS-only; LAAF
  absent so any LAAF decision fails closed);
- chain-scope and step-scope exact ATLAS mappings, resource-slot plans, and
  step sequences match the lineage's approved decisions exactly — including
  the split boundaries (no technique bleeds across sibling records);
- every exact mapping carries operational identity and evidence: chain-scope
  in the description (the v1 model has no chain-scope rationale field),
  step-scope in provenance; AML.CS case-step citations are checked against
  the pinned ATLAS case-step index, with ``retag``/``analogue`` hedges
  required to name the pinned technique they diverge from;
- cross-step linkage is explicit: every consumed reference is produced by
  an earlier step of the same chain.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from scenario_forge.data.catalog_lineage import load_atlas_case_step_index
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.models.attack_pattern import (
    AttackPattern,
    ExactMapping,
    compute_chain_semantic_digest,
    validate_attack_pattern,
    validate_legacy_attack_pattern,
)

_FILE = "data/taxonomies/attack-patterns/attack-patterns-atlas-derived.yaml"

# Authoritative resulting set from catalog-lineage.yaml for the five
# historical sources AP-T1-06, AP-T11-05, AP-T17-03, AP-T3-04, AP-T6-06.
EXPECTED: dict[str, dict[str, Any]] = {
    "AP-T1-06": {
        "threat_id": "T1",
        "chain_exact": {"AML.T0070", "AML.T0077"},
        "step_exact": {
            "zero_click_activation": {"AML.T0051.001"},
            "rendered_output_exfiltration": {"AML.T0077"},
        },
        "steps": [
            "craft_payload",
            "deliver_content",
            "rag_ingestion",
            "zero_click_activation",
            "data_collection",
            "rendered_output_exfiltration",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("rag_corpus", "integration", "intermediate"),
            ("exfil_endpoint", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0093", "AML.T0085", "AML.T0057", "AML.T0048"},
    },
    "AP-T3-04": {
        "threat_id": "T3",
        "chain_exact": {"AML.T0049"},
        "step_exact": {
            "reconnaissance": {"AML.T0006"},
            "initial_access": {"AML.T0049"},
        },
        "steps": ["reconnaissance", "initial_access"],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("control_interface", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0083", "AML.T0055", "AML.T0091.000", "AML.T0053"},
    },
    "AP-T3-05": {
        "threat_id": "T3",
        "chain_exact": {"AML.T0083"},
        "step_exact": {
            "config_credential_harvest": {"AML.T0083"},
            "env_credential_harvest": {"AML.T0055"},
            "lateral_movement": {"AML.T0091.000"},
        },
        "steps": [
            "config_credential_harvest",
            "env_credential_harvest",
            "lateral_movement",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("control_interface", "integration", "intermediate"),
            ("connected_service", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0049", "AML.T0006", "AML.T0051.000", "AML.T0053"},
    },
    "AP-T3-06": {
        "threat_id": "T3",
        "chain_exact": {"AML.T0051.000", "AML.T0053"},
        "step_exact": {
            "arbitrary_prompting": {"AML.T0051.000"},
            "privileged_tool_execution": {"AML.T0053"},
            "impact": {"AML.T0112.000"},
        },
        "steps": [
            "arbitrary_prompting",
            "system_discovery",
            "privileged_tool_execution",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("agent_tools", "tool", "intermediate"),
            ("container", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0049", "AML.T0083", "AML.T0055", "AML.T0091.000"},
    },
    "AP-T6-06": {
        "threat_id": "T6",
        "chain_exact": {"AML.T0054", "AML.T0051.001"},
        "step_exact": {
            "discover_control_sequences": {"AML.T0069.000"},
            "craft_injection": {"AML.T0065"},
            "injection_activation": {"AML.T0051.001"},
            "control_sequence_spoofing": {"AML.T0054"},
        },
        "steps": [
            "reconnaissance",
            "discover_control_sequences",
            "craft_injection",
            "stage_infrastructure",
            "social_engineering_lure",
            "initial_access",
            "injection_activation",
            "control_sequence_spoofing",
            "script_execution",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("control_sequences", "integration", "target"),
            ("execution_tool", "tool", "intermediate"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {
            "AML.T0081",
            "AML.T0108",
            "AML.T0080.001",
            "AML.T0051.002",
        },
    },
    "AP-T6-07": {
        "threat_id": "T6",
        "chain_exact": {"AML.T0081", "AML.T0108"},
        "step_exact": {
            "config_modification": {"AML.T0081"},
            "poisoned_prompt_activation": {"AML.T0051.002"},
            "propagation": {"AML.T0080.001"},
            "c2_activation": {"AML.T0108"},
        },
        "steps": [
            "config_modification",
            "poisoned_prompt_activation",
            "propagation",
            "c2_activation",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("agent_config", "integration", "intermediate"),
            ("c2_channel", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0054", "AML.T0069.000", "AML.T0065"},
    },
    "AP-T11-05": {
        "threat_id": "T11",
        "chain_exact": {"AML.T0100", "AML.T0051.001"},
        "step_exact": {
            "delivery": {"AML.T0078"},
            "gui_action_injection": {"AML.T0051.001"},
            "host_execution": {"AML.T0112.000"},
        },
        "steps": [
            "generate_adversarial_content",
            "stage_infrastructure",
            "delivery",
            "engagement",
            "gui_action_injection",
            "host_execution",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("malicious_site", "integration", "intermediate"),
            ("computer_use_agent", "tool", "intermediate"),
            ("host", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0017", "AML.T0079", "AML.T0053"},
    },
    "AP-T17-03": {
        "threat_id": "T17",
        "chain_exact": {"AML.T0073", "AML.T0104"},
        "step_exact": {
            "namesquatting": {"AML.T0073"},
            "publish_poisoned_tool": {"AML.T0104"},
            "tool_invocation": {"AML.T0011.002"},
            "exfiltration": {"AML.T0086"},
        },
        "steps": [
            "namesquatting",
            "develop_poisoned_tool",
            "publish_poisoned_tool",
            "supply_chain_distribution",
            "persistence",
            "tool_invocation",
            "exfiltration",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("tool_registry", "integration", "intermediate"),
            ("adopter_agent", "tool", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0109", "AML.T0111"},
    },
    "AP-T17-04": {
        "threat_id": "T17",
        "chain_exact": {"AML.T0109"},
        "step_exact": {
            "rug_pull_timing": {"AML.T0111"},
            "exfiltration": {"AML.T0086"},
        },
        "steps": [
            "publish_clean_tool",
            "rug_pull_timing",
            "push_malicious_update",
            "upgrade_distribution",
            "persistence",
            "tool_invocation",
            "exfiltration",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("tool_registry", "integration", "intermediate"),
            ("adopter_agent", "tool", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0073", "AML.T0104", "AML.T0011.002"},
    },
}

# Golden semantic digests of the authored chains: any semantic content edit
# must recompute these deliberately, not silently.
GOLDEN_DIGESTS = {
    "AP-T1-06": "fe445af904cde56022f4ad2e69c00adab9b2407a47ec23761047cbed9a843a1a",
    "AP-T3-04": "2117b6a9c4c163bd740a52cbc28d81eb64e8fcc4d30d909d87e0c260cbec1fd0",
    "AP-T3-05": "155d72ec8b178e1521cc7040275c8065824a66ec076fbeaf8a1f1b1ce81c52c4",
    "AP-T3-06": "b0516b957229509392a9b7af78caec95ddc85b58c8f1109b0853f3c8d491e1e9",
    "AP-T6-06": "99cf3d3bd01b4e97798926b777a1e47abbf2b22204b352c1493fa15979b03d63",
    "AP-T6-07": "a4398b01f9fa9529fdcbfa1ebafb1d9399a2ba764918885dd628b9b2eae6d8b5",
    "AP-T11-05": "e595dc888cb7bc345cfdcec9ffe3f8c9a91a27e0a273dcdf8b6819c6e0874194",
    "AP-T17-03": "ad2e1a30ee1caa142eb4f8c1b7a9039693527e0dc08dce0257ab24884af66a69",
    "AP-T17-04": "82be435cc29b946ddb1d2c6445ee3e6639be46c8e58f853918b0949e2377a74d",
}

# Split-derived first steps presuppose a sibling pattern's outcome; the
# precondition must be declared explicitly as a runtime_state existence fact.
EXPECTED_PRECONDITIONS = {
    ("AP-T3-05", "config_credential_harvest"): "control_interface_accessible",
    ("AP-T3-06", "arbitrary_prompting"): "control_interface_accessible",
    ("AP-T6-07", "config_modification"): "attacker_code_execution_on_agent_host",
}

_TIER_CONFIDENCE = {"observed": (85, 100), "variant": (60, 85), "inferred": (0, 60)}
_CASE_STEP_RE = re.compile(r"AML\.(CS\d{4}) S(\d{2})")
_HEDGE_TOKENS = ("analogue", "retag")


@pytest.fixture(scope="module")
def records() -> dict[str, dict]:
    return load_attack_patterns(_FILE)


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def case_steps():
    return load_atlas_case_step_index()


@pytest.fixture(scope="module")
def patterns(records, resolver) -> dict[str, AttackPattern]:
    return {pid: validate_attack_pattern(raw, resolver) for pid, raw in records.items()}


def _exact_ids(mappings) -> set[str]:
    return {tid for m in mappings if isinstance(m, ExactMapping) for tid in m.ids}


def _all_exact_ids(chain) -> set[str]:
    ids = _exact_ids(chain.mappings)
    for step in chain.steps:
        ids |= _exact_ids(step.mappings)
    return ids


def _step_by_id(chain, step_id: str):
    (step,) = [s for s in chain.steps if s.step_id == step_id]
    return step


class TestResultingSet:
    def test_exactly_the_nine_authoritative_ids(self, records):
        assert set(records) == set(EXPECTED)

    def test_merged_catalog_contains_all_nine_without_collision(self):
        merged = load_attack_patterns()
        for pid in EXPECTED:
            assert pid in merged
            assert merged[pid]["threat_id"] == EXPECTED[pid]["threat_id"]

    def test_threat_ids(self, patterns):
        for pid, pattern in patterns.items():
            assert pattern.threat_id == EXPECTED[pid]["threat_id"]


class TestLegacyIsolation:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_no_legacy_fields(self, records, pid):
        assert "kill_chain" not in records[pid]
        assert "evidence" not in records[pid]

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_records_fail_legacy_validation(self, records, pid):
        with pytest.raises(ValidationError):
            validate_legacy_attack_pattern(records[pid])

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_records_are_canonical_schema_valid(self, records, pid):
        schema = AttackPattern.model_json_schema()
        assert Draft202012Validator(schema).is_valid(records[pid])


class TestQualificationAndDigest:
    def test_taxonomy_context_pins_production_resolver(self, patterns, resolver):
        for pattern in patterns.values():
            context = pattern.canonical_chain.taxonomy_context
            assert context == resolver.taxonomy_context
            assert context.laaf is None

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_semantic_digest_recomputes_and_matches_golden(self, records, pid):
        chain = records[pid]["canonical_chain"]
        assert chain["semantic_digest"] == GOLDEN_DIGESTS[pid]
        assert compute_chain_semantic_digest(chain) == GOLDEN_DIGESTS[pid]
        reordered = {key: chain[key] for key in reversed(chain)}
        assert compute_chain_semantic_digest(reordered) == GOLDEN_DIGESTS[pid]

    def test_no_laaf_decisions_anywhere(self, records):
        for raw in records.values():
            chain = raw["canonical_chain"]
            scopes = [chain["mappings"], *(s["mappings"] for s in chain["steps"])]
            for mappings in scopes:
                for mapping in mappings:
                    assert mapping["taxonomy"] == "ATLAS"

    def test_every_exact_id_is_resolver_member(self, patterns, resolver):
        for pattern in patterns.values():
            for tid in _all_exact_ids(pattern.canonical_chain):
                assert resolver.contains("ATLAS", tid)


class TestLineageFidelity:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_chain_scope_exact_ids(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        assert _exact_ids(chain.mappings) == EXPECTED[pid]["chain_exact"]
        assert any(isinstance(m, ExactMapping) for m in chain.mappings)

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_step_scope_exact_ids(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        actual = {
            step.step_id: _exact_ids(step.mappings)
            for step in chain.steps
            if _exact_ids(step.mappings)
        }
        assert actual == EXPECTED[pid]["step_exact"]

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_split_boundary_exclusivity(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        assert _all_exact_ids(chain).isdisjoint(EXPECTED[pid]["forbidden_exact"])

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_step_sequence_and_total_order(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        assert [s.step_id for s in chain.steps] == EXPECTED[pid]["steps"]
        assert [s.order for s in chain.steps] == list(
            range(1, len(EXPECTED[pid]["steps"]) + 1)
        )

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_resource_slot_plan(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        actual = [(s.slot_id, s.kind, s.purpose) for s in chain.resource_slots]
        assert sorted(actual) == sorted(EXPECTED[pid]["slots"])
        assert chain.initial_ingress_slot_id == "ingress"


class TestChainSemantics:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_start_and_terminal(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        first, last = chain.steps[0], chain.steps[-1]
        assert first.attacker_controlled
        assert chain.earliest_attacker_controlled_step_id == first.step_id
        for step in chain.steps[:-1]:
            assert not any(
                p.security_relevant and p.terminal
                for p in step.observable_postconditions
            )
        assert any(
            p.security_relevant and p.terminal for p in last.observable_postconditions
        )

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_consumed_references_link_to_earlier_produced(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        produced_so_far: dict[str, str] = {}
        for step in chain.steps:
            for ref in step.consumed:
                assert ref.ref_id in produced_so_far, (
                    f"{pid}:{step.step_id} consumes {ref.ref_id} "
                    "which no earlier step produced"
                )
                assert ref.kind == produced_so_far[ref.ref_id]
                assert ref.kind in ("artifact", "state")
            for ref in step.produced:
                produced_so_far[ref.ref_id] = ref.kind

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_executor_mapping_coherence(self, patterns, pid):
        for step in patterns[pid].canonical_chain.steps:
            if step.attacker_controlled:
                assert step.executor_role == "attacker"
                assert not any(m.decision == "not_applicable" for m in step.mappings)
                for m in step.mappings:
                    if m.decision == "unmapped":
                        assert m.rationale.strip()
            else:
                assert all(m.decision == "not_applicable" for m in step.mappings)

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_provenance_tiers_confidence_and_lineage_reference(self, patterns, pid):
        for step in patterns[pid].canonical_chain.steps:
            lo, hi = _TIER_CONFIDENCE[step.provenance.tier]
            assert lo <= step.provenance.confidence <= hi
            assert step.provenance.adaptation_rationale.strip()
            refs = step.provenance.references
            assert (
                "design_record",
                f"catalog-lineage:{pid}",
            ) in {(r.reference_type, r.reference_id) for r in refs}

    @pytest.mark.parametrize(
        "pid,step_id",
        [(pid, sid) for pid, sid in EXPECTED_PRECONDITIONS],
    )
    def test_split_preconditions_declared(self, patterns, pid, step_id):
        step = _step_by_id(patterns[pid].canonical_chain, step_id)
        (pre,) = step.preconditions
        assert pre.condition.op == "existence"
        assert pre.condition.exists is True
        fact = pre.condition.fact
        assert fact.namespace == "runtime_state"
        assert fact.fact_id == EXPECTED_PRECONDITIONS[(pid, step_id)]


class TestEvidenceAndRationale:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_chain_exact_ids_have_identity_and_evidence_in_description(
        self, patterns, pid
    ):
        description = patterns[pid].description
        for tid in EXPECTED[pid]["chain_exact"]:
            assert tid in description
            window = description.split(tid, 1)[1]
            window = re.split(r"AML\.T\d{4}(?:\.\d{3})? —", window)[0]
            assert "exact" in window.lower()
            assert "AML.CS" in window
            assert "pinned technique definition" in window

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_case_step_citations_exist_in_pinned_atlas(self, patterns, case_steps, pid):
        pattern = patterns[pid]
        texts = [pattern.description]
        for step in pattern.canonical_chain.steps:
            texts.append(step.provenance.adaptation_rationale)
            for mapping in step.mappings:
                rationale = getattr(mapping, "rationale", "")
                if rationale:
                    texts.append(rationale)
        cited = set()
        for text in texts:
            for case, step_num in _CASE_STEP_RE.findall(text):
                cited.add((f"AML.{case}", f"S{step_num}"))
        assert cited, pid
        for case, step_id in cited:
            assert case in case_steps, f"{pid}: {case} absent from pinned ATLAS"
            assert step_id in case_steps[case], (
                f"{pid}: {case} {step_id} absent from pinned ATLAS"
            )

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_exact_step_mappings_citation_honesty(self, patterns, case_steps, pid):
        """Unhedged exact mappings must cite a step that pins the technique.

        Hedged mappings (``retag``/``analogue``) deliberately diverge from the
        pinned relationship and must name the pinned technique they replace.
        """
        chain = patterns[pid].canonical_chain
        for step_id, tids in EXPECTED[pid]["step_exact"].items():
            step = _step_by_id(chain, step_id)
            rationale = step.provenance.adaptation_rationale
            refs = [
                r.reference_id
                for r in step.provenance.references
                if r.reference_type == "catalog"
            ]
            for tid in tids:
                if any(token in rationale for token in _HEDGE_TOKENS):
                    pinned_elsewhere = re.findall(r"AML\.T\d{4}(?:\.\d{3})?", rationale)
                    assert any(t != tid for t in pinned_elsewhere), (
                        f"{pid}:{step_id}:{tid} hedge must name the pinned "
                        "technique it diverges from"
                    )
                else:
                    assert any(
                        (m := _CASE_STEP_RE.fullmatch(ref))
                        and tid in case_steps[f"AML.{m.group(1)}"][f"S{m.group(2)}"]
                        for ref in refs
                    ), (
                        f"{pid}:{step_id}:{tid} unhedged exact mapping lacks a "
                        "reference to a case step that pins it"
                    )
