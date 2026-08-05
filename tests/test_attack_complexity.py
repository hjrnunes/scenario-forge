"""Acceptance tests for the cmps.7 attack-complexity assessment.

Covers:
- candidate lower bound from typed candidate-v2 inputs (no zone counts,
  no technique tuples, no prose/labels)
- final assessment from typed realized action/access evidence only
- admission invariant with typed retry/quarantine routing (fail-closed)
- actor capability immutability (byte-for-byte) across computation and
  mismatch handling, including removal of the novice multi-zone guard
- deterministic reason ordering/dedup, rule version, and monotonicity
  (candidate lower bound never exceeds final)
- envelope/report persistence distinguishing actor capability, candidate
  lower bound, final required level, rule version, and reasons
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import TypeAdapter, ValidationError

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.attack_pattern import (
    compute_chain_semantic_digest,
)
from scenario_forge.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    ToolInvocationAction,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from scenario_forge.models.complexity import (
    COMPLEXITY_RULE_TABLE,
    AttackComplexityAssessment,
    Call0RegenerationRouting,
    CapabilityAdmissionViolation,
    ComplexityAdmissionRouting,
    ComplexityEvidenceReference,
    ComplexityPhaseAssessment,
    ComplexityReason,
    QuarantineRouting,
    RealizationRetryRouting,
)
from scenario_forge.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    RiskCardRef,
    ScenarioEnvelope,
)
from scenario_forge.pipeline.complexity import (
    assess_candidate_complexity,
    assess_final_complexity,
    evaluate_capability_admission,
)
from scenario_forge.pipeline.generate import generate_scenario
from scenario_forge.pipeline.projection import (
    ProjectedCandidate,
    ProjectionBudget,
    capture_capability_snapshot,
    project_authoritative_candidates,
)
from scenario_forge.pipeline.seeds import ScenarioSeed

ZERO = "0" * 64


# ---------------------------------------------------------------------------
# Candidate-v2 fixtures (projected through the merged 422o.3 seam)
# ---------------------------------------------------------------------------


class _TaxonomyResolver:
    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) == ("ATLAS", "AML.T0001")


def _mk_step(step_id: str, order: int, *, attacker: bool, final: bool = False) -> dict:
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
        "resource_links": (
            [
                {
                    "slot_id": "ingress",
                    "role": "ingress",
                    "trust_boundary_slot_id": None,
                }
            ]
            if attacker and order == 1
            else []
        ),
        "observable_outcome_links": (
            # Security-relevant terminal steps require an explicit outcome
            # link for model validation.
            [
                {
                    "postcondition_id": f"post.{order}",
                    "observation": "model_context",
                    "binding_slot_id": "ingress",
                }
            ]
            if final
            else []
        ),
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
            [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    }


def _pattern_with_attacker_steps(n_attacker: int) -> dict[str, Any]:
    steps = [
        _mk_step(f"step.{order}", order, attacker=True)
        for order in range(1, n_attacker + 1)
    ]
    steps.append(_mk_step(f"step.{n_attacker + 1}", n_attacker + 1, attacker=False))
    steps.append(
        _mk_step(f"step.{n_attacker + 2}", n_attacker + 2, attacker=False, final=True)
    )
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            "laaf": None,
            "mapping_set_digest": ZERO,
        },
        "mappings": [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}],
        "steps": steps,
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "entry_point", "purpose": "initial_ingress"},
            {"slot_id": "tool", "kind": "tool", "purpose": "supporting"},
            {"slot_id": "source", "kind": "integration", "purpose": "supporting"},
            {
                "slot_id": "boundary",
                "kind": "trust_boundary",
                "purpose": "intermediate",
            },
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


def _profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )


def _candidate(n_attacker: int = 1) -> ProjectedCandidate:
    raw = _pattern_with_attacker_steps(n_attacker)
    resolver = _TaxonomyResolver(
        __import__("scenario_forge.models.attack_pattern", fromlist=["AttackPattern"])
        .AttackPattern.model_validate(raw)
        .canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(_profile(), ())
    batch = project_authoritative_candidates(
        [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=8)
    )
    assert batch.candidates, f"expected candidates, got {batch.infeasibilities}"
    return batch.candidates[0]


def _requirements_digest(requirements: list[dict[str, Any]]) -> str:
    payload = b"scenario-forge:execution-requirements:v1\0" + json.dumps(
        requirements,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _candidate_with_requirements(*requirements: dict[str, Any]) -> ProjectedCandidate:
    """Rebuild a projected candidate carrying extra typed requirements."""
    data = _candidate().model_dump(mode="json")
    data["execution_requirements"].extend(requirements)
    data["complexity_inputs"]["execution_requirement_count"] = len(
        data["execution_requirements"]
    )
    data["execution_requirements_digest"] = _requirements_digest(
        data["execution_requirements"]
    )
    return ProjectedCandidate.model_validate(data)


# ---------------------------------------------------------------------------
# Realized evidence fixtures (cmps.9 typed actions, cmps.6 access provenance)
# ---------------------------------------------------------------------------


def _leaf(node_id: str, zone: str | None, action: Any) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id, label=node_id, gate=GateType.LEAF, zone=zone, action=action
    )


def _access(
    *, ingress_mode: str = "direct", access_class: str = "public"
) -> ActorAccessProvenance:
    return ActorAccessProvenance(
        initial_entry_point_id="ep:v1:" + "ab" * 16,
        ingress_mode=ingress_mode,
        access_class=access_class,
    )


def _actor(capability_level: str = "novice") -> ActorProfile:
    return ActorProfile(
        actor_type="adversarial-user",
        capability_level=capability_level,
        beliefs=["The system processes user input."],
        desires=["I want to manipulate output."],
        intentions=["I will craft adversarial prompts."],
        resources=["Public tutorials"],
    )


# ---------------------------------------------------------------------------
# Candidate lower bound
# ---------------------------------------------------------------------------


class TestCandidateLowerBound:
    def test_simple_candidate_remains_novice(self) -> None:
        """A simple candidate (one attacker step) assesses as novice.

        Exact ATLAS technique mappings are present but technique tuples
        are never authoritative inputs — they do not escalate.
        """
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        assert assessment.rule_version == "1"
        assert assessment.candidate_lower_bound.required_level == "novice"
        assert assessment.candidate_lower_bound.reasons == ()
        assert assessment.final is None

    def test_multi_step_chain_raises_to_intermediate(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=3))
        phase = assessment.candidate_lower_bound
        assert phase.required_level == "intermediate"
        assert [r.rule_id for r in phase.reasons] == [
            "chain.multi_step_attacker_control"
        ]
        assert "3 attacker-controlled" in phase.reasons[0].detail
        assert {e.kind for e in phase.reasons[0].evidence} == {"chain_step"}

    def test_deep_chain_raises_to_advanced(self) -> None:
        """Sophisticated structured evidence raises the required level.

        The candidate carries no zone information at all: structure, not
        zone count, drives the assessment.
        """
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        phase = assessment.candidate_lower_bound
        assert phase.required_level == "advanced"
        assert [r.rule_id for r in phase.reasons] == [
            "chain.deep_attacker_control",
            "chain.multi_step_attacker_control",
        ]

    def test_state_changing_tool_fixture_raises(self) -> None:
        candidate = _candidate_with_requirements(
            {
                "schema_version": "1",
                "requirement_id": "req.fixture.tool",
                "kind": "state_changing_tool_fixture",
                "tool_slot_id": "tool",
            }
        )
        assessment = assess_candidate_complexity(candidate)
        phase = assessment.candidate_lower_bound
        assert phase.required_level == "intermediate"
        assert [r.rule_id for r in phase.reasons] == ["tool.state_changing_fixture"]
        assert phase.reasons[0].evidence[0].ref_id == "req.fixture.tool"

    def test_upstream_source_influence_raises(self) -> None:
        candidate = _candidate_with_requirements(
            {
                "schema_version": "1",
                "requirement_id": "req.upstream.source",
                "kind": "upstream_source_influence",
                "source_slot_id": "source",
                "source_identity_kind": "integration",
                "trust_boundary_slot_id": "boundary",
                "target_ingress_slot_id": "ingress",
            }
        )
        assessment = assess_candidate_complexity(candidate)
        assert assessment.candidate_lower_bound.required_level == "intermediate"
        assert [r.rule_id for r in assessment.candidate_lower_bound.reasons] == [
            "access.upstream_source_influence"
        ]

    def test_security_outcome_assertion_alone_does_not_escalate(self) -> None:
        """Every candidate derives a security-outcome assertion; it is not
        a complexity discriminator."""
        candidate = _candidate(n_attacker=1)
        assert any(
            r.kind == "security_outcome_assertion"
            for r in candidate.execution_requirements
        )
        assert (
            assess_candidate_complexity(candidate).candidate_lower_bound.required_level
            == "novice"
        )


# ---------------------------------------------------------------------------
# Final assessment
# ---------------------------------------------------------------------------


class TestFinalAssessment:
    def test_multi_zone_realization_stays_novice(self) -> None:
        """Simple multi-zone actions may remain novice: zone count alone
        is never a complexity signal."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        leaves = [
            _leaf("n1.1", "input", AiSystemAction()),
            _leaf("n1.2", "reasoning", AiSystemAction()),
            _leaf("n1.3", "memory", AiSystemAction()),
            _leaf("n1.4", "inter_agent", AiSystemAction()),
        ]
        final = assess_final_complexity(assessment, leaves, None)
        assert final.final is not None
        assert final.final.required_level == "novice"
        assert final.final.reasons == ()

    def test_external_precondition_action_raises_final(self) -> None:
        """A typed realized action can raise final complexity above the
        candidate lower bound."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        leaves = [
            _leaf("n1.1", None, ExternalPreconditionAction()),
            _leaf("n1.2", "input", AiSystemAction()),
        ]
        final = assess_final_complexity(assessment, leaves, None)
        assert final.candidate_lower_bound.required_level == "novice"
        assert final.final is not None
        assert final.final.required_level == "intermediate"
        assert [r.rule_id for r in final.final.reasons] == [
            "action.external_precondition"
        ]
        assert final.final.reasons[0].evidence[0].kind == "leaf_action"
        assert final.final.reasons[0].evidence[0].ref_id == "n1.1"

    def test_supply_chain_free_text_provenance_does_not_trigger(self) -> None:
        """The free-text ``access_provenance`` label on an external
        precondition action is never keyword-matched: only the closed
        ``ActorAccessProvenance.access_class`` triggers supply-chain."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        leaves = [
            _leaf(
                "n1.1",
                None,
                ExternalPreconditionAction(access_provenance="supply-chain-staging"),
            )
        ]
        final = assess_final_complexity(assessment, leaves, None)
        assert final.final is not None
        assert final.final.required_level == "intermediate"
        assert {r.rule_id for r in final.final.reasons} == {
            "action.external_precondition"
        }

    def test_tool_invocation_action_does_not_trigger_fixture_rule(self) -> None:
        """A realized tool invocation is not a state-changing fixture: the
        rule fires only from the typed execution requirement."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        leaves = [
            _leaf(
                "n1.1",
                "tool_execution",
                ToolInvocationAction(tool_id="tool:v1:" + "ef" * 16),
            )
        ]
        final = assess_final_complexity(assessment, leaves, None)
        assert final.final is not None
        assert final.final.required_level == "novice"

    @pytest.mark.parametrize(
        ("access_class", "ingress_mode", "expected", "rule_id"),
        [
            ("privileged", "direct", "intermediate", "access.privileged_prerequisite"),
            ("supply_chain", "indirect", "advanced", "access.supply_chain_targeting"),
            (
                "authenticated",
                "indirect",
                "intermediate",
                "access.indirect_influence_path",
            ),
        ],
    )
    def test_access_provenance_rules(
        self, access_class: str, ingress_mode: str, expected: str, rule_id: str
    ) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        access = _access(ingress_mode=ingress_mode, access_class=access_class)
        final = assess_final_complexity(assessment, [], access)
        assert final.final is not None
        assert final.final.required_level == expected
        assert rule_id in {r.rule_id for r in final.final.reasons}
        reason = next(r for r in final.final.reasons if r.rule_id == rule_id)
        assert reason.evidence[0].kind == "actor_access_provenance"

    def test_public_direct_access_stays_novice(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        final = assess_final_complexity(
            assessment, [], _access(ingress_mode="direct", access_class="public")
        )
        assert final.final is not None
        assert final.final.required_level == "novice"

    def test_final_inherits_candidate_reasons(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=3))
        final = assess_final_complexity(assessment, [], None)
        assert final.final is not None
        assert final.final.required_level == "intermediate"
        assert [r.rule_id for r in final.final.reasons] == [
            "chain.multi_step_attacker_control"
        ]


# ---------------------------------------------------------------------------
# Determinism, ordering, monotonicity
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_assessment_is_deterministic_and_versioned(self) -> None:
        first = assess_candidate_complexity(_candidate(n_attacker=5))
        second = assess_candidate_complexity(_candidate(n_attacker=5))
        assert first == second
        assert first.model_dump(mode="json") == second.model_dump(mode="json")
        assert first.rule_version == "1"

    def test_reason_ordering_descending_level_then_rule_id(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            _access(ingress_mode="indirect", access_class="supply_chain"),
        )
        assert final.final is not None
        rule_ids = [r.rule_id for r in final.final.reasons]
        # Descending required level, then ascending rule_id; unique rule_ids.
        assert rule_ids == [
            "access.supply_chain_targeting",
            "chain.deep_attacker_control",
            "access.indirect_influence_path",
            "action.external_precondition",
            "chain.multi_step_attacker_control",
        ]
        assert len(set(rule_ids)) == len(rule_ids)

    def test_phase_assessment_rejects_unsorted_or_duplicate_reasons(self) -> None:
        reason_a = ComplexityReason(
            rule_id="chain.multi_step_attacker_control",
            required_level="intermediate",
            detail="a",
            evidence=(ComplexityEvidenceReference(kind="chain_step", ref_id="s1"),),
        )
        reason_b = ComplexityReason(
            rule_id="chain.deep_attacker_control",
            required_level="advanced",
            detail="b",
            evidence=(ComplexityEvidenceReference(kind="chain_step", ref_id="s1"),),
        )
        with pytest.raises(ValidationError):
            ComplexityPhaseAssessment(
                phase="final", required_level="advanced", reasons=(reason_a, reason_b)
            )
        with pytest.raises(ValidationError):
            ComplexityPhaseAssessment(
                phase="final", required_level="advanced", reasons=(reason_b, reason_b)
            )

    def test_candidate_lower_bound_never_exceeds_final(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=3))
        data = assessment.model_dump(mode="json")
        data["final"] = {
            "phase": "final",
            "required_level": "novice",
            "reasons": [],
        }
        with pytest.raises(ValidationError, match="cannot be below"):
            AttackComplexityAssessment.model_validate(data)

    def test_final_slot_must_carry_final_phase(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        data = assessment.model_dump(mode="json")
        data["final"] = data["candidate_lower_bound"]
        with pytest.raises(ValidationError, match="final slot"):
            AttackComplexityAssessment.model_validate(data)


# ---------------------------------------------------------------------------
# Admission invariant (fail-closed typed routing)
# ---------------------------------------------------------------------------


class TestAdmissionInvariant:
    def test_candidate_lower_bound_blocks_below_floor_actor(self) -> None:
        """Call 0 actor generation cannot return below the known candidate
        lower bound: the contract fails closed with regeneration routing."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        decision = evaluate_capability_admission(
            "novice", assessment, phase="candidate_lower_bound"
        )
        assert not decision.admitted
        violation = decision.violation
        assert violation is not None
        assert violation.rule_id == "actor_capability_below_attack_complexity"
        assert violation.phase == "candidate_lower_bound"
        assert violation.rule_version == "1"
        assert violation.actor_capability_level == "novice"
        assert violation.required_level == "advanced"
        assert [r.rule_id for r in violation.triggering_reasons] == [
            "chain.deep_attacker_control"
        ]
        assert violation.routing.stage == "call0_actor_generation"
        assert violation.routing.action == "regenerate_actor_with_higher_capability"
        assert "advanced" in violation.routing.feedback

    def test_final_mismatch_from_typed_action_routes_to_realization_retry(
        self,
    ) -> None:
        """A typed leaf action introduced after Call 0 raises final
        complexity; the mismatch routes to attack-tree/realization retry
        (the earliest responsible bounded stage) and the actor is
        untouched — feedback never asks for a more capable actor."""
        actor = _actor(capability_level="novice")
        before = actor.model_dump(mode="json")
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            None,
        )
        decision = evaluate_capability_admission(
            actor.capability_level, final, phase="final"
        )
        assert not decision.admitted
        violation = decision.violation
        assert violation is not None
        assert violation.required_level == "intermediate"
        assert isinstance(violation.routing, RealizationRetryRouting)
        assert violation.routing.stage == "attack_tree_realization"
        assert violation.routing.action == "retry_realization_for_simpler_attack"
        assert "simpler" in violation.routing.feedback
        assert "never relabel" in violation.routing.feedback
        assert "more capable actor" not in violation.routing.feedback
        assert actor.model_dump(mode="json") == before

    def test_final_mismatch_from_access_provenance_routes_to_call0(self) -> None:
        """Access provenance is established at Call 0 actor generation
        (cmps.6), so a supply-chain-raised final mismatch routes back to
        bounded Call 0 regeneration — constructing a new actor, never
        relabelling the realized one."""
        actor = _actor(capability_level="novice")
        before = actor.model_dump(mode="json")
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", "input", AiSystemAction())],
            _access(ingress_mode="indirect", access_class="supply_chain"),
        )
        decision = evaluate_capability_admission(
            actor.capability_level, final, phase="final"
        )
        assert not decision.admitted
        violation = decision.violation
        assert violation is not None
        assert violation.required_level == "advanced"
        assert [r.rule_id for r in violation.triggering_reasons] == [
            "access.supply_chain_targeting"
        ]
        assert isinstance(violation.routing, Call0RegenerationRouting)
        assert violation.routing.stage == "call0_actor_generation"
        assert violation.routing.action == "regenerate_actor_with_higher_capability"
        assert "never relabel" in violation.routing.feedback
        assert actor.model_dump(mode="json") == before

    def test_multiple_top_level_reasons_pick_earliest_stage_deterministically(
        self,
    ) -> None:
        """When several top-level triggering reasons exist, routing picks
        the earliest responsible stage (Call 0 < realization < quarantine)
        and preserves every triggering reason."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            _access(ingress_mode="direct", access_class="privileged"),
        )
        assert final.final is not None
        assert final.final.required_level == "intermediate"
        top = {r.rule_id for r in final.final.reasons}
        assert top == {
            "action.external_precondition",
            "access.privileged_prerequisite",
        }
        decision = evaluate_capability_admission("novice", final, phase="final")
        assert not decision.admitted
        violation = decision.violation
        assert violation is not None
        # Both top-level reasons are preserved, deterministically ordered.
        assert [r.rule_id for r in violation.triggering_reasons] == [
            "access.privileged_prerequisite",
            "action.external_precondition",
        ]
        # Earliest stage wins: access provenance is known at Call 0, which
        # precedes attack-tree realization.
        assert isinstance(violation.routing, Call0RegenerationRouting)
        assert violation.routing.stage == "call0_actor_generation"

    def test_capable_actor_may_execute_simpler_attack(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        for level in ("novice", "intermediate", "advanced", "expert"):
            decision = evaluate_capability_admission(
                level, assessment, phase="candidate_lower_bound"
            )
            assert decision.admitted
            assert decision.violation is None

    def test_equal_level_is_admitted(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=3))
        decision = evaluate_capability_admission(
            "intermediate", assessment, phase="candidate_lower_bound"
        )
        assert decision.admitted

    def test_fail_closed_when_final_phase_unavailable(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        assert assessment.final is None
        decision = evaluate_capability_admission("expert", assessment, phase="final")
        assert not decision.admitted
        violation = decision.violation
        assert violation is not None
        assert violation.rule_id == "complexity_assessment_phase_unavailable"
        assert violation.required_level is None
        assert violation.triggering_reasons == ()
        # Quarantine is the fail-closed/exhaustion fallback owned by cmps.5.
        assert isinstance(violation.routing, QuarantineRouting)
        assert violation.routing.stage == "post_realization_validation"
        assert violation.routing.action == "quarantine_scenario"

    def test_actor_capability_unchanged_byte_for_byte(self) -> None:
        """Across complexity computation and mismatch handling the actor
        profile is identical, byte-for-byte."""
        actor = _actor(capability_level="novice")
        serialized_before = json.dumps(
            actor.model_dump(mode="json"), sort_keys=True
        ).encode("utf-8")
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            _access(ingress_mode="indirect", access_class="supply_chain"),
        )
        decision = evaluate_capability_admission(
            actor.capability_level, final, phase="final"
        )
        assert not decision.admitted
        serialized_after = json.dumps(
            actor.model_dump(mode="json"), sort_keys=True
        ).encode("utf-8")
        assert serialized_before == serialized_after


# ---------------------------------------------------------------------------
# Field-level capability immutability
# ---------------------------------------------------------------------------


class TestCapabilityFieldFrozen:
    """``ActorProfile.capability_level`` is frozen at construction: a
    post-Call-0 relabel is a ValidationError, not just a convention."""

    def test_construction_and_validation_still_work(self) -> None:
        actor = _actor(capability_level="novice")
        assert actor.capability_level == "novice"
        # Round-trip construction/validation is unchanged.
        restored = ActorProfile.model_validate(actor.model_dump(mode="json"))
        assert restored == actor

    def test_post_construction_assignment_fails(self) -> None:
        actor = _actor(capability_level="novice")
        with pytest.raises(ValidationError, match="frozen"):
            actor.capability_level = "intermediate"  # type: ignore[misc]
        assert actor.capability_level == "novice"

    def test_unrelated_actor_state_remains_mutable(self) -> None:
        """Only capability is frozen; Call-0 assembly may still attach
        access provenance and goal metadata to the profile."""
        actor = _actor(capability_level="novice")
        actor.beliefs = ["updated belief"]
        assert actor.beliefs == ["updated belief"]


# ---------------------------------------------------------------------------
# Closed v1 rule table enforcement in persisted models
# ---------------------------------------------------------------------------


def _reason(
    rule_id: str,
    required_level: str,
    evidence_kind: str,
    ref_id: str = "ref.1",
) -> ComplexityReason:
    return ComplexityReason(
        rule_id=rule_id,  # type: ignore[arg-type]
        required_level=required_level,  # type: ignore[arg-type]
        detail="adversarial fixture",
        evidence=(
            ComplexityEvidenceReference(
                kind=evidence_kind,  # type: ignore[arg-type]
                ref_id=ref_id,
            ),
        ),
    )


class TestClosedRuleTable:
    """Persisted reasons are validated against the one authoritative
    ``COMPLEXITY_RULE_TABLE``: impossible claims are unrepresentable."""

    def test_rule_table_is_closed_and_complete(self) -> None:
        assert set(COMPLEXITY_RULE_TABLE) == {
            "chain.multi_step_attacker_control",
            "chain.deep_attacker_control",
            "access.upstream_source_influence",
            "tool.state_changing_fixture",
            "action.external_precondition",
            "access.indirect_influence_path",
            "access.privileged_prerequisite",
            "access.supply_chain_targeting",
        }
        for spec in COMPLEXITY_RULE_TABLE.values():
            assert spec.rule_id is not None
            assert spec.responsible_stage in (
                "call0_actor_generation",
                "attack_tree_realization",
            )

    def test_wrong_required_level_rejected(self) -> None:
        with pytest.raises(ValidationError, match="requires level"):
            _reason("chain.deep_attacker_control", "novice", "chain_step")

    def test_wrong_evidence_kind_rejected(self) -> None:
        with pytest.raises(ValidationError, match="evidence kinds"):
            _reason("chain.deep_attacker_control", "advanced", "leaf_action")

    def test_wrong_level_and_kind_rejected_after_json_round_trip(self) -> None:
        good = _reason(
            "access.supply_chain_targeting",
            "advanced",
            "actor_access_provenance",
            "ep:v1:" + "ab" * 16,
        )
        data = good.model_dump(mode="json")
        data["required_level"] = "expert"
        with pytest.raises(ValidationError):
            ComplexityReason.model_validate(data)
        data2 = good.model_dump(mode="json")
        data2["evidence"][0]["kind"] = "execution_requirement"
        with pytest.raises(ValidationError):
            ComplexityReason.model_validate(data2)

    def test_final_only_rule_rejected_in_candidate_phase(self) -> None:
        with pytest.raises(ValidationError, match="final phase"):
            ComplexityPhaseAssessment(
                phase="candidate_lower_bound",
                required_level="intermediate",
                reasons=(
                    _reason(
                        "action.external_precondition",
                        "intermediate",
                        "leaf_action",
                    ),
                ),
            )

    def test_final_only_rule_rejected_in_candidate_phase_after_round_trip(
        self,
    ) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            None,
        )
        assert final.final is not None
        # Forge a candidate phase carrying a final-only reason via JSON.
        data = final.candidate_lower_bound.model_dump(mode="json")
        data["reasons"] = [
            r.model_dump(mode="json")
            for r in final.final.reasons
            if r.rule_id == "action.external_precondition"
        ]
        data["required_level"] = "intermediate"
        with pytest.raises(ValidationError, match="final phase"):
            ComplexityPhaseAssessment.model_validate(data)

    def test_candidate_reasons_inherited_unchanged_into_final(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        final = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            None,
        )
        assert final.final is not None
        candidate_ids = {r.rule_id for r in assessment.candidate_lower_bound.reasons}
        final_ids = {r.rule_id for r in final.final.reasons}
        assert candidate_ids < final_ids
        for reason in assessment.candidate_lower_bound.reasons:
            assert reason in final.final.reasons

    def test_adversarial_assessment_round_trip(self) -> None:
        """A tampered persisted assessment fails validation on reload."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        data = assessment.model_dump(mode="json")
        # Tamper: deep-chain reason downgraded to novice.
        data["candidate_lower_bound"]["required_level"] = "novice"
        for reason in data["candidate_lower_bound"]["reasons"]:
            reason["required_level"] = "novice"
        with pytest.raises(ValidationError):
            AttackComplexityAssessment.model_validate(data)


# ---------------------------------------------------------------------------
# Discriminated routing contract
# ---------------------------------------------------------------------------


class TestRoutingDiscriminatedContract:
    """Routing is a discriminated union on ``stage``; invalid stage/action
    pairs are unrepresentable in both directions."""

    def _violation_payload(self, routing: dict[str, Any]) -> dict[str, Any]:
        reason = _reason("action.external_precondition", "intermediate", "leaf_action")
        violation = CapabilityAdmissionViolation(
            rule_id="actor_capability_below_attack_complexity",
            phase="final",
            rule_version="1",
            actor_capability_level="novice",
            required_level="intermediate",
            triggering_reasons=(reason,),
            routing=RealizationRetryRouting(feedback="fixture"),
        )
        data = violation.model_dump(mode="json")
        data["routing"] = routing
        return data

    def test_each_variant_round_trips_with_a_matching_reason(self) -> None:
        call0_reason = _reason(
            "access.supply_chain_targeting",
            "advanced",
            "actor_access_provenance",
            "ep:v1:" + "ab" * 16,
        )
        realization_reason = _reason(
            "action.external_precondition", "intermediate", "leaf_action"
        )
        combos = (
            ((call0_reason,), "advanced", Call0RegenerationRouting(feedback="a")),
            (
                (realization_reason,),
                "intermediate",
                RealizationRetryRouting(feedback="b"),
            ),
            (
                (call0_reason, realization_reason),
                "advanced",
                Call0RegenerationRouting(feedback="c"),
            ),
        )
        for reasons, top_level, routing in combos:
            violation = CapabilityAdmissionViolation(
                rule_id="actor_capability_below_attack_complexity",
                phase="final",
                rule_version="1",
                actor_capability_level="novice",
                required_level=top_level,  # type: ignore[arg-type]
                triggering_reasons=reasons,
                routing=routing,
            )
            restored = CapabilityAdmissionViolation.model_validate(
                violation.model_dump(mode="json")
            )
            assert restored.routing == routing
            assert type(restored.routing) is type(routing)

    def test_mismatched_reason_routing_variants_rejected(self) -> None:
        """Routing stage must equal the deterministic earliest responsible
        stage implied by the triggering reasons — the typed contract is
        authoritative, not only the helper producer."""
        realization_reason = _reason(
            "action.external_precondition", "intermediate", "leaf_action"
        )
        call0_reason = _reason(
            "access.supply_chain_targeting",
            "advanced",
            "actor_access_provenance",
            "ep:v1:" + "ab" * 16,
        )

        def _violation(reasons, level, routing) -> None:
            CapabilityAdmissionViolation(
                rule_id="actor_capability_below_attack_complexity",
                phase="final",
                rule_version="1",
                actor_capability_level="novice",
                required_level=level,
                triggering_reasons=reasons,
                routing=routing,
            )

        # Realization-owned reason cannot route to Call 0 or quarantine.
        with pytest.raises(ValidationError, match="earliest responsible stage"):
            _violation(
                (realization_reason,),
                "intermediate",
                Call0RegenerationRouting(feedback="x"),
            )
        with pytest.raises(ValidationError, match="earliest responsible stage"):
            _violation(
                (realization_reason,), "intermediate", QuarantineRouting(feedback="x")
            )
        # Call-0-owned reason cannot route to realization retry.
        with pytest.raises(ValidationError, match="earliest responsible stage"):
            _violation(
                (call0_reason,), "advanced", RealizationRetryRouting(feedback="x")
            )
        # Mixed top-level reasons: earliest stage (Call 0) is required.
        with pytest.raises(ValidationError, match="earliest responsible stage"):
            _violation(
                (call0_reason, realization_reason),
                "advanced",
                RealizationRetryRouting(feedback="x"),
            )

    def test_required_level_must_equal_top_of_triggering_reasons(self) -> None:
        realization_reason = _reason(
            "action.external_precondition", "intermediate", "leaf_action"
        )
        with pytest.raises(ValidationError, match="top level"):
            CapabilityAdmissionViolation(
                rule_id="actor_capability_below_attack_complexity",
                phase="final",
                rule_version="1",
                actor_capability_level="novice",
                required_level="advanced",
                triggering_reasons=(realization_reason,),
                routing=RealizationRetryRouting(feedback="x"),
            )

    def test_phase_unavailable_must_carry_quarantine_routing(self) -> None:
        for bad_routing in (
            Call0RegenerationRouting(feedback="x"),
            RealizationRetryRouting(feedback="x"),
        ):
            with pytest.raises(ValidationError, match="quarantine routing"):
                CapabilityAdmissionViolation(
                    rule_id="complexity_assessment_phase_unavailable",
                    phase="final",
                    rule_version="1",
                    actor_capability_level="expert",
                    required_level=None,
                    triggering_reasons=(),
                    routing=bad_routing,
                )

    @pytest.mark.parametrize(
        ("stage", "action"),
        [
            ("call0_actor_generation", "quarantine_scenario"),
            ("call0_actor_generation", "retry_realization_for_simpler_attack"),
            ("attack_tree_realization", "regenerate_actor_with_higher_capability"),
            ("attack_tree_realization", "quarantine_scenario"),
            ("post_realization_validation", "regenerate_actor_with_higher_capability"),
            ("post_realization_validation", "retry_realization_for_simpler_attack"),
        ],
    )
    def test_mismatched_stage_action_pairs_unrepresentable(
        self, stage: str, action: str
    ) -> None:
        payload = self._violation_payload(
            {"stage": stage, "action": action, "feedback": "forged"}
        )
        with pytest.raises(ValidationError):
            CapabilityAdmissionViolation.model_validate(payload)

    def test_wrong_action_on_variant_class_rejected(self) -> None:
        with pytest.raises(ValidationError):
            QuarantineRouting(
                action="regenerate_actor_with_higher_capability",  # type: ignore[arg-type]
                feedback="forged",
            )
        with pytest.raises(ValidationError):
            Call0RegenerationRouting(
                stage="attack_tree_realization",  # type: ignore[arg-type]
                feedback="forged",
            )

    def test_union_alias_accepts_each_variant(self) -> None:
        for routing in (
            Call0RegenerationRouting(feedback="a"),
            RealizationRetryRouting(feedback="b"),
            QuarantineRouting(feedback="c"),
        ):
            parsed = TypeAdapter(ComplexityAdmissionRouting).validate_python(
                routing.model_dump(mode="json")
            )
            assert type(parsed) is type(routing)


# ---------------------------------------------------------------------------
# Evidence determinism (canonical ordering, no caller-order leakage)
# ---------------------------------------------------------------------------

_FIXTURE_REQ = {
    "schema_version": "1",
    "requirement_id": "req.fixture.tool",
    "kind": "state_changing_tool_fixture",
    "tool_slot_id": "tool",
}
_UPSTREAM_REQ = {
    "schema_version": "1",
    "requirement_id": "req.upstream.source",
    "kind": "upstream_source_influence",
    "source_slot_id": "source",
    "source_identity_kind": "integration",
    "trust_boundary_slot_id": "boundary",
    "target_ingress_slot_id": "ingress",
}


def _canonical_json(model: Any) -> bytes:
    return json.dumps(model.model_dump(mode="json"), sort_keys=True).encode("utf-8")


class TestEvidenceDeterminism:
    """The same typed evidence set must serialize byte-identically
    regardless of producer iteration order; duplicates are invalid."""

    def test_reversed_realized_leaves_byte_identical(self) -> None:
        leaf_a = _leaf("n1.1", None, ExternalPreconditionAction())
        leaf_b = _leaf("n1.2", None, ExternalPreconditionAction())
        forward = assess_final_complexity(
            assess_candidate_complexity(_candidate(n_attacker=1)),
            [leaf_a, leaf_b],
            None,
        )
        reversed_ = assess_final_complexity(
            assess_candidate_complexity(_candidate(n_attacker=1)),
            [leaf_b, leaf_a],
            None,
        )
        assert forward == reversed_
        assert _canonical_json(forward) == _canonical_json(reversed_)

    def test_reversed_requirements_byte_identical(self) -> None:
        forward = assess_candidate_complexity(
            _candidate_with_requirements(_FIXTURE_REQ, _UPSTREAM_REQ)
        )
        reversed_ = assess_candidate_complexity(
            _candidate_with_requirements(_UPSTREAM_REQ, _FIXTURE_REQ)
        )
        assert forward == reversed_
        assert _canonical_json(forward) == _canonical_json(reversed_)

    def test_unsorted_evidence_normalized_at_construction(self) -> None:
        reason = ComplexityReason(
            rule_id="action.external_precondition",
            required_level="intermediate",
            detail="fixture",
            evidence=(
                ComplexityEvidenceReference(kind="leaf_action", ref_id="n1.2"),
                ComplexityEvidenceReference(kind="leaf_action", ref_id="n1.1"),
            ),
        )
        assert [ref.ref_id for ref in reason.evidence] == ["n1.1", "n1.2"]

    def test_duplicate_evidence_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unique by"):
            ComplexityReason(
                rule_id="action.external_precondition",
                required_level="intermediate",
                detail="fixture",
                evidence=(
                    ComplexityEvidenceReference(kind="leaf_action", ref_id="n1.1"),
                    ComplexityEvidenceReference(kind="leaf_action", ref_id="n1.1"),
                ),
            )

    def test_tampered_evidence_reload_normalized_or_invalid(self) -> None:
        """Reordered persisted evidence reloads to the identical canonical
        model; duplicated persisted evidence is invalid on reload."""
        final = assess_final_complexity(
            assess_candidate_complexity(_candidate(n_attacker=1)),
            [
                _leaf("n1.1", None, ExternalPreconditionAction()),
                _leaf("n1.2", None, ExternalPreconditionAction()),
            ],
            None,
        )
        data = final.model_dump(mode="json")
        reasons = data["final"]["reasons"]
        (ext_reason,) = [
            r for r in reasons if r["rule_id"] == "action.external_precondition"
        ]
        ext_reason["evidence"] = list(reversed(ext_reason["evidence"]))
        reloaded = AttackComplexityAssessment.model_validate(data)
        assert reloaded == final
        assert _canonical_json(reloaded) == _canonical_json(final)
        # Duplicate persisted evidence is rejected.
        data2 = final.model_dump(mode="json")
        reasons2 = data2["final"]["reasons"]
        (ext2,) = [
            r for r in reasons2 if r["rule_id"] == "action.external_precondition"
        ]
        ext2["evidence"].append(dict(ext2["evidence"][0]))
        with pytest.raises(ValidationError, match="unique by"):
            AttackComplexityAssessment.model_validate(data2)


# ---------------------------------------------------------------------------
# Closed rule table runtime immutability
# ---------------------------------------------------------------------------


class TestRuleTableImmutable:
    def test_mutation_rejected(self) -> None:
        with pytest.raises(TypeError):
            COMPLEXITY_RULE_TABLE["chain.new_rule"] = None  # type: ignore[index]
        with pytest.raises(TypeError):
            del COMPLEXITY_RULE_TABLE["chain.multi_step_attacker_control"]  # type: ignore[attr-defined]
        with pytest.raises(TypeError):
            COMPLEXITY_RULE_TABLE["chain.deep_attacker_control"] = (  # type: ignore[index]
                COMPLEXITY_RULE_TABLE["chain.deep_attacker_control"]
            )

    def test_specs_themselves_frozen(self) -> None:
        spec = COMPLEXITY_RULE_TABLE["chain.deep_attacker_control"]
        with pytest.raises(ValidationError):
            spec.required_level = "novice"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Removed novice multi-zone guard (post-Call-0 immutability)
# ---------------------------------------------------------------------------


def _make_seed() -> ScenarioSeed:
    return ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Misaligned Behaviors",
        attack_pattern_name="Misaligned pattern",
        attack_pattern_description="desc",
        risk_card_ref=RiskCardRef(
            risk_id="R-01",
            risk_name="Test risk",
            risk_description="Description for R-01",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM09"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0054"],
    )


def _llm_result(content: Any) -> LLMResult:
    return LLMResult(
        content=content,
        system_prompt="sys",
        user_prompt="usr",
        prompt_tokens=10,
        completion_tokens=10,
        duration_ms=100,
    )


def _three_zone_narrative() -> Any:
    from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep

    return NarrativeLayer(
        title="Multi-zone novice scenario",
        summary="A novice actor path that happens to span three zones.",
        entry_point="user prompts (input)",
        zone_sequence=["input", "reasoning", "memory"],
        steps=[
            NarrativeStep(
                step_number=1, zone="input", action="Craft prompt", effect="Enters"
            ),
            NarrativeStep(
                step_number=2, zone="reasoning", action="Trick", effect="Reasons"
            ),
            NarrativeStep(
                step_number=3, zone="memory", action="Read", effect="Recalls"
            ),
        ],
    )


def _small_tree() -> AttackTree:
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Manipulate the agent output.",
        root=AttackTreeNode(
            id="n1",
            label="root",
            gate=GateType.AND,
            children=[
                _leaf("n1.1", "input", AiSystemAction()),
                _leaf("n1.2", "reasoning", AiSystemAction()),
            ],
        ),
    )


class TestNoviceGuardRemoved:
    """The legacy novice multi-zone guard relabelled actor capability
    post-Call-0 when the narrative spanned 3+ zones.  It is removed:
    zone count alone is never a complexity signal."""

    @patch("scenario_forge.pipeline.generate._warn_dominant_threat_id_crossref")
    @patch("scenario_forge.pipeline.generate._call_behavior_spec")
    @patch("scenario_forge.pipeline.generate._call_attack_tree")
    @patch("scenario_forge.pipeline.generate._call_narrative")
    @patch("scenario_forge.pipeline.generate._validate_actor_type")
    @patch("scenario_forge.pipeline.generate._call_actor_profile")
    def test_novice_actor_survives_multi_zone_narrative(
        self,
        mock_call0: MagicMock,
        mock_validate: MagicMock,
        mock_call1: MagicMock,
        mock_call2: MagicMock,
        mock_call3: MagicMock,
        _mock_crossref: MagicMock,
    ) -> None:
        from scenario_forge.manifest import generate_sortable_run_id

        actor = _actor(capability_level="novice")
        mock_call0.return_value = (actor, _llm_result({}), None)
        mock_validate.side_effect = lambda profile: profile
        mock_call1.return_value = (_three_zone_narrative(), _llm_result({}))
        mock_call2.return_value = (_small_tree(), _llm_result({}))
        mock_call3.return_value = ("Feature: Test", _llm_result({}))

        client = MagicMock()
        client.model = "test-model"
        envelope, _ = generate_scenario(
            seed=_make_seed(),
            profile=CapabilityProfile(
                zones_active=["input", "reasoning", "memory"],
                entry_points=["user prompts (input)"],
                kc_subcodes=["KC1.1"],
                confidence=ConfidenceLevel.high,
            ),
            client=client,
            use_case="Test system",
            pinned_entry_point_id="ep:v1:" + "cd" * 16,
            run_id=generate_sortable_run_id(),
            candidate_id="cand:v1:" + "ab" * 16,
        )
        assert envelope.actor_profile is not None
        assert envelope.actor_profile.capability_level == "novice"
        # Multi-zone realization is preserved as-is; no relabel occurred.
        assert len(set(envelope.narrative.zone_sequence)) == 3

    def test_no_post_call0_capability_assignment_survives(self) -> None:
        """Prove no post-Call-0 mutation/relabel path remains in src/."""
        import re
        from pathlib import Path

        src = Path(__file__).resolve().parents[1] / "src"
        offenders: list[str] = []
        for path in src.rglob("*.py"):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if re.search(r"\.capability_level\s*=[^=]", line):
                    offenders.append(f"{path}:{lineno}: {line.strip()}")
        assert offenders == [], f"post-Call-0 capability assignments: {offenders}"


# ---------------------------------------------------------------------------
# Persistence and reporting surfaces
# ---------------------------------------------------------------------------


def _envelope_with_assessment(
    assessment: AttackComplexityAssessment,
) -> ScenarioEnvelope:
    from datetime import UTC, datetime

    from scenario_forge.models.scenario import (
        ArchitectureMatch,
        AttackComplexity,
        CallMetadata,
        CallName,
        CapabilityProfileRef,
        FacetingMetadata,
        GenerationMetadata,
        LikelihoodLevel,
        NarrativeLayer,
        NarrativeStep,
        Priority,
        PrioritySignals,
        SeverityLevel,
        StructuralExposureSignal,
        TaxonomyChain,
        TechniqueMaturity,
    )

    return ScenarioEnvelope(
        scenario_id="scenario:v2:" + "a1" * 32,
        candidate_id="cand:v1:" + "b2" * 16,
        initial_entry_point_id="ep:v1:" + "cd" * 16,
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        narrative=NarrativeLayer(
            title="Test",
            summary="Summary",
            entry_point="user prompts",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1, zone="input", action="Act", effect="Effect"
                )
            ],
        ),
        attack_tree=_small_tree(),
        behavior_spec="Feature: Test",
        actor_profile=_actor(capability_level="novice"),
        attack_complexity_assessment=assessment,
        faceting=FacetingMetadata(
            risk_card=RiskCardRef(
                risk_id="r1",
                risk_name="Risk",
                risk_description="Desc",
                taxonomy="ibm-risk-atlas",
                confidence=0.9,
                grounding_confidence="high",
            ),
            taxonomy_chain=TaxonomyChain(
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=["T1"],
                scenario_seed="AP-T1-01",
            ),
            capability_profile=CapabilityProfileRef(
                zones_traversed=["input"],
                architecture_match=ArchitectureMatch.explicit,
                entry_point="user prompts",
            ),
            maestro_layers=[1],
        ),
        priority=Priority(
            composite=0.5,
            signals=PrioritySignals(
                technique_maturity=TechniqueMaturity.feasible,
                risk_impact=SeverityLevel.medium,
                risk_likelihood=LikelihoodLevel.medium,
                attack_complexity=AttackComplexity.medium,
                architecture_match=ArchitectureMatch.explicit,
                structural_exposure=StructuralExposureSignal.none,
            ),
        ),
        generation=GenerationMetadata(
            model="test-model",
            call_metadata=[
                CallMetadata(
                    call=CallName.narrative,
                    prompt_tokens=100,
                    completion_tokens=200,
                    duration_ms=1000,
                )
            ],
        ),
    )


class TestPersistenceAndReporting:
    def test_envelope_persists_assessment_distinctly(self) -> None:
        """The envelope distinguishes actor capability, candidate lower
        bound, final required level, rule version, and reasons."""
        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        assessment = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            None,
        )
        envelope = _envelope_with_assessment(assessment)
        data = envelope.model_dump(mode="json", exclude_none=True)
        persisted = data["attack_complexity_assessment"]
        assert persisted["rule_version"] == "1"
        assert persisted["candidate_lower_bound"]["required_level"] == "advanced"
        assert persisted["final"]["required_level"] == "advanced"
        assert data["actor_profile"]["capability_level"] == "novice"
        # Round-trip preserves the assessment exactly.
        restored = ScenarioEnvelope.model_validate(data)
        assert restored.attack_complexity_assessment == assessment

    def test_envelope_without_assessment_stays_absent(self) -> None:
        assessment = assess_candidate_complexity(_candidate(n_attacker=1))
        envelope = _envelope_with_assessment(assessment)
        object.__setattr__(envelope, "attack_complexity_assessment", None)
        data = envelope.model_dump(mode="json", exclude_none=True)
        assert "attack_complexity_assessment" not in data

    def test_persisted_assessment_validates_against_hand_schema(self) -> None:
        from pathlib import Path

        import jsonschema

        assessment = assess_candidate_complexity(_candidate(n_attacker=3))
        assessment = assess_final_complexity(assessment, [], None)
        envelope = _envelope_with_assessment(assessment)
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "src"
                / "scenario_forge"
                / "data"
                / "schemas"
                / "scenario-envelope.schema.json"
            ).read_text(encoding="utf-8")
        )
        jsonschema.validate(envelope.model_dump(mode="json"), schema)

    def test_report_block_distinguishes_capability_and_complexity(self) -> None:
        from scenario_forge.report.template import _build_complexity_assessment_block

        assessment = assess_candidate_complexity(_candidate(n_attacker=5))
        assessment = assess_final_complexity(
            assessment,
            [_leaf("n1.1", None, ExternalPreconditionAction())],
            None,
        )
        envelope = _envelope_with_assessment(assessment)
        html = _build_complexity_assessment_block(
            envelope.model_dump(mode="json", exclude_none=True)
        )
        assert "ATTACK COMPLEXITY (RULE V1)" in html
        assert "Candidate lower bound" in html
        assert "Final required level" in html
        assert "Advanced" in html
        assert "chain.deep_attacker_control" in html
        # Evidence references render as kind:ref_id.
        assert "chain_step:step.1" in html
        assert "leaf_action:n1.1" in html
        # Absent assessment renders nothing (legacy outputs unchanged).
        assert _build_complexity_assessment_block({"scenario_id": "x"}) == ""
