"""Tests for compute_compatible_actor_types (ok0p bead).

Covers:
- R1: Adversarial-only threat -> remove negligent-insider
- R2: Indirect EP -> remove negligent-insider (T2+RAG exception)
- R3: System EP -> restrict to {malicious-insider, supply-chain-actor, nation-state}
- R4: Technique requires direct access -> remove negligent-insider, supply-chain-actor
- R5: Supply chain target layer -> restrict to {supply-chain-actor, nation-state,
      malicious-insider, automated-agent}
- Rule stacking
- Diversity tracker interaction
- Prompt template integration
"""

from __future__ import annotations

import pytest

from scenario_forge.pipeline.generate import (
    ALL_ACTOR_TYPES,
    _ADVERSARIAL_ONLY_THREATS,
    compute_compatible_actor_types,
)
from scenario_forge.prompts import render_prompt


# ---------------------------------------------------------------------------
# R1: Adversarial-only threat -> remove negligent-insider
# ---------------------------------------------------------------------------


class TestR1AdversarialOnlyThreat:
    """R1: When threat_id is adversarial-only, negligent-insider is removed."""

    @pytest.mark.parametrize("threat_id", list(_ADVERSARIAL_ONLY_THREATS))
    def test_all_adversarial_threats_exclude_negligent(self, threat_id: str):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", threat_id
        )
        assert "negligent-insider" not in result

    def test_non_adversarial_threat_keeps_negligent(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2"
        )
        assert "negligent-insider" in result

    def test_none_threat_keeps_negligent(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", None
        )
        assert "negligent-insider" in result


# ---------------------------------------------------------------------------
# R2: Indirect EP -> remove negligent-insider (T2+RAG exception)
# ---------------------------------------------------------------------------


class TestR2IndirectEP:
    """R2: Indirect EP removes negligent-insider, except T2+RAG/knowledge."""

    def test_indirect_ep_removes_negligent(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T2"
        )
        assert "negligent-insider" not in result

    def test_t2_rag_exception_keeps_negligent(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T2",
            entry_point_name="RAG knowledge-grounding system",
        )
        assert "negligent-insider" in result

    def test_t2_knowledge_exception_keeps_negligent(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T2",
            entry_point_name="Knowledge base ingestion",
        )
        assert "negligent-insider" in result

    def test_t2_rag_case_insensitive(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T2",
            entry_point_name="rag Knowledge System",
        )
        assert "negligent-insider" in result

    def test_non_t2_indirect_no_exception(self):
        # T7 is adversarial-only, so R1 would also fire, but let's test with
        # a non-adversarial non-T2 threat
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T1",
            entry_point_name="RAG knowledge-grounding system",
        )
        # T1 is not adversarial-only, but R2 fires for indirect EP without T2
        assert "negligent-insider" not in result

    def test_direct_ep_no_r2_effect(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2"
        )
        assert "negligent-insider" in result


# ---------------------------------------------------------------------------
# R3: System EP -> restrict to small set
# ---------------------------------------------------------------------------


class TestR3SystemEP:
    """R3: System EP restricts to {malicious-insider, supply-chain-actor, nation-state}."""

    def test_system_ep_restricts(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "system", "T2"
        )
        assert result == {"malicious-insider", "supply-chain-actor", "nation-state"}

    def test_system_ep_excludes_external_actors(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "system", "T2"
        )
        for excluded in [
            "adversarial-user", "cybercriminal", "hacktivist",
            "competitor", "automated-agent", "negligent-insider",
        ]:
            assert excluded not in result

    def test_direct_ep_no_r3(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2"
        )
        # Should have the full set minus any other rule effects
        assert len(result) == len(ALL_ACTOR_TYPES)


# ---------------------------------------------------------------------------
# R4: Technique requires direct access
# ---------------------------------------------------------------------------


class TestR4DirectAccessTechnique:
    """R4: Techniques requiring direct access remove negligent-insider and
    supply-chain-actor."""

    def test_direct_access_technique_removes_negligent_and_supply_chain(self):
        # AML.T0051.000 has requires_direct_access = True
        result = compute_compatible_actor_types(
            ["AML.T0051.000"], "direct", "T2"
        )
        assert "negligent-insider" not in result
        assert "supply-chain-actor" not in result

    def test_direct_access_technique_t0054(self):
        # AML.T0054 also has requires_direct_access = True
        result = compute_compatible_actor_types(
            ["AML.T0054"], "direct", "T2"
        )
        assert "negligent-insider" not in result
        assert "supply-chain-actor" not in result

    def test_non_direct_access_keeps_both(self):
        # AML.T0053 has requires_direct_access = False
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2"
        )
        assert "negligent-insider" in result
        assert "supply-chain-actor" in result

    def test_mixed_techniques_direct_access_wins(self):
        # If any technique requires direct access, R4 fires
        result = compute_compatible_actor_types(
            ["AML.T0053", "AML.T0054"], "direct", "T2"
        )
        assert "negligent-insider" not in result
        assert "supply-chain-actor" not in result


# ---------------------------------------------------------------------------
# R5: Supply chain target layer
# ---------------------------------------------------------------------------


class TestR5SupplyChainTargetLayer:
    """R5: Supply chain target layer restricts to specific set."""

    def test_supply_chain_technique_restricts(self):
        # AML.T0010 has target_layer = "supply_chain"
        result = compute_compatible_actor_types(
            ["AML.T0010"], "direct", "T2"
        )
        expected = {"supply-chain-actor", "nation-state", "malicious-insider", "automated-agent"}
        assert result == expected

    def test_supply_chain_technique_t0048(self):
        # AML.T0048 also has target_layer = "supply_chain"
        result = compute_compatible_actor_types(
            ["AML.T0048"], "direct", "T2"
        )
        expected = {"supply-chain-actor", "nation-state", "malicious-insider", "automated-agent"}
        assert result == expected

    def test_non_supply_chain_no_restriction(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2"
        )
        assert len(result) == len(ALL_ACTOR_TYPES)

    def test_automated_agent_included_in_supply_chain(self):
        """Automated agents can participate in supply chain attacks."""
        result = compute_compatible_actor_types(
            ["AML.T0010"], "direct", "T2"
        )
        assert "automated-agent" in result


# ---------------------------------------------------------------------------
# Rule stacking
# ---------------------------------------------------------------------------


class TestRuleStacking:
    """Multiple rules narrowing the compatible set together."""

    def test_r1_and_r3_stacking(self):
        # T7 (adversarial-only) + system EP
        result = compute_compatible_actor_types(
            ["AML.T0053"], "system", "T7"
        )
        # R1 removes negligent-insider, R3 restricts to {malicious, supply-chain, nation-state}
        # negligent-insider is already not in R3's set, so effectively same as R3
        assert result == {"malicious-insider", "supply-chain-actor", "nation-state"}

    def test_r4_and_r5_stacking(self):
        # A technique that both requires direct access AND targets supply chain
        # (AML.T0010 is supply chain but not direct access)
        # Let's use a combo: AML.T0054 (direct access) + AML.T0010 (supply chain)
        result = compute_compatible_actor_types(
            ["AML.T0054", "AML.T0010"], "direct", "T2"
        )
        # R4 removes negligent-insider and supply-chain-actor
        # R5 restricts to {supply-chain-actor, nation-state, malicious-insider, automated-agent}
        # Intersection: nation-state, malicious-insider, automated-agent
        # (supply-chain-actor removed by R4)
        assert result == {"nation-state", "malicious-insider", "automated-agent"}

    def test_r1_r2_double_removal_idempotent(self):
        # T7 (adversarial-only) + indirect EP both try to remove negligent-insider
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T7"
        )
        assert "negligent-insider" not in result
        # Other types should still be present
        assert "adversarial-user" in result

    def test_all_rules_combined(self):
        # R1 (T7) + R3 (system) + R5 (supply chain technique)
        result = compute_compatible_actor_types(
            ["AML.T0010"], "system", "T7"
        )
        # R1: remove negligent-insider
        # R3: restrict to {malicious, supply-chain, nation-state}
        # R5: restrict to {supply-chain, nation-state, malicious, automated-agent}
        # Intersection of R3 and R5: {malicious-insider, supply-chain-actor, nation-state}
        assert result == {"malicious-insider", "supply-chain-actor", "nation-state"}


# ---------------------------------------------------------------------------
# ALL_ACTOR_TYPES constant integrity
# ---------------------------------------------------------------------------


class TestAllActorTypes:
    def test_nine_actor_types(self):
        assert len(ALL_ACTOR_TYPES) == 9

    def test_contains_expected_types(self):
        expected = {
            "adversarial-user", "malicious-insider", "negligent-insider",
            "supply-chain-actor", "cybercriminal", "nation-state",
            "hacktivist", "competitor", "automated-agent",
        }
        assert ALL_ACTOR_TYPES == expected


# ---------------------------------------------------------------------------
# Prompt template integration
# ---------------------------------------------------------------------------


class TestActorTypePromptConstraint:
    """The call0_system.j2 template includes the constraint when compatible
    set is narrower than full."""

    def test_constraint_appears_when_narrowed(self):
        prompt = render_prompt(
            "call0_system.j2",
            compatible_actor_types=["adversarial-user", "cybercriminal"],
            minimum_capability_level="novice",
        )
        assert "Actor Type Constraint (MANDATORY)" in prompt
        assert "adversarial-user" in prompt
        assert "cybercriminal" in prompt

    def test_constraint_lists_all_compatible(self):
        types = sorted(["nation-state", "malicious-insider", "supply-chain-actor"])
        prompt = render_prompt(
            "call0_system.j2",
            compatible_actor_types=types,
            minimum_capability_level="novice",
        )
        for t in types:
            assert t in prompt

    def test_no_constraint_without_kwarg(self):
        prompt = render_prompt("call0_system.j2")
        assert "Actor Type Constraint (MANDATORY)" not in prompt

    def test_empty_list_no_constraint(self):
        prompt = render_prompt(
            "call0_system.j2",
            compatible_actor_types=[],
            minimum_capability_level="novice",
        )
        assert "Actor Type Constraint (MANDATORY)" not in prompt


# ---------------------------------------------------------------------------
# Edge cases and adversarial tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for compute_compatible_actor_types."""

    def test_none_techniques(self):
        result = compute_compatible_actor_types(None, "direct", "T2")
        assert result == ALL_ACTOR_TYPES

    def test_empty_techniques(self):
        result = compute_compatible_actor_types([], "direct", "T2")
        assert result == ALL_ACTOR_TYPES

    def test_none_ep_controllability(self):
        result = compute_compatible_actor_types(["AML.T0053"], None, "T2")
        assert result == ALL_ACTOR_TYPES

    def test_none_threat_id(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", None)
        assert result == ALL_ACTOR_TYPES

    def test_unknown_technique_ignored(self):
        result = compute_compatible_actor_types(
            ["UNKNOWN.T9999"], "direct", "T2"
        )
        assert result == ALL_ACTOR_TYPES

    def test_tuple_technique_ids_accepted(self):
        result = compute_compatible_actor_types(
            ("AML.T0051.000",), "direct", "T2"
        )
        assert "negligent-insider" not in result

    def test_result_is_set(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
        assert isinstance(result, set)

    def test_never_empty_with_system_ep(self):
        """R3 always leaves at least 3 types."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "system", "T2"
        )
        assert len(result) >= 1

    def test_validate_actor_type_still_runs(self):
        """_validate_actor_type is defence-in-depth — not removed by ok0p.
        This test verifies the function is still importable."""
        from scenario_forge.pipeline.generate import _validate_actor_type
        assert callable(_validate_actor_type)
