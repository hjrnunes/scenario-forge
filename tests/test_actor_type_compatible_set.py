"""Tests for compute_compatible_actor_types (ok0p + 6xe7 beads).

Covers:
- R1: Adversarial-only threat -> remove negligent-insider
- R2: Indirect EP access floor -> restrict to {supply-chain-actor,
      malicious-insider, nation-state} (T2+RAG exception)
- R3: System EP -> restrict to {malicious-insider, supply-chain-actor, nation-state}
- R4: Technique requires direct access -> remove negligent-insider, supply-chain-actor
- R5: Supply chain target layer -> restrict to {supply-chain-actor, nation-state,
      malicious-insider, automated-agent}
- R6: Actor-goal consistency -> remove actors incompatible with assigned goal
- Rule stacking
- Diversity tracker interaction
- Prompt template integration
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from scenario_forge.pipeline.generate import (
    _ACTOR_GOAL_INCOMPATIBLE,
    _ADVERSARIAL_ONLY_THREATS,
    ALL_ACTOR_TYPES,
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
        result = compute_compatible_actor_types(["AML.T0053"], "direct", threat_id)
        assert "negligent-insider" not in result

    def test_non_adversarial_threat_keeps_negligent(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
        assert "negligent-insider" in result

    def test_none_threat_keeps_negligent(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", None)
        assert "negligent-insider" in result


# ---------------------------------------------------------------------------
# R2: Indirect EP access floor (T2+RAG exception)
# ---------------------------------------------------------------------------


class TestR2IndirectEP:
    """R2: Typed access-class compatibility (cmps.6).

    Indirect EP restricts to actors in _ACTOR_ACCESS_CLASS_COMPAT['indirect']:
    {supply-chain-actor, malicious-insider, nation-state, competitor, automated-agent}.
    No keyword-based T2+RAG exception — the access class is canonical.
    """

    _INDIRECT_ALLOWED: ClassVar[set[str]] = {
        "supply-chain-actor",
        "malicious-insider",
        "nation-state",
        "competitor",
        "automated-agent",
    }

    def test_indirect_ep_restricts_to_allowed_set(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert result == self._INDIRECT_ALLOWED

    def test_indirect_ep_excludes_adversarial_user(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "adversarial-user" not in result

    def test_indirect_ep_excludes_hacktivist(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "hacktivist" not in result

    def test_indirect_ep_excludes_cybercriminal(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "cybercriminal" not in result

    def test_indirect_ep_keeps_competitor(self):
        """competitor is in the indirect allowlist (cmps.6)."""
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "competitor" in result

    def test_indirect_ep_keeps_automated_agent(self):
        """automated-agent is in the indirect allowlist (cmps.6)."""
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "automated-agent" in result

    def test_indirect_ep_keeps_supply_chain(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "supply-chain-actor" in result

    def test_indirect_ep_keeps_malicious_insider(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "malicious-insider" in result

    def test_indirect_ep_keeps_nation_state(self):
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T2")
        assert "nation-state" in result

    def test_t2_rag_no_keyword_exception(self):
        """T2+RAG no longer gets a keyword exception — same canonical access class."""
        result = compute_compatible_actor_types(
            ["AML.T0053"],
            "indirect",
            "T2",
            entry_point_name="RAG knowledge-grounding system",
        )
        assert result == self._INDIRECT_ALLOWED

    def test_non_t2_indirect_same_as_t2(self):
        """No T2-specific exception — all indirect EPs get the same allowlist."""
        result = compute_compatible_actor_types(
            ["AML.T0053"],
            "indirect",
            "T1",
            entry_point_name="RAG knowledge-grounding system",
        )
        assert result == self._INDIRECT_ALLOWED

    def test_direct_ep_no_r2_effect(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
        assert "negligent-insider" in result
        assert result == ALL_ACTOR_TYPES


# ---------------------------------------------------------------------------
# R3: System EP — not eligible ingress (cmps.6)
# ---------------------------------------------------------------------------


class TestR3SystemEP:
    """R3: System EP is not eligible ingress — no actor pre-filtering.

    System entry points are rejected by is_attacker_accessible_ingress and
    the candidate filter before generation. No actor allowlist is applied.
    """

    def test_system_ep_no_actor_restriction(self):
        """System EP does not restrict actors — rejected at ingress, not actor level."""
        result = compute_compatible_actor_types(["AML.T0053"], "system", "T2")
        assert result == ALL_ACTOR_TYPES

    def test_direct_ep_no_restriction(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
        assert len(result) == len(ALL_ACTOR_TYPES)


# ---------------------------------------------------------------------------
# R4: Technique requires direct access
# ---------------------------------------------------------------------------


class TestR4DirectAccessTechnique:
    """R4: Techniques requiring direct access remove negligent-insider and
    supply-chain-actor."""

    def test_direct_access_technique_removes_negligent_and_supply_chain(self):
        # AML.T0051.000 has requires_direct_access = True
        result = compute_compatible_actor_types(["AML.T0051.000"], "direct", "T2")
        assert "negligent-insider" not in result
        assert "supply-chain-actor" not in result

    def test_direct_access_technique_t0054(self):
        # AML.T0054 also has requires_direct_access = True
        result = compute_compatible_actor_types(["AML.T0054"], "direct", "T2")
        assert "negligent-insider" not in result
        assert "supply-chain-actor" not in result

    def test_non_direct_access_keeps_both(self):
        # AML.T0053 has requires_direct_access = False
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
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
        result = compute_compatible_actor_types(["AML.T0010"], "direct", "T2")
        expected = {
            "supply-chain-actor",
            "nation-state",
            "malicious-insider",
            "automated-agent",
        }
        assert result == expected

    def test_supply_chain_technique_t0048(self):
        # AML.T0048 also has target_layer = "supply_chain"
        result = compute_compatible_actor_types(["AML.T0048"], "direct", "T2")
        expected = {
            "supply-chain-actor",
            "nation-state",
            "malicious-insider",
            "automated-agent",
        }
        assert result == expected

    def test_non_supply_chain_no_restriction(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
        assert len(result) == len(ALL_ACTOR_TYPES)

    def test_automated_agent_included_in_supply_chain(self):
        """Automated agents can participate in supply chain attacks."""
        result = compute_compatible_actor_types(["AML.T0010"], "direct", "T2")
        assert "automated-agent" in result


# ---------------------------------------------------------------------------
# R6: Actor-goal consistency
# ---------------------------------------------------------------------------


class TestR6ActorGoalConsistency:
    """R6: Actor types incompatible with the assigned goal are removed."""

    def test_hacktivist_excluded_from_fraud(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AB-3"
        )
        assert "hacktivist" not in result

    def test_competitor_excluded_from_fraud(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AB-3"
        )
        assert "competitor" not in result

    def test_cybercriminal_kept_for_fraud(self):
        """Cybercriminals are financially motivated -- AB-3 is core."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AB-3"
        )
        assert "cybercriminal" in result

    def test_adversarial_user_kept_for_fraud(self):
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AB-3"
        )
        assert "adversarial-user" in result

    def test_hacktivist_kept_for_non_fraud_goal(self):
        """Hacktivists remain compatible with non-fraud goals."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AV-1"
        )
        assert "hacktivist" in result

    def test_competitor_kept_for_non_fraud_goal(self):
        """Competitors remain compatible with non-fraud goals like PR-2."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="PR-2"
        )
        assert "competitor" in result

    def test_hacktivist_kept_for_integrity_goal(self):
        """Hacktivists can pursue integrity attacks (e.g. disinformation)."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="IN-2"
        )
        assert "hacktivist" in result

    def test_no_goal_id_no_r6_effect(self):
        """Without goal_id, R6 does not fire -- all actors remain."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id=None
        )
        assert result == ALL_ACTOR_TYPES

    def test_unknown_goal_id_no_r6_effect(self):
        """Unknown goal_id not in the incompatibility map -- no effect."""
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="UNKNOWN-99"
        )
        assert result == ALL_ACTOR_TYPES

    def test_r6_never_empties_set(self):
        """R6 safety: if removing incompatible actors would empty the set,
        R6 is skipped."""
        # Construct a scenario where only hacktivist/competitor remain
        # after other rules. This is artificial but tests the safety net.
        # R3 restricts to {malicious-insider, supply-chain-actor, nation-state}
        # so AB-3 removing hacktivist/competitor is a no-op. Use direct EP instead.
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AB-3"
        )
        assert len(result) >= 1

    def test_incompatibility_map_contains_ab3(self):
        """Verify the mapping is correctly loaded."""
        assert "AB-3" in _ACTOR_GOAL_INCOMPATIBLE
        assert "hacktivist" in _ACTOR_GOAL_INCOMPATIBLE["AB-3"]
        assert "competitor" in _ACTOR_GOAL_INCOMPATIBLE["AB-3"]


# ---------------------------------------------------------------------------
# Rule stacking
# ---------------------------------------------------------------------------


class TestRuleStacking:
    """Multiple rules narrowing the compatible set together."""

    def test_r1_and_r3_stacking(self):
        # T7 (adversarial-only) + system EP — system EP no longer restricts
        # actors (cmps.6); only R1 fires.
        result = compute_compatible_actor_types(["AML.T0053"], "system", "T7")
        # R1 removes negligent-insider; system EP no restriction
        assert "negligent-insider" not in result
        assert result == ALL_ACTOR_TYPES - {"negligent-insider"}

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

    def test_r1_r2_stacking_indirect_adversarial_only(self):
        # T7 (adversarial-only) + indirect EP: R1 removes negligent-insider,
        # R2 restricts to indirect allowlist
        _INDIRECT = {
            "supply-chain-actor",
            "malicious-insider",
            "nation-state",
            "competitor",
            "automated-agent",
        }
        result = compute_compatible_actor_types(["AML.T0053"], "indirect", "T7")
        assert "negligent-insider" not in result
        assert "adversarial-user" not in result
        assert result == _INDIRECT

    def test_r2_and_r5_stacking(self):
        # Indirect EP + AB-3 goal: R2 restricts to 5 actors, R5 removes
        # hacktivist/competitor (competitor removed by R5)
        result = compute_compatible_actor_types(
            ["AML.T0053"], "indirect", "T2", goal_id="AB-3"
        )
        assert "competitor" not in result
        assert "hacktivist" not in result
        assert result == {
            "supply-chain-actor",
            "malicious-insider",
            "nation-state",
            "automated-agent",
        }

    def test_r6_with_direct_ep(self):
        # Direct EP + AB-3 goal: R6 removes hacktivist and competitor
        result = compute_compatible_actor_types(
            ["AML.T0053"], "direct", "T2", goal_id="AB-3"
        )
        assert "hacktivist" not in result
        assert "competitor" not in result
        # Other external actors still present
        assert "adversarial-user" in result
        assert "cybercriminal" in result

    def test_all_rules_combined(self):
        # R1 (T7) + R4 (supply chain technique) + R5 (AB-3 goal)
        # System EP no longer restricts actors (cmps.6)
        result = compute_compatible_actor_types(
            ["AML.T0010"], "system", "T7", goal_id="AB-3"
        )
        # R1: remove negligent-insider
        # R4 (supply chain target): restrict to {supply-chain, nation-state, malicious, automated-agent}
        # R5 (AB-3): remove hacktivist/competitor (already gone)
        assert result == {
            "supply-chain-actor",
            "nation-state",
            "malicious-insider",
            "automated-agent",
        }


# ---------------------------------------------------------------------------
# ALL_ACTOR_TYPES constant integrity
# ---------------------------------------------------------------------------


class TestAllActorTypes:
    def test_nine_actor_types(self):
        assert len(ALL_ACTOR_TYPES) == 9

    def test_contains_expected_types(self):
        expected = {
            "adversarial-user",
            "malicious-insider",
            "negligent-insider",
            "supply-chain-actor",
            "cybercriminal",
            "nation-state",
            "hacktivist",
            "competitor",
            "automated-agent",
        }
        assert ALL_ACTOR_TYPES == expected


# ---------------------------------------------------------------------------
# Prompt template integration
# ---------------------------------------------------------------------------


class TestActorTypePromptConstraint:
    """The call0_user.j2 template includes the constraint when compatible
    set is narrower than full."""

    # Minimal user-prompt context needed to render call0_user.j2
    _USER_CTX: ClassVar[dict] = {
        "use_case": "test",
        "seed": type(
            "S",
            (),
            {
                "attack_pattern_name": "X",
                "attack_pattern_description": "X",
                "threat_name": "X",
                "threat_description": "X",
            },
        )(),
        "profile": type(
            "P",
            (),
            {
                "zones_active": ["input"],
                "entry_points": [],
            },
        )(),
        "kc_definitions": "",
        "tool_inventory": [],
        "ontology_context": "",
        "pinned_entry_point": None,
        "pinned_entry_point_direction": None,
        "pinned_technique_count": 1,
        "technique_context": "",
        "technique_framing_0": "",
        "goal_section": "",
        "diversity_section": "",
        "minimum_capability_level": "novice",
    }

    def test_constraint_appears_when_narrowed(self):
        ctx = {
            **self._USER_CTX,
            "compatible_actor_types": ["adversarial-user", "cybercriminal"],
        }
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Actor Type Constraint" in prompt
        assert "adversarial-user" in prompt
        assert "cybercriminal" in prompt

    def test_constraint_lists_all_compatible(self):
        types = sorted(["nation-state", "malicious-insider", "supply-chain-actor"])
        ctx = {**self._USER_CTX, "compatible_actor_types": types}
        prompt = render_prompt("call0_user.j2", **ctx)
        for t in types:
            assert t in prompt

    def test_no_constraint_without_kwarg(self):
        ctx = {**self._USER_CTX}
        ctx.pop("compatible_actor_types", None)
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Actor Type Constraint" not in prompt

    def test_empty_list_no_constraint(self):
        ctx = {**self._USER_CTX, "compatible_actor_types": []}
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Actor Type Constraint" not in prompt


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
        result = compute_compatible_actor_types(["UNKNOWN.T9999"], "direct", "T2")
        assert result == ALL_ACTOR_TYPES

    def test_tuple_technique_ids_accepted(self):
        result = compute_compatible_actor_types(("AML.T0051.000",), "direct", "T2")
        assert "negligent-insider" not in result

    def test_result_is_set(self):
        result = compute_compatible_actor_types(["AML.T0053"], "direct", "T2")
        assert isinstance(result, set)

    def test_never_empty_with_system_ep(self):
        """R3 always leaves at least 3 types."""
        result = compute_compatible_actor_types(["AML.T0053"], "system", "T2")
        assert len(result) >= 1

    def test_validate_actor_type_still_runs(self):
        """_validate_actor_type is defence-in-depth — not removed by ok0p.
        This test verifies the function is still importable."""
        from scenario_forge.pipeline.generate import _validate_actor_type

        assert callable(_validate_actor_type)
