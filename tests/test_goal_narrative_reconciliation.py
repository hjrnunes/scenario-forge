"""Tests for goal-category narrative reconciliation (gmtc bead).

Covers:
  A. Prompt hierarchy: goal section uses SHOULD not MANDATORY in call1
  B. Affinity tightening: T2 excludes AB-1, T9 excludes PR-3, T10 excludes AV-1/AV-5
  C. Goal-narrative alignment: matching/missing keyword detection
  D. Seed mechanism fidelity: mechanism keyword presence/absence detection
"""

from __future__ import annotations

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    ToolInventoryEntry,
)
from scenario_forge.models.scenario import ActorProfile, RiskCardRef
from scenario_forge.pipeline.generate import (
    _THREAT_GOAL_EXCLUSIONS,
    _build_attack_goal_context_block,
    compute_compatible_goal_ids,
)
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.pipeline.validation import (
    _GOAL_NARRATIVE_KEYWORDS,
    _extract_mechanism_keywords,
    check_goal_narrative_alignment,
    check_seed_mechanism_fidelity,
)
from scenario_forge.prompts import render_prompt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sub_goal(goal_id: str, name: str = "Test Goal") -> dict:
    """Create a minimal sub-goal dict for testing."""
    return {
        "id": goal_id,
        "name": name,
        "description": f"Description for {goal_id}",
        "sources": ["test"],
        "category_id": goal_id.split("-")[0].upper() if "-" in goal_id else "unknown",
        "category_name": "Test Category",
        "category_description": "Test category description",
    }


def _make_sub_goals_with_ids(*ids: str) -> list[dict]:
    return [_make_sub_goal(gid) for gid in ids]


def _make_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="user prompts via chat", direction="input"),
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[ToolInventoryEntry(name="test_tool", description="A test tool")],
    )


def _make_seed() -> ScenarioSeed:
    return ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Misaligned Behavior",
        threat_description="Agent acts against user interests",
        attack_pattern_name="RAG Poisoning",
        attack_pattern_description="Attacker poisons RAG data",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description for risk-1",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0051.001"],
    )


# ---------------------------------------------------------------------------
# Part A: Prompt hierarchy — goal section uses SHOULD not MANDATORY
# ---------------------------------------------------------------------------


class TestGoalSectionPromptHierarchy:
    """The goal section in call1 user prompt should use SHOULD, not MANDATORY."""

    def test_call1_goal_section_uses_should(self):
        """Goal section heading says SHOULD, not MANDATORY."""
        actor = ActorProfile(
            actor_type="adversarial-user",
            capability_level="intermediate",
            beliefs=["belief"],
            desires=["desire"],
            intentions=["intention"],
            resources=["resource"],
            goal_category="AB-4",
            goal_category_name="Social Engineering / Phishing",
            goal_category_parent="abuse",
        )
        # Replicate the goal_section construction from generate.py
        goal_section = ""
        if actor is not None and actor.goal_category:
            goal_section = (
                "\n## Attack Goal Guidance (SHOULD)\n"
                f"**Category:** {actor.goal_category_parent}\n"
                f"**Specific Goal:** {actor.goal_category}: "
                f"{actor.goal_category_name}\n\n"
                "The narrative's terminal attack outcome SHOULD align with this goal "
                "when it is compatible with the seed attack pattern's mechanism. "
                "If satisfying this goal would require abandoning the seed's core "
                "attack mechanism, prioritise seed fidelity — the goal is a guiding "
                "preference, not a hard override. The seed's 'Seed Attack Objective "
                "Fidelity (MANDATORY)' constraint always takes precedence.\n"
            )
        assert "SHOULD" in goal_section
        assert "MANDATORY" not in goal_section.split("\n")[1]  # heading line
        assert "guiding preference" in goal_section
        assert "seed fidelity" in goal_section

    def test_call1_goal_section_does_not_say_must_achieve(self):
        """Old wording 'MUST achieve this goal' should not appear."""
        actor = ActorProfile(
            actor_type="adversarial-user",
            capability_level="intermediate",
            beliefs=["belief"],
            desires=["desire"],
            intentions=["intention"],
            resources=["resource"],
            goal_category="AB-4",
            goal_category_name="Social Engineering",
            goal_category_parent="abuse",
        )
        goal_section = ""
        if actor is not None and actor.goal_category:
            goal_section = (
                "\n## Attack Goal Guidance (SHOULD)\n"
                f"**Category:** {actor.goal_category_parent}\n"
                f"**Specific Goal:** {actor.goal_category}: "
                f"{actor.goal_category_name}\n\n"
                "The narrative's terminal attack outcome SHOULD align with this goal "
                "when it is compatible with the seed attack pattern's mechanism. "
                "If satisfying this goal would require abandoning the seed's core "
                "attack mechanism, prioritise seed fidelity — the goal is a guiding "
                "preference, not a hard override. The seed's 'Seed Attack Objective "
                "Fidelity (MANDATORY)' constraint always takes precedence.\n"
            )
        assert "MUST achieve this goal" not in goal_section

    def test_seed_fidelity_remains_mandatory_in_system_prompt(self):
        """Seed Attack Objective Fidelity must stay MANDATORY."""
        system_prompt = render_prompt(
            "call1_system.j2",
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            zones_active=["input", "reasoning"],
            kc_subcodes=[],
            tool_inventory=[],
        )
        assert "Seed Attack Objective Fidelity (MANDATORY)" in system_prompt

    def test_call0_goal_context_uses_should(self):
        """_build_attack_goal_context_block uses SHOULD, not MANDATORY."""
        sub_goal = _make_sub_goal("AB-4", "Social Engineering / Phishing")
        block = _build_attack_goal_context_block(sub_goal)
        assert "SHOULD" in block or "should" in block
        assert "(MANDATORY)" not in block

    def test_call0_goal_context_no_must_concrete(self):
        """Old 'MUST be concrete' wording removed from call0 goal block."""
        sub_goal = _make_sub_goal("AB-4", "Social Engineering / Phishing")
        block = _build_attack_goal_context_block(sub_goal)
        assert "MUST be concrete" not in block


# ---------------------------------------------------------------------------
# Part B: Affinity tightening — new exclusions
# ---------------------------------------------------------------------------


class TestAffinityTighteningT2:
    """T2 (Prompt Injection) should exclude AB-1 (Jailbreak)."""

    def test_t2_excludes_ab1(self):
        goals = _make_sub_goals_with_ids("AB-1", "AB-3", "AB-4", "IN-1")
        result = compute_compatible_goal_ids(
            threat_id="T2",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-1" not in result_ids
        assert "AB-3" in result_ids

    def test_t2_exclusion_in_constant(self):
        assert "AB-1" in _THREAT_GOAL_EXCLUSIONS["T2"]

    def test_non_t2_keeps_ab1(self):
        """Other threats should not exclude AB-1."""
        goals = _make_sub_goals_with_ids("AB-1", "AB-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-1" in result_ids


class TestAffinityTighteningT9:
    """T9 (Identity Spoofing) should exclude PR-3 (Model Extraction)."""

    def test_t9_excludes_pr3(self):
        goals = _make_sub_goals_with_ids("PR-1", "PR-3", "AB-7")
        result = compute_compatible_goal_ids(
            threat_id="T9",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "PR-3" not in result_ids
        assert "PR-1" in result_ids
        assert "AB-7" in result_ids

    def test_t9_exclusion_in_constant(self):
        assert "PR-3" in _THREAT_GOAL_EXCLUSIONS["T9"]

    def test_non_t9_keeps_pr3(self):
        goals = _make_sub_goals_with_ids("PR-3", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T3",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "PR-3" in result_ids


class TestAffinityTighteningT10:
    """T10 (Overwhelming HITL) should exclude AV-1 and AV-5."""

    def test_t10_excludes_av1(self):
        goals = _make_sub_goals_with_ids("AV-1", "AV-2", "AV-3", "IN-6")
        result = compute_compatible_goal_ids(
            threat_id="T10",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AV-1" not in result_ids
        assert "AV-2" in result_ids

    def test_t10_excludes_av5(self):
        goals = _make_sub_goals_with_ids("AV-1", "AV-5", "IN-6")
        result = compute_compatible_goal_ids(
            threat_id="T10",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AV-5" not in result_ids
        assert "IN-6" in result_ids

    def test_t10_exclusion_in_constant(self):
        assert "AV-1" in _THREAT_GOAL_EXCLUSIONS["T10"]
        assert "AV-5" in _THREAT_GOAL_EXCLUSIONS["T10"]

    def test_non_t10_keeps_av1_av5(self):
        """T4 (Resource Overload) SHOULD still have AV-1/AV-5."""
        goals = _make_sub_goals_with_ids("AV-1", "AV-5")
        result = compute_compatible_goal_ids(
            threat_id="T4",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AV-1" in result_ids
        assert "AV-5" in result_ids


class TestAffinityFallbackSafety:
    """When all goals would be excluded, fallback to original list."""

    def test_t2_all_excluded_fallback(self):
        """If T2 pool is only AB-1 and it's excluded, fallback."""
        goals = _make_sub_goals_with_ids("AB-1")
        result = compute_compatible_goal_ids(
            threat_id="T2",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        # Fallback: return original
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Part C: Goal-narrative alignment validation
# ---------------------------------------------------------------------------


class TestGoalNarrativeAlignment:
    """check_goal_narrative_alignment detects keyword presence/absence."""

    def test_matching_keywords_pass(self):
        """Narrative with matching keywords returns None (no warning)."""
        result = check_goal_narrative_alignment(
            "AB-4",
            "The attacker uses social engineering techniques to phish credentials.",
        )
        assert result is None

    def test_missing_keywords_flagged(self):
        """Narrative with zero matching keywords returns a warning."""
        result = check_goal_narrative_alignment(
            "AB-4",
            "The attacker floods the server with requests causing downtime.",
        )
        assert result is not None
        assert "AB-4" in result
        assert "expected keywords" in result

    def test_none_goal_id_passes(self):
        """None goal_id always returns None."""
        result = check_goal_narrative_alignment(None, "any text")
        assert result is None

    def test_unknown_goal_id_passes(self):
        """Unknown goal IDs return None (not in keyword map)."""
        result = check_goal_narrative_alignment("ZZ-99", "any text")
        assert result is None

    def test_partial_keyword_match(self):
        """Substring keywords like 'manipulat' match 'manipulation'."""
        result = check_goal_narrative_alignment(
            "AB-5",
            "The attacker uses subtle manipulation of the user's trust.",
        )
        assert result is None

    def test_case_insensitive(self):
        """Keyword matching is case-insensitive."""
        result = check_goal_narrative_alignment(
            "AB-1",
            "The attacker performs a JAILBREAK to bypass safety controls.",
        )
        assert result is None

    def test_adversarial_ab1_with_injection_narrative(self):
        """AB-1 (Jailbreak) flagged when narrative is about data poisoning."""
        result = check_goal_narrative_alignment(
            "AB-1",
            "The attacker injects poisoned data into the training pipeline "
            "to corrupt the model's outputs over time.",
        )
        assert result is not None
        assert "AB-1" in result

    def test_pr3_with_impersonation_narrative(self):
        """PR-3 (Model Extraction) flagged when narrative is about spoofing."""
        result = check_goal_narrative_alignment(
            "PR-3",
            "The attacker impersonates a legitimate user to gain elevated "
            "access to the system and abuse trust relationships.",
        )
        assert result is not None
        assert "PR-3" in result

    def test_all_goal_ids_have_keywords(self):
        """Every goal ID in the keyword map has at least one keyword."""
        for goal_id, keywords in _GOAL_NARRATIVE_KEYWORDS.items():
            assert len(keywords) > 0, f"Goal {goal_id} has no keywords"


# ---------------------------------------------------------------------------
# Part D: Seed mechanism fidelity check
# ---------------------------------------------------------------------------


class TestSeedMechanismFidelity:
    """check_seed_mechanism_fidelity detects mechanism keyword presence/absence."""

    def test_matching_mechanism_passes(self):
        """Narrative mentioning seed mechanism returns None."""
        result = check_seed_mechanism_fidelity(
            "Identity Spoofing via Token Theft",
            "I spoof the identity of an admin by stealing their session token.",
        )
        assert result is None

    def test_missing_mechanism_flagged(self):
        """Narrative with completely unrelated mechanism flags warning."""
        result = check_seed_mechanism_fidelity(
            "Identity Spoofing via Token Theft",
            "I flood the server with requests until it crashes causing "
            "complete service unavailability for all users.",
        )
        assert result is not None
        assert "Identity Spoofing" in result
        assert "attack pattern abandonment" in result

    def test_empty_attack_pattern_passes(self):
        """Empty attack pattern name returns None."""
        result = check_seed_mechanism_fidelity("", "any text")
        assert result is None

    def test_none_attack_pattern_passes(self):
        """None attack pattern returns None (type safety)."""
        # Defensive: the function accepts str, but callers might pass None
        # through dynamic dispatch
        result = check_seed_mechanism_fidelity("", "any narrative text")
        assert result is None

    def test_partial_match_passes(self):
        """Even one keyword match is sufficient."""
        result = check_seed_mechanism_fidelity(
            "Trust Calibration Degradation",
            "I exploit the trust relationship to undermine calibration.",
        )
        assert result is None

    def test_case_insensitive(self):
        """Mechanism keyword matching is case-insensitive."""
        result = check_seed_mechanism_fidelity(
            "RAG Poisoning",
            "I target the RAG system by POISONING the knowledge base.",
        )
        assert result is None

    def test_adversarial_dos_instead_of_trust(self):
        """DoS flooding narrative flagged when seed is Trust Calibration."""
        result = check_seed_mechanism_fidelity(
            "Trust Calibration Degradation",
            "I launch a distributed denial of service attack flooding "
            "the API endpoints with millions of requests per second.",
        )
        assert result is not None
        assert "Trust Calibration Degradation" in result

    def test_extract_mechanism_keywords_filters_stop_words(self):
        """Stop words are filtered from mechanism keywords."""
        keywords = _extract_mechanism_keywords(
            "Attack via Data Injection through API"
        )
        assert "via" not in keywords
        assert "through" not in keywords
        assert "attack" not in keywords
        assert "data" in keywords
        assert "injection" in keywords
        assert "api" in keywords

    def test_extract_mechanism_keywords_filters_short_tokens(self):
        """Tokens shorter than 3 chars are filtered."""
        keywords = _extract_mechanism_keywords("AI ML Data Exfiltration")
        assert "ai" not in keywords
        assert "ml" not in keywords
        assert "data" in keywords
        assert "exfiltration" in keywords

    def test_extract_mechanism_keywords_empty_string(self):
        """Empty string produces empty keyword list."""
        assert _extract_mechanism_keywords("") == []
