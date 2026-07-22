"""Tests for goal-category / profile compatibility gate (0o84 bead).

Covers:
- PR-2 always excluded from goal pool (system prompt theft is structurally phantom)
- AB-2 excluded when KC6.2.2 absent, accepted when present
- PR-4 / PR-6 excluded when has_persistent_memory=false, accepted when true
- AP-T9-05 seed rejected by rule filter when has_persistent_memory=false
- Other goal categories pass through unaffected
"""

from __future__ import annotations

from scenario_forge.data.loaders import load_attack_goals_taxonomy
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    ToolInventoryEntry,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import (
    CandidateTriple,
    _rule_seed_profile_compatibility,
    apply_rule_based_filter,
)
from scenario_forge.pipeline.generate import (
    compute_compatible_goal_ids,
    filter_sub_goals_by_zones,
    get_all_sub_goals,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sub_goal(goal_id: str, name: str = "Test Goal") -> dict:
    """Create a minimal sub-goal dict for testing."""
    cat_id = goal_id.split("-")[0].upper() if "-" in goal_id else "unknown"
    return {
        "id": goal_id,
        "name": name,
        "description": f"Description for {goal_id}",
        "sources": ["test"],
        "category_id": cat_id,
        "category_name": "Test Category",
        "category_description": "Test category description",
    }


def _make_sub_goals_with_ids(*ids: str) -> list[dict]:
    """Create a list of sub-goals with the given IDs."""
    return [_make_sub_goal(gid) for gid in ids]


def _make_ref(risk_id: str = "risk-1", confidence: float = 0.9) -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=confidence,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_profile(
    entry_points: list[str] | None = None,
    kc_subcodes: list[str] | None = None,
) -> CapabilityProfile:
    kc = kc_subcodes or ["KC1.1"]
    # Add tool inventory if tool_execution zone would be activated
    tool_inventory = None
    if any(kc_code.startswith(("KC5.", "KC6.")) for kc_code in kc):
        tool_inventory = [
            ToolInventoryEntry(name="test_tool", description="A test tool"),
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points or ["user prompts (input)"],
        confidence=ConfidenceLevel.high,
        kc_subcodes=kc,
        tool_inventory=tool_inventory,
    )


def _make_candidate(
    seed_id: str = "AP-T7-01",
    threat_id: str = "T7",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
) -> CandidateTriple:
    return CandidateTriple(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        entry_point=entry_point,
        atlas_technique_ids=technique_ids,
        atlas_technique_names=tuple(f"Tech {t}" for t in technique_ids),
        atlas_technique_descriptions=tuple(f"Desc {t}" for t in technique_ids),
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
    )


# ---------------------------------------------------------------------------
# PR-2: Always excluded (system prompt theft is structurally phantom)
# ---------------------------------------------------------------------------


class TestPR2AlwaysExcluded:
    """PR-2 (System Prompt / IP Theft) should always be excluded."""

    def test_pr2_excluded_from_zone_filter(self):
        """PR-2 is excluded by filter_sub_goals_by_zones regardless of profile."""
        goals = _make_sub_goals_with_ids("PR-1", "PR-2", "PR-3")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning", "tool_execution", "memory"],
            has_persistent_memory=True,
            hitl=True,
            multi_agent=True,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-2" not in result_ids
        assert "PR-1" in result_ids
        assert "PR-3" in result_ids

    def test_pr2_excluded_minimal_profile(self):
        """PR-2 excluded even with minimal profile."""
        goals = _make_sub_goals_with_ids("PR-2", "AV-1")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-2" not in result_ids
        assert "AV-1" in result_ids

    def test_pr2_excluded_full_taxonomy(self):
        """PR-2 excluded from full taxonomy load."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        result = filter_sub_goals_by_zones(
            all_goals,
            zones_active=["input", "reasoning", "tool_execution", "memory"],
            has_persistent_memory=True,
            hitl=True,
            multi_agent=True,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-2" not in result_ids


# ---------------------------------------------------------------------------
# AB-2: Excluded when KC6.2.2 absent, accepted when present
# ---------------------------------------------------------------------------


class TestAB2CodeGenPrecise:
    """AB-2 exclusion should check KC6.2.2 specifically when kc_subcodes available."""

    def test_ab2_excluded_without_kc622(self):
        """AB-2 excluded when KC6.2.2 not in kc_subcodes."""
        goals = _make_sub_goals_with_ids("AB-1", "AB-2", "AB-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=["KC1.1", "KC6.1.1"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids
        assert "AB-1" in result_ids

    def test_ab2_accepted_with_kc622(self):
        """AB-2 accepted when KC6.2.2 is present."""
        goals = _make_sub_goals_with_ids("AB-1", "AB-2", "AB-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=["KC1.1", "KC6.2.2"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" in result_ids

    def test_ab2_excluded_with_tool_execution_but_no_kc622(self):
        """Even with tool_execution zone, AB-2 excluded if KC6.2.2 absent."""
        goals = _make_sub_goals_with_ids("AB-2", "IN-1")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=["KC1.1", "KC5.1"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids

    def test_ab2_zone_fallback_without_kc_subcodes(self):
        """When kc_subcodes is None, falls back to zone-level heuristic."""
        goals = _make_sub_goals_with_ids("AB-2", "IN-1")
        # With tool_execution: AB-2 should be kept (zone heuristic)
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=None,
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" in result_ids

    def test_ab2_zone_fallback_without_tool_execution(self):
        """When kc_subcodes is None and no tool_execution, AB-2 excluded."""
        goals = _make_sub_goals_with_ids("AB-2", "IN-1")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning"],
            kc_subcodes=None,
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids


# ---------------------------------------------------------------------------
# PR-4, PR-6: Excluded when has_persistent_memory=false
# ---------------------------------------------------------------------------


class TestCrossUserGoals:
    """PR-4 and PR-6 require persistent memory for cross-user patterns."""

    def test_pr4_excluded_without_persistent_memory(self):
        goals = _make_sub_goals_with_ids("PR-1", "PR-4", "PR-6")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-4" not in result_ids

    def test_pr6_excluded_without_persistent_memory(self):
        goals = _make_sub_goals_with_ids("PR-1", "PR-4", "PR-6")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-6" not in result_ids

    def test_pr4_accepted_with_persistent_memory(self):
        goals = _make_sub_goals_with_ids("PR-1", "PR-4", "PR-6")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=True,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-4" in result_ids

    def test_pr6_accepted_with_persistent_memory(self):
        goals = _make_sub_goals_with_ids("PR-1", "PR-4", "PR-6")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=True,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-6" in result_ids

    def test_pr1_unaffected_without_persistent_memory(self):
        """PR-1 (Data Exfiltration) should not be affected by memory check."""
        goals = _make_sub_goals_with_ids("PR-1", "PR-4", "PR-6")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-1" in result_ids


# ---------------------------------------------------------------------------
# AP-T9-05: Seed rejected when has_persistent_memory=false
# ---------------------------------------------------------------------------


class TestAPT905SeedRejection:
    """AP-T9-05 should be rejected by rule filter when no persistent memory."""

    def test_rule_rejects_t905_without_persistent_memory(self):
        """Direct rule function test."""
        profile = _make_profile()
        assert not profile.has_persistent_memory
        reject, rationale = _rule_seed_profile_compatibility("AP-T9-05", profile)
        assert reject is True
        assert rationale is not None
        assert "AP-T9-05" in rationale
        assert "persistent memory" in rationale

    def test_rule_accepts_t905_with_persistent_memory(self):
        """AP-T9-05 accepted when profile has persistent memory."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC4.3"])
        assert profile.has_persistent_memory
        reject, rationale = _rule_seed_profile_compatibility("AP-T9-05", profile)
        assert reject is False
        assert rationale is None

    def test_rule_accepts_other_seeds(self):
        """Other seed IDs are not affected by this rule."""
        profile = _make_profile()
        reject, _ = _rule_seed_profile_compatibility("AP-T7-01", profile)
        assert reject is False
        reject, _ = _rule_seed_profile_compatibility("AP-T9-01", profile)
        assert reject is False

    def test_apply_rule_filter_rejects_t905(self):
        """End-to-end: apply_rule_based_filter rejects AP-T9-05 candidates."""
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidate = _make_candidate(
            seed_id="AP-T9-05",
            threat_id="T9",
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(rejected) == 1
        assert len(passed) == 0
        assert rejected[0].seed_id == "AP-T9-05"
        assert verdicts[0].verdict == "reject"
        assert "persistent memory" in verdicts[0].rationale

    def test_apply_rule_filter_accepts_t905_with_memory(self):
        """AP-T9-05 passes rule filter when profile has persistent memory.

        T9 also requires tool_execution or inter_agent zones, so the
        profile must include KC5.1 (or similar) to satisfy zone prereqs.
        """
        profile = _make_profile(
            entry_points=["user prompts (input)"],
            kc_subcodes=["KC1.1", "KC4.3", "KC5.1"],
        )
        candidate = _make_candidate(
            seed_id="AP-T9-05",
            threat_id="T9",
        )
        passed, rejected, verdicts = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        assert len(rejected) == 0

    def test_mixed_candidates_only_t905_rejected(self):
        """In a mixed set, only AP-T9-05 is rejected for the memory rule.

        T9 also requires tool_execution or inter_agent zones, so we
        include KC5.1 to satisfy T9's zone prerequisites.  Without
        persistent memory, only AP-T9-05 should be rejected by the
        seed compatibility rule; other T9 seeds pass.
        """
        profile = _make_profile(
            entry_points=["user prompts (input)"],
            kc_subcodes=["KC1.1", "KC5.1"],
        )
        candidates = [
            _make_candidate(seed_id="AP-T7-01", threat_id="T7"),
            _make_candidate(seed_id="AP-T9-05", threat_id="T9"),
            _make_candidate(seed_id="AP-T9-01", threat_id="T9"),
        ]
        passed, rejected, verdicts = apply_rule_based_filter(candidates, profile)
        rejected_ids = {c.seed_id for c in rejected}
        passed_ids = {c.seed_id for c in passed}
        assert "AP-T9-05" in rejected_ids
        assert "AP-T7-01" in passed_ids
        assert "AP-T9-01" in passed_ids


# ---------------------------------------------------------------------------
# Other goal categories pass through unaffected
# ---------------------------------------------------------------------------


class TestUnaffectedGoals:
    """Goal categories not mentioned in the gate pass through unchanged."""

    def test_availability_goals_unaffected(self):
        """AV-1, AV-2, AV-3 pass through regardless of profile."""
        goals = _make_sub_goals_with_ids("AV-1", "AV-2", "AV-3")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "AV-1" in result_ids
        assert "AV-2" in result_ids
        assert "AV-3" in result_ids

    def test_integrity_goals_unaffected(self):
        """IN-1, IN-2 pass through (IN-5 already excluded by memory check)."""
        goals = _make_sub_goals_with_ids("IN-1", "IN-2", "IN-3")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "IN-1" in result_ids

    def test_abuse_goals_unaffected(self):
        """AB-1 (Safety Bypass) passes through."""
        goals = _make_sub_goals_with_ids("AB-1", "AB-4", "AB-5")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "AB-1" in result_ids
        assert "AB-4" in result_ids
        assert "AB-5" in result_ids

    def test_pr1_pr3_unaffected(self):
        """PR-1 (Data Exfil) and PR-3 (Model Extraction) pass through."""
        goals = _make_sub_goals_with_ids("PR-1", "PR-3")
        result = filter_sub_goals_by_zones(
            goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-1" in result_ids
        assert "PR-3" in result_ids


# ---------------------------------------------------------------------------
# Integration: full taxonomy with compatibility gate
# ---------------------------------------------------------------------------


class TestFullTaxonomyIntegration:
    """End-to-end integration test with the real taxonomy."""

    def test_no_persistent_memory_excludes_cross_user_and_pr2(self):
        """With no persistent memory: PR-2, PR-4, PR-5, PR-6 all excluded."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        result = filter_sub_goals_by_zones(
            all_goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-2" not in result_ids
        assert "PR-4" not in result_ids
        assert "PR-5" not in result_ids
        assert "PR-6" not in result_ids
        # But PR-1 and PR-3 should still be available
        assert "PR-1" in result_ids
        assert "PR-3" in result_ids

    def test_with_persistent_memory_keeps_pr4_pr6(self):
        """With persistent memory: PR-4, PR-6 are available (PR-2 still excluded)."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        result = filter_sub_goals_by_zones(
            all_goals,
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=True,
            hitl=False,
            multi_agent=False,
        )
        result_ids = {g["id"] for g in result}
        assert "PR-2" not in result_ids  # always excluded
        assert "PR-4" in result_ids
        assert "PR-6" in result_ids

    def test_ab2_with_kc622_in_full_pipeline(self):
        """AB-2 accepted when KC6.2.2 present in compute_compatible_goal_ids."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        zone_filtered = filter_sub_goals_by_zones(
            all_goals,
            zones_active=["input", "reasoning", "tool_execution"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        # With KC6.2.2: AB-2 should be available
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=zone_filtered,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=["KC1.1", "KC6.2.2"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" in result_ids

    def test_ab2_without_kc622_in_full_pipeline(self):
        """AB-2 excluded when KC6.2.2 absent in compute_compatible_goal_ids."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        zone_filtered = filter_sub_goals_by_zones(
            all_goals,
            zones_active=["input", "reasoning", "tool_execution"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        # Without KC6.2.2 but with KC5.1 (tool but no code gen): AB-2 excluded
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=zone_filtered,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=["KC1.1", "KC5.1"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids
