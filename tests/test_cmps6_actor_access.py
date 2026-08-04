"""Tests for cmps.6: evidence-based actor and initial-ingress access policy.

Covers:
- Valid insider-public (direct ingress with material_insider_advantage)
- Invalid unevidenced insider-public (direct ingress without advantage)
- Valid indirect influence (complete source/mechanism/boundary evidence)
- Fabricated indirect access (indirect without evidence)
- System/output exclusion (system and output EPs are not eligible ingress)
- Incompatible forced diversity (diversity must not force an incompatible actor)
- Retry routing (access provenance mismatch retries Call 0)
- Exhaustion (persistent mismatch proceeds to quarantine after max retries)
"""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import MagicMock, patch

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from scenario_forge.models.scenario import (
    ACTOR_TYPES,
    ActorAccessProvenance,
    ActorProfile,
)
from scenario_forge.pipeline.generate.actor import (
    build_actor_access_provenance,
    compute_compatible_actor_types,
    validate_actor_access_provenance,
)
from scenario_forge.pipeline.generate.constants import (
    _ACTOR_ACCESS_CLASS_COMPAT,
    _ACTOR_ACCESS_MAX_RETRIES,
    _INSIDER_ACTOR_TYPES,
)
from scenario_forge.pipeline.generate.constants import (
    ALL_ACTOR_TYPES as CONST_ALL_ACTOR_TYPES,
)
from scenario_forge.pipeline.seeds import RiskCardRef, ScenarioSeed

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry_point(
    name: str = "user prompts (chat)",
    direction: str = "input",
    controllability: str = "direct",
) -> EntryPoint:
    return EntryPoint(name=name, direction=direction, controllability=controllability)


def _make_profile(
    entry_points: list[EntryPoint] | None = None,
    zones_active: list[str] | None = None,
) -> CapabilityProfile:
    if zones_active is None:
        zones_active = ["input", "reasoning", "tool_execution"]
    if entry_points is None:
        entry_points = [_make_entry_point()]
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=entry_points,
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _make_seed(threat_id: str = "T2") -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=f"AP-{threat_id}-01",
        threat_id=threat_id,
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="Test description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        atlas_technique_ids=[],
    )


def _make_call0_response(
    actor_type: str = "cybercriminal",
    influence_source: str | None = None,
    influence_mechanism: str | None = None,
    trust_boundary: str | None = None,
    material_insider_advantage: str | None = None,
):
    """Create a mock Call0Response-like object with access provenance fields."""
    from scenario_forge.pipeline.generate.actor import Call0Response

    return Call0Response(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["The system exposes a chat interface."],
        desires=["I want to extract data."],
        intentions=["I will send crafted input."],
        resources=["Standard tools"],
        influence_source=influence_source,
        influence_mechanism=influence_mechanism,
        trust_boundary=trust_boundary,
        material_insider_advantage=material_insider_advantage,
    )


def _make_actor_with_access(
    actor_type: str = "cybercriminal",
    entry_point_id: str = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    access_class: str = "direct",
    influence_source: str | None = None,
    influence_mechanism: str | None = None,
    trust_boundary: str | None = None,
    material_insider_advantage: str | None = None,
) -> ActorProfile:
    access = ActorAccessProvenance(
        initial_entry_point_id=entry_point_id,
        access_class=access_class,  # type: ignore[arg-type]
        influence_source=influence_source,
        influence_mechanism=influence_mechanism,
        trust_boundary=trust_boundary,
        material_insider_advantage=material_insider_advantage,
    )
    return ActorProfile(
        actor_type=actor_type,  # type: ignore[arg-type]
        capability_level="intermediate",
        beliefs=["The system has a vulnerability."],
        desires=["Extract data."],
        intentions=["Send crafted input."],
        resources=["Tools"],
        access=access,
    )


_VALID_EP_ID = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_VALID_EP_ID_2 = "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


# ---------------------------------------------------------------------------
# Tests: validate_actor_access_provenance
# ---------------------------------------------------------------------------


class TestValidateActorAccessProvenance:
    """Unit tests for the access provenance validation function."""

    def test_missing_access_provenance_flagged(self):
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        violations = validate_actor_access_provenance(actor)
        assert len(violations) == 1
        assert violations[0].rule == "missing_access_provenance"

    def test_direct_external_actor_passes(self):
        actor = _make_actor_with_access(
            actor_type="cybercriminal",
            access_class="direct",
        )
        violations = validate_actor_access_provenance(actor)
        assert violations == []

    def test_indirect_supply_chain_with_evidence_passes(self):
        actor = _make_actor_with_access(
            actor_type="supply-chain-actor",
            access_class="indirect",
            influence_source="RAG knowledge base",
            influence_mechanism="document poisoning",
            trust_boundary="external content provider → retrieval pipeline",
        )
        violations = validate_actor_access_provenance(actor)
        assert violations == []

    def test_indirect_without_evidence_flagged(self):
        actor = _make_actor_with_access(
            actor_type="supply-chain-actor",
            access_class="indirect",
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "incomplete_indirect_evidence" in rules

    def test_indirect_partial_evidence_flagged(self):
        actor = _make_actor_with_access(
            actor_type="nation-state",
            access_class="indirect",
            influence_source="product catalog feed",
            influence_mechanism=None,
            trust_boundary=None,
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "incomplete_indirect_evidence" in rules
        msg = violations[0].message
        assert "influence_mechanism" in msg
        assert "trust_boundary" in msg

    def test_indirect_incompatible_actor_flagged(self):
        """adversarial-user is not in the indirect allowlist."""
        actor = _make_actor_with_access(
            actor_type="adversarial-user",
            access_class="indirect",
            influence_source="x",
            influence_mechanism="y",
            trust_boundary="z",
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "actor_access_class_incompatible" in rules

    def test_insider_direct_with_advantage_passes(self):
        """Valid insider-public: malicious-insider with material advantage."""
        actor = _make_actor_with_access(
            actor_type="malicious-insider",
            access_class="direct",
            material_insider_advantage="knowledge of internal rate-limit bypass",
        )
        violations = validate_actor_access_provenance(actor)
        assert violations == []

    def test_insider_direct_without_advantage_flagged(self):
        """Invalid unevidenced insider-public."""
        actor = _make_actor_with_access(
            actor_type="malicious-insider",
            access_class="direct",
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "missing_insider_advantage" in rules

    def test_negligent_insider_direct_without_advantage_flagged(self):
        actor = _make_actor_with_access(
            actor_type="negligent-insider",
            access_class="direct",
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "missing_insider_advantage" in rules

    def test_insider_indirect_no_advantage_required(self):
        """Insider using indirect ingress doesn't need material_insider_advantage."""
        actor = _make_actor_with_access(
            actor_type="malicious-insider",
            access_class="indirect",
            influence_source="internal wiki",
            influence_mechanism="content poisoning",
            trust_boundary="employee editing → knowledge base ingestion",
        )
        violations = validate_actor_access_provenance(actor)
        assert violations == []

    def test_blank_advantage_flagged(self):
        actor = _make_actor_with_access(
            actor_type="malicious-insider",
            access_class="direct",
            material_insider_advantage="   ",
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "missing_insider_advantage" in rules


# ---------------------------------------------------------------------------
# Tests: build_actor_access_provenance
# ---------------------------------------------------------------------------


class TestBuildActorAccessProvenance:
    """Tests for the provenance builder from canonical EP identity."""

    def test_direct_ep_builds_direct_access(self):
        resp = _make_call0_response(actor_type="cybercriminal")
        access = build_actor_access_provenance(
            entry_point_id=_VALID_EP_ID,
            ep_controllability="direct",
            actor_type="cybercriminal",
            resp=resp,
        )
        assert access.access_class == "direct"
        assert access.initial_entry_point_id == _VALID_EP_ID

    def test_indirect_ep_builds_indirect_access(self):
        resp = _make_call0_response(
            actor_type="supply-chain-actor",
            influence_source="data feed",
            influence_mechanism="poisoning",
            trust_boundary="external → internal",
        )
        access = build_actor_access_provenance(
            entry_point_id=_VALID_EP_ID,
            ep_controllability="indirect",
            actor_type="supply-chain-actor",
            resp=resp,
        )
        assert access.access_class == "indirect"
        assert access.influence_source == "data feed"
        assert access.influence_mechanism == "poisoning"
        assert access.trust_boundary == "external → internal"

    def test_system_ep_defaults_to_direct(self):
        """System EP is not eligible ingress; defaults to direct for constructibility."""
        resp = _make_call0_response()
        access = build_actor_access_provenance(
            entry_point_id=_VALID_EP_ID,
            ep_controllability="system",
            actor_type="malicious-insider",
            resp=resp,
        )
        assert access.access_class == "direct"

    def test_none_controllability_defaults_to_direct(self):
        resp = _make_call0_response()
        access = build_actor_access_provenance(
            entry_point_id=_VALID_EP_ID,
            ep_controllability=None,
            actor_type="cybercriminal",
            resp=resp,
        )
        assert access.access_class == "direct"


# ---------------------------------------------------------------------------
# Tests: System/output exclusion
# ---------------------------------------------------------------------------


class TestSystemOutputExclusion:
    """System and output entry points are not eligible ingress."""

    def test_system_ep_not_attacker_accessible(self):
        from scenario_forge.models.capability_profile import (
            is_attacker_accessible_ingress,
        )

        ep = _make_entry_point(controllability="system")
        assert not is_attacker_accessible_ingress(ep)

    def test_output_ep_not_attacker_accessible(self):
        from scenario_forge.models.capability_profile import (
            is_attacker_accessible_ingress,
        )

        ep = _make_entry_point(direction="output", controllability="direct")
        assert not is_attacker_accessible_ingress(ep)

    def test_system_ep_no_actor_restriction_in_compute(self):
        """System EP does not restrict actors — rejected at ingress level."""
        result = compute_compatible_actor_types([], "system", "T2")
        assert result == set(CONST_ALL_ACTOR_TYPES)

    def test_output_ep_direct_still_not_accessible(self):
        """Even direct controllability output EPs are not ingress."""
        from scenario_forge.models.capability_profile import (
            is_attacker_accessible_ingress,
        )

        ep = EntryPoint(
            name="system response channel",
            direction="output",
            controllability="direct",
        )
        assert not is_attacker_accessible_ingress(ep)


# ---------------------------------------------------------------------------
# Tests: Incompatible forced diversity
# ---------------------------------------------------------------------------


class TestIncompatibleForcedDiversity:
    """Diversity must never force an incompatible actor."""

    def test_indirect_allowlist_excludes_adversarial_user(self):
        """adversarial-user cannot be forced for indirect ingress."""
        allowed = _ACTOR_ACCESS_CLASS_COMPAT["indirect"]
        assert "adversarial-user" not in allowed

    def test_indirect_allowlist_excludes_cybercriminal(self):
        allowed = _ACTOR_ACCESS_CLASS_COMPAT["indirect"]
        assert "cybercriminal" not in allowed

    def test_indirect_allowlist_excludes_hacktivist(self):
        allowed = _ACTOR_ACCESS_CLASS_COMPAT["indirect"]
        assert "hacktivist" not in allowed

    def test_direct_allowlist_includes_all(self):
        allowed = _ACTOR_ACCESS_CLASS_COMPAT["direct"]
        assert allowed == set(CONST_ALL_ACTOR_TYPES)

    def test_compute_indirect_excludes_incompatible(self):
        """compute_compatible_actor_types narrows for indirect access."""
        result = compute_compatible_actor_types([], "indirect", "T2")
        assert "adversarial-user" not in result
        assert "cybercriminal" not in result
        assert "hacktivist" not in result
        assert "negligent-insider" not in result

    def test_forced_adversarial_user_with_indirect_still_incompatible(self):
        """Even if diversity forces adversarial-user, provenance validation catches it."""
        actor = _make_actor_with_access(
            actor_type="adversarial-user",
            access_class="indirect",
            influence_source="x",
            influence_mechanism="y",
            trust_boundary="z",
        )
        violations = validate_actor_access_provenance(actor)
        rules = [v.rule for v in violations]
        assert "actor_access_class_incompatible" in rules


# ---------------------------------------------------------------------------
# Tests: Retry routing and exhaustion
# ---------------------------------------------------------------------------


class TestRetryRouting:
    """Access provenance mismatch retries Call 0 (cmps.6 retry seam)."""

    _PATCHES: ClassVar[list[str]] = [
        "scenario_forge.pipeline.generate._assemble_envelope",
        "scenario_forge.pipeline.generate._call_attack_tree",
        "scenario_forge.pipeline.generate._call_behavior_spec",
        "scenario_forge.pipeline.generate._call_narrative",
        "scenario_forge.pipeline.generate._call_actor_profile",
    ]

    def test_max_retries_constant(self):
        assert _ACTOR_ACCESS_MAX_RETRIES == 2

    def test_valid_access_no_retry(self):
        """When access provenance is valid, no retry occurs."""
        from scenario_forge.pipeline.generate import generate_scenario

        ep = _make_entry_point(controllability="direct")
        profile = _make_profile(entry_points=[ep])
        seed = _make_seed()

        actor = _make_actor_with_access(
            actor_type="cybercriminal",
            entry_point_id=ep.entry_point_id,
            access_class="direct",
        )

        llm_result = LLMResult(
            content=None, prompt_tokens=100, completion_tokens=50, duration_ms=500
        )

        with (
            patch(self._PATCHES[4], return_value=(actor, llm_result)) as mock_actor,
            patch(self._PATCHES[3], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[2], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[1], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[0], return_value=MagicMock()),
        ):
            generate_scenario(
                seed=seed,
                profile=profile,
                client=MagicMock(model="test"),
                use_case="test",
                pinned_entry_point=ep.name,
                pinned_entry_point_id=ep.entry_point_id,
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="cand:v1:11111111111111111111111111111111",
            )

        assert mock_actor.call_count == 1

    def test_missing_access_triggers_retry(self):
        """When access provenance is missing, Call 0 is retried."""
        from scenario_forge.pipeline.generate import generate_scenario

        ep = _make_entry_point(controllability="direct")
        profile = _make_profile(entry_points=[ep])
        seed = _make_seed()

        # Actor without access provenance — will trigger retry
        bad_actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        good_actor = _make_actor_with_access(
            actor_type="cybercriminal",
            entry_point_id=ep.entry_point_id,
            access_class="direct",
        )

        llm_result = LLMResult(
            content=None, prompt_tokens=100, completion_tokens=50, duration_ms=500
        )

        with (
            patch(
                self._PATCHES[4],
                side_effect=[(bad_actor, llm_result), (good_actor, llm_result)],
            ) as mock_actor,
            patch(self._PATCHES[3], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[2], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[1], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[0], return_value=MagicMock()),
        ):
            generate_scenario(
                seed=seed,
                profile=profile,
                client=MagicMock(model="test"),
                use_case="test",
                pinned_entry_point=ep.name,
                pinned_entry_point_id=ep.entry_point_id,
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="cand:v1:11111111111111111111111111111111",
            )

        assert mock_actor.call_count == 2

    def test_exhaustion_proceeds_to_quarantine(self):
        """After max retries, generation proceeds (semantic validation quarantines)."""
        from scenario_forge.pipeline.generate import generate_scenario

        ep = _make_entry_point(controllability="direct")
        profile = _make_profile(entry_points=[ep])
        seed = _make_seed()

        # Actor always missing access provenance — will exhaust retries
        bad_actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )

        llm_result = LLMResult(
            content=None, prompt_tokens=100, completion_tokens=50, duration_ms=500
        )

        with (
            patch(self._PATCHES[4], return_value=(bad_actor, llm_result)) as mock_actor,
            patch(self._PATCHES[3], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[2], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[1], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[0], return_value=MagicMock()) as mock_assemble,
        ):
            generate_scenario(
                seed=seed,
                profile=profile,
                client=MagicMock(model="test"),
                use_case="test",
                pinned_entry_point=ep.name,
                pinned_entry_point_id=ep.entry_point_id,
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="cand:v1:11111111111111111111111111111111",
            )

        # 1 initial + 2 retries = 3 calls
        assert mock_actor.call_count == 1 + _ACTOR_ACCESS_MAX_RETRIES
        # Assembly still happens — scenario proceeds to quarantine
        assert mock_assemble.called

    def test_no_retry_without_pinned_entry_point(self):
        """Access provenance retry only fires when entry point is pinned."""
        from scenario_forge.pipeline.generate import generate_scenario

        profile = _make_profile()
        seed = _make_seed()

        bad_actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )

        llm_result = LLMResult(
            content=None, prompt_tokens=100, completion_tokens=50, duration_ms=500
        )

        with (
            patch(self._PATCHES[4], return_value=(bad_actor, llm_result)) as mock_actor,
            patch(self._PATCHES[3], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[2], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[1], return_value=(MagicMock(), llm_result)),
            patch(self._PATCHES[0], return_value=MagicMock()),
        ):
            generate_scenario(
                seed=seed,
                profile=profile,
                client=MagicMock(model="test"),
                use_case="test",
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="cand:v1:11111111111111111111111111111111",
            )

        assert mock_actor.call_count == 1


# ---------------------------------------------------------------------------
# Tests: Insider actor types constant
# ---------------------------------------------------------------------------


class TestInsiderActorTypes:
    """Verify the insider actor types constant."""

    def test_contains_malicious_and_negligent(self):
        assert "malicious-insider" in _INSIDER_ACTOR_TYPES
        assert "negligent-insider" in _INSIDER_ACTOR_TYPES

    def test_does_not_contain_external(self):
        assert "adversarial-user" not in _INSIDER_ACTOR_TYPES
        assert "cybercriminal" not in _INSIDER_ACTOR_TYPES
        assert "nation-state" not in _INSIDER_ACTOR_TYPES

    def test_all_actor_types_has_nine(self):
        assert len(CONST_ALL_ACTOR_TYPES) == 9

    def test_actor_types_list_matches(self):
        assert set(ACTOR_TYPES) == set(CONST_ALL_ACTOR_TYPES)
