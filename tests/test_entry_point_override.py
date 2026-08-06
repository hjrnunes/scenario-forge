"""Tests for the post-Call-1 entry_point override in generate_scenario.

When pinned_entry_point is set and the narrative's entry_point diverges,
the assembly code must override it by construction.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from scenario_forge.models.projection_envelope import ProjectionTraceabilityResult
from scenario_forge.models.scenario import (
    ActorProfile,
    NarrativeLayer,
    NarrativeStep,
)
from scenario_forge.pipeline.generate import generate_scenario
from scenario_forge.pipeline.seeds import RiskCardRef, ScenarioSeed
from tests.helpers.projection_factory import get_projected_candidate, get_test_snapshot

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_seed(**overrides) -> ScenarioSeed:
    defaults = {
        "seed_id": "AP-T7-01",
        "threat_id": "T7",
        "threat_name": "Misaligned Behaviors",
        "attack_pattern_name": "Misaligned pattern",
        "attack_pattern_description": "desc",
        "owasp_origin": "LLM09",
        "risk_card_ref": RiskCardRef(
            risk_id="R-01",
            risk_name="Test risk",
            risk_description="Description for R-01",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        "owasp_llm_ids": ["LLM09"],
        "agentic_threat_ids": ["T7"],
        "atlas_technique_ids": ["AML.T0054"],
    }
    defaults.update(overrides)
    return ScenarioSeed(**defaults)


def _make_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user prompts (input)", "api inputs (input)"],
        kc_subcodes=["KC1.1"],
        confidence=ConfidenceLevel.high,
    )


def _make_actor() -> ActorProfile:
    return ActorProfile(
        actor_type="adversarial-user",
        capability_level="intermediate",
        beliefs=["The system processes user input."],
        desires=["I want to manipulate output."],
        intentions=["I will craft adversarial prompts."],
        resources=["Prompt injection toolkit"],
    )


def _make_narrative(entry_point: str = "user prompts (input)") -> NarrativeLayer:
    return NarrativeLayer(
        title="Test scenario",
        summary="A test attack narrative.",
        entry_point=entry_point,
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft adversarial prompt",
                effect="Prompt enters system",
                projected_step_ids=("step.1",),
                canonical_action_kind="prepare",
                canonical_executor_role="attacker",
                canonical_boundary_position="crossing",
            ),
        ],
    )


def _make_llm_result(content) -> LLMResult:
    return LLMResult(
        content=content,
        system_prompt="sys",
        user_prompt="usr",
        prompt_tokens=10,
        completion_tokens=10,
        duration_ms=100,
    )


def _make_mock_client() -> MagicMock:
    client = MagicMock()
    client.model = "test-model"
    return client


def _make_tree_mock():
    """Create a mock attack tree with proper root structure."""
    root = MagicMock()
    root.maestro_layer = 3
    root.children = None
    root.threat_id = "T7"
    root.structural_exposure = None
    tree = MagicMock()
    tree.root = root
    tree.collect_technique_ids.return_value = {"AML.T0054"}
    return tree


# Common patch targets
_PATCHES = [
    "scenario_forge.pipeline.generate._assemble_envelope",
    "scenario_forge.pipeline.generate._call_behavior_spec",
    "scenario_forge.pipeline.generate._call_attack_tree",
    "scenario_forge.pipeline.generate._call_narrative",
    "scenario_forge.pipeline.generate._validate_actor_type",
    "scenario_forge.pipeline.generate._call_actor_profile",
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@patch(
    "scenario_forge.pipeline.projection_validation.validate_projection_traceability",
    new=MagicMock(return_value=ProjectionTraceabilityResult(valid=True, violations=[])),
)
class TestEntryPointOverride:
    """The generate_scenario function must pin entry_point by construction.

    These tests mock _assemble_envelope (returning a MagicMock) to isolate
    entry-point override behaviour from Pydantic model assembly.  Because
    the production path now runs projection traceability validation on the
    assembled envelope, the validator is patched to return valid here —
    traceability enforcement is covered by the dedicated traceability suite.
    """

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    @patch(_PATCHES[5])
    def test_narrative_entry_point_not_overridden_on_candidate_v2(
        self,
        mock_call_actor,
        mock_validate,
        mock_call_narrative,
        mock_call_tree,
        mock_call_spec,
        mock_assemble,
    ):
        """On candidate-v2 paths, entry-point overwrite is semantic repair
        and is prohibited (422o.4).  The mismatch is logged, not silently
        fixed."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()
        actor = _make_actor()
        pinned_ep = "api inputs (input)"

        # Narrative returns with WRONG entry point (diverges from pinned)
        wrong_narrative = _make_narrative(entry_point="user prompts (input)")
        tree_mock = _make_tree_mock()

        mock_call_actor.return_value = (actor, _make_llm_result(actor), None)
        mock_validate.return_value = actor
        mock_call_narrative.return_value = (
            wrong_narrative,
            _make_llm_result(wrong_narrative),
        )
        mock_call_tree.return_value = (tree_mock, _make_llm_result("tree"))
        mock_call_spec.return_value = ("Feature: test", _make_llm_result("spec"))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test use case",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20240101T120000_abcdef1234567890abcdef1234567890",
            candidate_id="",
            pinned_entry_point=pinned_ep,
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

        # On candidate-v2 paths, entry-point overwrite is NOT performed.
        # The narrative retains its original (divergent) entry point.
        call2_args = mock_call_tree.call_args
        narrative_arg = call2_args[0][1]  # second positional arg is narrative
        assert narrative_arg.entry_point == "user prompts (input)"

        # The narrative passed to _assemble_envelope also retains original ep.
        assemble_kwargs = mock_assemble.call_args[1]
        assert assemble_kwargs["narrative"].entry_point == "user prompts (input)"

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    @patch(_PATCHES[5])
    def test_narrative_entry_point_unchanged_when_matches(
        self,
        mock_call_actor,
        mock_validate,
        mock_call_narrative,
        mock_call_tree,
        mock_call_spec,
        mock_assemble,
    ):
        """When narrative.entry_point == pinned_entry_point, no override."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()
        actor = _make_actor()
        pinned_ep = "user prompts (input)"

        correct_narrative = _make_narrative(entry_point=pinned_ep)
        tree_mock = _make_tree_mock()

        mock_call_actor.return_value = (actor, _make_llm_result(actor), None)
        mock_validate.return_value = actor
        mock_call_narrative.return_value = (
            correct_narrative,
            _make_llm_result(correct_narrative),
        )
        mock_call_tree.return_value = (tree_mock, _make_llm_result("tree"))
        mock_call_spec.return_value = ("Feature: test", _make_llm_result("spec"))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test use case",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20240101T120000_abcdef1234567890abcdef1234567890",
            candidate_id="",
            pinned_entry_point=pinned_ep,
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

        # Narrative should retain original entry point (no override)
        assemble_kwargs = mock_assemble.call_args[1]
        assert assemble_kwargs["narrative"].entry_point == pinned_ep

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    @patch(_PATCHES[5])
    def test_no_override_when_pinned_entry_point_is_none(
        self,
        mock_call_actor,
        mock_validate,
        mock_call_narrative,
        mock_call_tree,
        mock_call_spec,
        mock_assemble,
    ):
        """When pinned_entry_point is None, entry_point is not touched."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()
        actor = _make_actor()

        original_ep = "user prompts (input)"
        narrative = _make_narrative(entry_point=original_ep)
        tree_mock = _make_tree_mock()

        mock_call_actor.return_value = (actor, _make_llm_result(actor), None)
        mock_validate.return_value = actor
        mock_call_narrative.return_value = (
            narrative,
            _make_llm_result(narrative),
        )
        mock_call_tree.return_value = (tree_mock, _make_llm_result("tree"))
        mock_call_spec.return_value = ("Feature: test", _make_llm_result("spec"))
        mock_assemble.return_value = MagicMock()

        generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test use case",
            pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            run_id="20240101T120000_abcdef1234567890abcdef1234567890",
            candidate_id="",
            pinned_entry_point=None,
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

        assemble_kwargs = mock_assemble.call_args[1]
        assert assemble_kwargs["narrative"].entry_point == original_ep

    def test_narrative_model_copy_preserves_other_fields(self):
        """model_copy(update=...) must preserve all other NarrativeLayer fields."""
        narrative = _make_narrative(entry_point="original ep")
        updated = narrative.model_copy(update={"entry_point": "new ep"})

        assert updated.entry_point == "new ep"
        assert updated.title == narrative.title
        assert updated.summary == narrative.summary
        assert updated.zone_sequence == narrative.zone_sequence
        assert updated.steps == narrative.steps

    @patch(_PATCHES[0])
    @patch(_PATCHES[1])
    @patch(_PATCHES[2])
    @patch(_PATCHES[3])
    @patch(_PATCHES[4])
    @patch(_PATCHES[5])
    def test_override_logged(
        self,
        mock_call_actor,
        mock_validate,
        mock_call_narrative,
        mock_call_tree,
        mock_call_spec,
        mock_assemble,
        caplog,
    ):
        """Entry-point override should emit an INFO log."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()
        actor = _make_actor()
        pinned_ep = "api inputs (input)"

        wrong_narrative = _make_narrative(entry_point="user prompts (input)")
        tree_mock = _make_tree_mock()

        mock_call_actor.return_value = (actor, _make_llm_result(actor), None)
        mock_validate.return_value = actor
        mock_call_narrative.return_value = (
            wrong_narrative,
            _make_llm_result(wrong_narrative),
        )
        mock_call_tree.return_value = (tree_mock, _make_llm_result("tree"))
        mock_call_spec.return_value = ("Feature: test", _make_llm_result("spec"))
        mock_assemble.return_value = MagicMock()

        with caplog.at_level(logging.INFO):
            generate_scenario(
                seed=seed,
                profile=profile,
                client=client,
                use_case="Test use case",
                pinned_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="",
                pinned_entry_point=pinned_ep,
                projected_candidate=get_projected_candidate(),
                capability_snapshot=get_test_snapshot(),
            )

        assert any("not overwriting on candidate-v2 path" in m for m in caplog.messages)
