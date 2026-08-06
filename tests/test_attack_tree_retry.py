"""Tests for attack tree YAML generation retry logic (bead 40s).

Covers:
1. Successful parse on first attempt -- no retry.
2. Failed first attempt, successful retry -- returns the retried result.
3. Both attempts fail -- raises the original error.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.capability_profile import CapabilityProfile, EntryPoint
from scenario_forge.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
)
from scenario_forge.pipeline.generate import _call_attack_tree
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_TREE_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: LEAF
  zone: input
  action:
    kind: initial_ingress
    entry_point_id: ep:v1:52306ddb893a33ef2dc0f20c01e815f1
"""

_INVALID_YAML = "{{{{not yaml at all: ][]["


def _make_seed(seed_id: str = "AP-T2-05") -> MagicMock:
    seed = MagicMock()
    seed.seed_id = seed_id
    seed.attack_pattern_name = "Test Mechanism"
    seed.attack_pattern_description = "A test mechanism"
    seed.threat_name = "Test Threat"
    seed.threat_description = "A test threat"
    seed.atlas_technique_ids = []
    seed.owasp_llm_ids = []
    seed.agentic_threat_ids = []
    return seed


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Test narrative",
        summary="A test summary",
        entry_point="user chat interface",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft malicious input",
                effect="Input accepted",
                control_point=None,
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
        ],
    )


def _make_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(
                name="user prompts via chat interface",
                direction="input",
                controllability="direct",
            )
        ],
        kc_subcodes=["KC1.1"],
        confidence="medium",
    )


def _make_llm_result(content: str) -> LLMResult:
    return LLMResult(
        content=content,
        prompt_tokens=100,
        completion_tokens=200,
        duration_ms=500,
        system_prompt="system",
        user_prompt="user",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAttackTreeRetry:
    """Tests for retry logic in _call_attack_tree."""

    def test_success_on_first_attempt_no_retry(self) -> None:
        """When YAML parses successfully on the first try, no retry is made."""
        seed = _make_seed()
        narrative = _make_narrative()
        first_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.return_value = first_result

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        assert tree.root.id == "n1"
        assert result is first_result
        # Only one call to the LLM
        assert client.complete.call_count == 1

    def test_retry_on_first_failure_returns_retried_result(self) -> None:
        """When first attempt fails but retry succeeds, return retry result."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

        # The retry call's user prompt should mention the error
        retry_call_args = client.complete.call_args_list[1]
        retry_user_prompt = retry_call_args.kwargs.get(
            "user_prompt", retry_call_args[1] if len(retry_call_args[1]) > 1 else ""
        )
        assert "rejected" in retry_user_prompt or "not valid YAML" in retry_user_prompt

    def test_both_attempts_fail_raises_original_error(self) -> None:
        """When both attempts fail, the original error is raised."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result("also: [broken: yaml: {{")

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception) as exc_info:
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        # Should be the original error, not the retry error
        assert client.complete.call_count == 2
        # The original error is from parsing _INVALID_YAML
        assert "even after colon sanitization" in str(exc_info.value)

    def test_retry_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """A WARNING log is emitted when the first parse fails."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_INVALID_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        import logging

        with caplog.at_level(
            logging.WARNING, logger="scenario_forge.pipeline.generate"
        ):
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        assert any(
            "Attack tree first attempt failed, retrying" in record.message
            for record in caplog.records
        )


# ---------------------------------------------------------------------------
# Tests: raw generated single-child gate rejection (cmps.9 review 2.3)
# ---------------------------------------------------------------------------

_SINGLE_CHILD_AND_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: AND
  zone: input
  children:
    - id: n1.1
      label: Only child
      gate: LEAF
      zone: input
      action:
        kind: initial_ingress
        entry_point_id: ep:v1:52306ddb893a33ef2dc0f20c01e815f1
"""

_SINGLE_CHILD_OR_YAML = """\
id: tree-AP-T2-05
seed_id: AP-T2-05
goal: Compromise the target system
root:
  id: n1
  label: Root attack node
  gate: OR
  zone: input
  children:
    - id: n1.1
      label: Only child
      gate: LEAF
      zone: input
      action:
        kind: initial_ingress
        entry_point_id: ep:v1:52306ddb893a33ef2dc0f20c01e815f1
"""


class TestSingleChildGateRejection:
    """Raw generated single-child AND/OR gates must be rejected/retried,
    not silently repaired (cmps.9 second review correction 3).

    _parse_attack_tree_yaml must NOT call repair_attack_tree_dict before
    Pydantic validation.  Malformed gates must fail model validation so
    the caller retries or rejects — no silent structural mutation.
    """

    def test_single_child_and_rejected_and_retried(self) -> None:
        """A single-child AND gate is rejected on first attempt and retried."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_SINGLE_CHILD_AND_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        # Retry succeeded with the valid tree
        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

    def test_single_child_or_rejected_and_retried(self) -> None:
        """A single-child OR gate is rejected on first attempt and retried."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_SINGLE_CHILD_OR_YAML)
        retry_result = _make_llm_result(_VALID_TREE_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=_make_profile(),
            pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
        )

        # Retry succeeded with the valid tree
        assert tree.root.id == "n1"
        assert result is retry_result
        assert client.complete.call_count == 2

    def test_single_child_and_both_attempts_fail_raises(self) -> None:
        """When both attempts produce single-child gates, the error is raised."""
        seed = _make_seed()
        narrative = _make_narrative()

        first_result = _make_llm_result(_SINGLE_CHILD_AND_YAML)
        retry_result = _make_llm_result(_SINGLE_CHILD_OR_YAML)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception, match="single.child|children"):
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=_make_profile(),
                pinned_entry_point_id="ep:v1:52306ddb893a33ef2dc0f20c01e815f1",
            )

        assert client.complete.call_count == 2

    def test_single_child_gate_not_mutated(self) -> None:
        """The raw dict is not mutated by repair before validation."""
        from scenario_forge.pipeline.generate.tree import _parse_attack_tree_yaml

        # _parse_attack_tree_yaml should raise on single-child gate
        with pytest.raises(Exception, match="single.child|children"):
            _parse_attack_tree_yaml(
                _SINGLE_CHILD_AND_YAML,
                MagicMock(seed_id="AP-T2-05"),
            )


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #2: Projection validation participates in retry
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# 422o.4 Review blocker #2: Projection validation participates in retry
# ---------------------------------------------------------------------------#


class TestCall2ProjectionRetry:
    """Call 2 retry must fire on projection validation failures, not only
    YAML parse errors.  The original projection-rich user prompt must
    survive the retry, with feedback appended only.
    """

    @staticmethod
    def _make_projection_context() -> dict:
        from scenario_forge.pipeline.generate.assembly import _build_projection_context
        from tests.helpers.projection_factory import get_projected_candidate

        candidate = get_projected_candidate()
        return _build_projection_context(candidate)

    @staticmethod
    def _get_ingress_id() -> str:
        from tests.helpers.projection_factory import get_projected_candidate

        return get_projected_candidate().canonical_ingress.entry_point_id

    @staticmethod
    def _make_profile():
        from tests.helpers.projection_factory import get_test_profile

        return get_test_profile()

    @staticmethod
    def _make_valid_tree_yaml(ctx: dict) -> str:
        """Build a YAML tree that passes both parse and projection validation."""
        import yaml as _yaml

        from scenario_forge.models.attack_tree import (
            AiSystemAction,
            AttackTree,
            AttackTreeNode,
            GateType,
            ImpactAction,
            InitialIngressAction,
        )
        from tests.helpers.projection_factory import (
            get_projected_candidate,
            make_step_realizations,
        )

        candidate = get_projected_candidate()
        ingress_id = candidate.canonical_ingress.entry_point_id
        selected = candidate.projection.selected_step_ids

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                        projected_step_ids=(selected[0],),
                        realizations=make_step_realizations((selected[0],)),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="Observe",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                        projected_step_ids=(selected[1],),
                        realizations=make_step_realizations((selected[1],)),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="Impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                        projected_step_ids=(selected[2],),
                        realizations=make_step_realizations((selected[2],)),
                    ),
                ],
            ),
        )
        data = tree.model_dump(mode="json")
        return _yaml.dump(data, default_flow_style=False, sort_keys=False)

    def _make_projectionless_tree_yaml(self) -> str:
        """A valid YAML tree with a security leaf missing projected_step_ids."""
        ingress_id = self._get_ingress_id()
        return (
            "id: tree-AP-T1-01\n"
            "seed_id: AP-T1-01\n"
            "goal: test\n"
            "root:\n"
            "  id: n1\n"
            "  label: Root\n"
            "  gate: AND\n"
            "  children:\n"
            "    - id: n1.1\n"
            "      label: Ingress\n"
            "      gate: LEAF\n"
            "      zone: input\n"
            "      action:\n"
            f"        kind: initial_ingress\n"
            f"        entry_point_id: {ingress_id}\n"
            "    - id: n1.2\n"
            "      label: No projection\n"
            "      gate: LEAF\n"
            "      zone: reasoning\n"
            "      action:\n"
            "        kind: ai_system_action\n"
        )

    def test_projection_invalid_first_response_triggers_retry(self) -> None:
        """A syntactically valid but projection-invalid first response
        triggers the retry, and the retry with valid output succeeds."""
        ctx = self._make_projection_context()
        valid_yaml = self._make_valid_tree_yaml(ctx)
        projectionless_yaml = self._make_projectionless_tree_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(projectionless_yaml)
        retry_result = _make_llm_result(valid_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        tree, result = _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=self._make_profile(),
            pinned_entry_point_id=ingress_id,
            projection_context=ctx,
        )

        # Retry was used
        assert client.complete.call_count == 2
        assert result is retry_result
        # Tree from retry output
        assert tree.root.id == "n1"

    def test_retry_preserves_full_projection_context(self) -> None:
        """The retry user prompt must contain the original projection
        digest, selected step IDs, bindings/resource refs, conditions/
        evidence, and original context — not just parse feedback."""
        ctx = self._make_projection_context()
        valid_yaml = self._make_valid_tree_yaml(ctx)
        projectionless_yaml = self._make_projectionless_tree_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(projectionless_yaml)
        retry_result = _make_llm_result(valid_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        _call_attack_tree(
            seed=seed,
            narrative=narrative,
            client=client,
            use_case="A test use case",
            profile=self._make_profile(),
            pinned_entry_point_id=ingress_id,
            projection_context=ctx,
        )

        assert client.complete.call_count == 2
        retry_call = client.complete.call_args_list[1]
        retry_prompt = retry_call.kwargs.get("user_prompt", "")

        # Original projection context survives in the retry prompt
        assert ctx["projection_digest"] in retry_prompt
        assert "step.1" in retry_prompt
        # Bindings / resource refs present
        assert any(b["slot_id"] in retry_prompt for b in ctx["bindings"]), (
            "Retry prompt should contain binding slot IDs"
        )
        # Feedback appended (not replacing original prompt)
        assert "Feedback" in retry_prompt

    def test_both_projection_invalid_raises(self) -> None:
        """When both outputs are projection-invalid, the first error is raised."""
        ctx = self._make_projection_context()
        projectionless_yaml = self._make_projectionless_tree_yaml()
        ingress_id = self._get_ingress_id()

        seed = _make_seed("AP-T1-01")
        narrative = _make_narrative()

        first_result = _make_llm_result(projectionless_yaml)
        retry_result = _make_llm_result(projectionless_yaml)

        client = MagicMock()
        client.complete.side_effect = [first_result, retry_result]

        with pytest.raises(Exception) as exc_info:
            _call_attack_tree(
                seed=seed,
                narrative=narrative,
                client=client,
                use_case="A test use case",
                profile=self._make_profile(),
                pinned_entry_point_id=ingress_id,
                projection_context=ctx,
            )

        assert client.complete.call_count == 2
        # Should be the original projection validation error
        assert "no projected_step_ids" in str(exc_info.value)
