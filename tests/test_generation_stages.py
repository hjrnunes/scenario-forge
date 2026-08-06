"""Typed single-attempt generation seam tests for cmps.5 phase 1."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import MagicMock, patch

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.scenario import CallName
from scenario_forge.pipeline.generate.stages import (
    GenerationRequest,
    PreparedGeneration,
    RetryDirective,
    generate_actor_stage,
    generate_behavior_stage,
    generate_narrative_stage,
    generate_tree_stage,
)


def _result() -> LLMResult:
    return LLMResult(
        content="fixture",
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
        system_prompt="system",
        user_prompt="user",
    )


def _prepared() -> PreparedGeneration:
    request = GenerationRequest(
        seed=cast(Any, object()),
        profile=cast(Any, object()),
        client=cast(Any, MagicMock(model="test-model")),
        use_case="test",
        pinned_entry_point_id="ep:v1:test",
        projected_candidate=cast(Any, object()),
        capability_snapshot=cast(Any, object()),
        run_id="20260101T000000_0123456789abcdef0123456789abcdef",
    )
    return PreparedGeneration(request, "cand:v2:test", "scenario:v2:test", {"x": 1})


def test_each_stage_delegates_to_exactly_one_call_primitive() -> None:
    prepared = _prepared()
    actor = cast(Any, object())
    narrative = cast(Any, object())
    tree = cast(Any, object())
    behavior = cast(Any, object())

    with (
        patch(
            "scenario_forge.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ) as call0,
        patch(
            "scenario_forge.pipeline.generate._call_narrative",
            return_value=(narrative, _result()),
        ) as call1,
        patch(
            "scenario_forge.pipeline.generate._call_attack_tree_once",
            return_value=(tree, _result()),
        ) as call2,
        patch(
            "scenario_forge.pipeline.generate._call_behavior_spec",
            return_value=(behavior, _result()),
        ) as call3,
    ):
        actor_result = generate_actor_stage(prepared)
        narrative_result = generate_narrative_stage(prepared, actor)
        tree_result = generate_tree_stage(prepared, actor, narrative)
        behavior_result = generate_behavior_stage(prepared, narrative, tree)

    assert actor_result.artifact is actor
    assert narrative_result.artifact is narrative
    assert tree_result.artifact is tree
    assert behavior_result.artifact is behavior
    assert [
        actor_result.evidence.call_name,
        narrative_result.evidence.call_name,
        tree_result.evidence.call_name,
        behavior_result.evidence.call_name,
    ] == list(CallName)
    for primitive in (call0, call1, call2, call3):
        primitive.assert_called_once()


def test_retry_directive_is_data_not_hidden_control_flow() -> None:
    prepared = _prepared()
    actor = cast(Any, object())
    with patch(
        "scenario_forge.pipeline.generate._call_actor_profile",
        return_value=(actor, _result(), "limited"),
    ) as primitive:
        result = generate_actor_stage(
            prepared,
            RetryDirective(feedback="repair evidence", forced_actor_type="external"),
        )

    primitive.assert_called_once()
    assert primitive.call_args.kwargs["access_feedback"] == "repair evidence"
    assert primitive.call_args.kwargs["forced_actor_type"] == "external"
    assert result.diversity_limitation == "limited"
