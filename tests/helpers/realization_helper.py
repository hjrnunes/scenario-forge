"""Shared test helper for building ProjectedStepRealization records.

Used by tests that construct NarrativeStep, BehaviorAction, AttackTreeNode,
Call1Step, or Call3Action with projected_step_ids and need valid realization
records but do not need the full projection factory chain.
"""

from __future__ import annotations

from scenario_forge.models.realization import ProjectedStepRealization


def make_realizations(
    step_ids: tuple[str, ...] | list[str],
    *,
    action_kind: str = "deliver",
    executor_role: str = "attacker",
    boundary_position: str = "crossing",
) -> tuple[ProjectedStepRealization, ...]:
    """Build minimal valid ProjectedStepRealization records for the given step IDs.

    Each field is populated with the provided values; tuple fields default
    to empty (valid for steps with no consumed/produced resources).
    """
    return tuple(
        ProjectedStepRealization(
            projected_step_id=sid,
            action_kind=action_kind,
            executor_role=executor_role,
            boundary_position=boundary_position,
            resource_ref_ids=(),
            consumed_ref_ids=(),
            produced_ref_ids=(),
            produced_effect_ids=(),
            outcome_link_pc_ids=(),
            postcondition_ids=(),
        )
        for sid in step_ids
    )
