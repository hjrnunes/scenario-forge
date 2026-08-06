"""Shared test helper for building ProjectedStepRealization records.

Used by tests that construct NarrativeStep, BehaviorAction, AttackTreeNode,
Call1Step, or Call3Action with projected_step_ids and need valid realization
records but do not need the full projection factory chain.

Uses :func:`derive_step_realization` to produce canonical records with
exact opaque resource IDs — not empty tuples that would bypass the
unconditional comparison validator.
"""

from __future__ import annotations

from scenario_forge.models.realization import ProjectedStepRealization
from scenario_forge.pipeline.projection_validation import derive_step_realization


def make_realizations(
    step_ids: tuple[str, ...] | list[str],
    *,
    action_kind: str = "deliver",
    executor_role: str = "attacker",
    boundary_position: str = "crossing",
) -> tuple[ProjectedStepRealization, ...]:
    """Build canonical ProjectedStepRealization records for the given step IDs.

    For step IDs found in the test projection's embedded source chain,
    derives canonical records using :func:`derive_step_realization` so that
    all fields match the canonical step exactly — including resource_ref_ids,
    consumed/produced refs, effects, outcome links, and postconditions.

    For step IDs **not** in the test projection (synthetic IDs used by
    isolated model/zone tests that don't need projection validation),
    falls back to minimal records with the provided override values.
    The ``action_kind``, ``executor_role``, and ``boundary_position``
    keyword arguments are only used for these fallback records.
    """
    from tests.helpers.projection_factory import get_projected_candidate

    candidate = get_projected_candidate()
    chain = candidate.projection.source_chain
    step_by_id = {s.step_id: s for s in chain.steps}
    binding_by_slot = {b.slot_id: b.resource_ref for b in candidate.projection.bindings}

    records: list[ProjectedStepRealization] = []
    for sid in step_ids:
        if sid in step_by_id:
            records.append(derive_step_realization(step_by_id[sid], binding_by_slot))
        else:
            # Fallback for synthetic IDs not in the test projection.
            records.append(
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
            )
    return tuple(records)
