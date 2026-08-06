"""Per-projected-step canonical realization record.

Shared by :mod:`scenario_forge.models.scenario` (NarrativeStep,
BehaviorAction) and :mod:`scenario_forge.models.attack_tree`
(AttackTreeNode) so that all three generated artifact boundaries carry
the same typed canonical semantics for validation to reconcile against
the embedded :class:`~scenario_forge.models.projection_envelope.ProjectionEnvelopeBlock`.

Pre-alpha: all fields are required (no defaults).  A field may be an
empty tuple when the canonical step genuinely has no entries of that
kind, but the field must be present and explicitly provided.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ProjectedStepRealization(BaseModel):
    """Per-projected-step canonical realization record on generated elements.

    Carries the canonical step semantics that validation reconciles
    against the embedded projection block.  Prose may explain but cannot
    be the authority -- these typed fields are the authority.

    One record per ``projected_step_id``, supporting controlled
    many-to-many realization (a generated element may carry multiple
    records when it combines multiple projected steps; a projected step
    may be realized by multiple elements when it is split).
    """

    model_config = ConfigDict(extra="forbid")

    projected_step_id: str = Field(
        min_length=1,
        description="Canonical projected step ID this record realizes.",
    )
    action_kind: str = Field(
        min_length=1,
        description=(
            "Canonical action kind from the projected step (prepare, deliver, "
            "invoke, transform, persist, observe, impact)."
        ),
    )
    executor_role: str = Field(
        min_length=1,
        description="Canonical executor role from the projected step (attacker, system, operator).",
    )
    boundary_position: str = Field(
        min_length=1,
        description="Canonical boundary position from the projected step (outside, crossing, inside).",
    )
    resource_ref_ids: tuple[str, ...] = Field(
        description="Concrete resource reference IDs for this step's resource_links.",
    )
    consumed_ref_ids: tuple[str, ...] = Field(
        description="Consumed reference IDs (must match step.consumed[*].ref_id).",
    )
    produced_ref_ids: tuple[str, ...] = Field(
        description="Produced reference IDs (must match step.produced[*].ref_id).",
    )
    produced_effect_ids: tuple[str, ...] = Field(
        description="Produced effect IDs (subset of produced where kind == 'effect').",
    )
    outcome_link_pc_ids: tuple[str, ...] = Field(
        description="Observable outcome link postcondition IDs.",
    )
    postcondition_ids: tuple[str, ...] = Field(
        description="Owned observable postcondition IDs.",
    )
