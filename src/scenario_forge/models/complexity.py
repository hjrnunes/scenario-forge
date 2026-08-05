"""Closed, versioned attack-complexity assessment models (cmps.7).

This module separates two concepts that legacy generation conflated:

- **Actor capability** (``ActorProfile.capability_level``) — an immutable
  attribute of the generated threat actor, fixed at Call 0 and never
  relabelled afterwards to save a generated attack.
- **Attack complexity** — a deterministic, versioned assessment of the
  capability level an attack path *requires*, derived only from typed
  candidate-v2 projection inputs and typed realized action/access
  evidence.

The assessment is persisted separately from the actor profile so reports
and metrics can show actor capability and attack complexity distinctly.

Deliberately unsupported in rule version ``1`` (no typed, unambiguous
representation exists; do not invent heuristics for these):

- privileged access prerequisites at the *candidate* phase (chain
  preconditions are generic fact ASTs without a closed fact registry);
- supply-chain/training targeting at the *candidate* phase (typed only
  via realized ``ActorAccessProvenance.access_class``);
- custom exploit/code requirements (no typed field exists in the
  candidate-v2 or realized-action models);
- the ``expert`` required level (reserved for future typed evidence).

Zone counts, technique tuples, generated prose, free-text keyword
matching, and labels are never authoritative inputs.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Capability level scale (shared with ActorProfile.capability_level)
# ---------------------------------------------------------------------------

CapabilityLevel = Literal["novice", "intermediate", "advanced", "expert"]

CAPABILITY_LEVEL_ORDER: tuple[CapabilityLevel, ...] = (
    "novice",
    "intermediate",
    "advanced",
    "expert",
)
"""Canonical ascending ordering of capability levels (novice < expert)."""


def capability_level_rank(level: CapabilityLevel) -> int:
    """Return the ordinal rank of a capability level (novice=0 .. expert=3)."""
    return CAPABILITY_LEVEL_ORDER.index(level)


COMPLEXITY_RULE_VERSION: Literal["1"] = "1"
"""Closed version of the deterministic reviewed complexity rule table."""

AssessmentPhase = Literal["candidate_lower_bound", "final"]


# ---------------------------------------------------------------------------
# Reason and evidence records
# ---------------------------------------------------------------------------


class ComplexityModel(BaseModel):
    """Common closed, immutable configuration for assessment records."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ComplexityEvidenceReference(ComplexityModel):
    """Typed pointer to the exact structured input that fired a rule."""

    kind: Literal[
        "chain_step",
        "execution_requirement",
        "leaf_action",
        "actor_access_provenance",
    ] = Field(description="Which typed input surface the reference points at.")
    ref_id: str = Field(
        min_length=1,
        description=(
            "Stable identifier of the referenced input: canonical chain "
            "step_id, execution requirement_id, attack-tree node id, or the "
            "access-provenance initial_entry_point_id."
        ),
    )


ComplexityRuleId = Literal[
    # Candidate phase (ProjectedCandidate typed inputs).
    "chain.multi_step_attacker_control",
    "chain.deep_attacker_control",
    "access.upstream_source_influence",
    "tool.state_changing_fixture",
    # Final phase (typed realized actions and access provenance).
    "action.external_precondition",
    "access.indirect_influence_path",
    "access.privileged_prerequisite",
    "access.supply_chain_targeting",
]
"""Closed set of stable rule identifiers in rule-table version ``1``."""


class ComplexityReason(ComplexityModel):
    """One typed reason record explaining a required-level trigger."""

    rule_id: ComplexityRuleId = Field(description="Stable rule identifier.")
    required_level: CapabilityLevel = Field(
        description="Capability level this rule requires when it fires."
    )
    detail: str = Field(
        min_length=1,
        description=(
            "Structured explanation of the trigger, including observed "
            "values (e.g. step counts) so the reason stands alone."
        ),
    )
    evidence: tuple[ComplexityEvidenceReference, ...] = Field(
        min_length=1,
        description="Typed references to the exact inputs that fired the rule.",
    )


class ComplexityPhaseAssessment(ComplexityModel):
    """Assessment of one phase: candidate lower bound or final."""

    phase: AssessmentPhase
    required_level: CapabilityLevel
    reasons: tuple[ComplexityReason, ...] = Field(
        description=(
            "Reasons that fired in this phase, ordered deterministically "
            "by descending required level then ascending rule_id, deduplicated "
            "by rule_id. Empty when the phase assesses as novice."
        ),
    )

    @model_validator(mode="after")
    def deterministic_reason_order(self) -> ComplexityPhaseAssessment:
        rule_ids = [reason.rule_id for reason in self.reasons]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("complexity reasons must be unique by rule_id")
        ordered = sorted(
            self.reasons,
            key=lambda r: (-capability_level_rank(r.required_level), r.rule_id),
        )
        if list(self.reasons) != ordered:
            raise ValueError(
                "complexity reasons must be ordered by descending required "
                "level then ascending rule_id"
            )
        if self.reasons:
            top = capability_level_rank(self.reasons[0].required_level)
            if capability_level_rank(self.required_level) != top:
                raise ValueError(
                    "phase required_level must equal the highest reason level"
                )
        elif self.required_level != "novice":
            raise ValueError("a reasonless phase assessment must be novice")
        return self


class AttackComplexityAssessment(ComplexityModel):
    """Closed, versioned attack-complexity assessment record.

    Carries the candidate lower bound (computed before Call 0 from typed
    candidate-v2 projection inputs) and, once typed realized actions
    exist, the final required level.  Persisted separately from the
    immutable actor capability.
    """

    rule_version: Literal["1"] = Field(
        description="Closed version of the deterministic rule table used."
    )
    candidate_lower_bound: ComplexityPhaseAssessment = Field(
        description=(
            "Lower bound on actor capability computed from typed "
            "candidate-v2 projection inputs before Call 0."
        ),
    )
    final: ComplexityPhaseAssessment | None = Field(
        default=None,
        description=(
            "Final required level computed after typed realized actions "
            "exist; inherits the candidate lower bound and may only raise it."
        ),
    )

    @model_validator(mode="after")
    def coherent_phases(self) -> AttackComplexityAssessment:
        if self.candidate_lower_bound.phase != "candidate_lower_bound":
            raise ValueError(
                "candidate_lower_bound slot must carry a candidate_lower_bound "
                "phase assessment"
            )
        if self.final is not None:
            if self.final.phase != "final":
                raise ValueError("final slot must carry a final phase assessment")
            if capability_level_rank(self.final.required_level) < capability_level_rank(
                self.candidate_lower_bound.required_level
            ):
                raise ValueError(
                    "final required level cannot be below the candidate lower "
                    "bound for the same realized scenario"
                )
        return self


# ---------------------------------------------------------------------------
# Admission contract (fail-closed, typed routing)
# ---------------------------------------------------------------------------


class ComplexityAdmissionRouting(ComplexityModel):
    """Typed routing data for a capability/attack-complexity mismatch.

    Identifies the earliest responsible stage and the action that stage
    must take through its existing bounded mechanism.  cmps.7 exposes
    this contract only; wiring into the Call 0 retry loop and the
    post-realization quarantine partition is owned by cmps.5.
    """

    stage: Literal["call0_actor_generation", "post_realization_validation"] = Field(
        description="Earliest lifecycle stage responsible for handling."
    )
    action: Literal[
        "regenerate_actor_with_higher_capability", "quarantine_scenario"
    ] = Field(
        description=(
            "Bounded action the owning stage must take: regenerate the "
            "actor through the existing Call 0 retry loop, or quarantine "
            "the scenario through semantic validation."
        ),
    )
    feedback: str = Field(
        min_length=1,
        description=(
            "Explicit reason text the owning stage can surface as retry "
            "feedback or quarantine evidence, including the required level."
        ),
    )


class CapabilityAdmissionViolation(ComplexityModel):
    """Typed violation produced when the admission invariant fails.

    The invariant is: actor capability >= attack required level.  The
    check is fail-closed: requesting admission against an assessment
    phase that has not been computed is itself a violation.
    """

    rule_id: Literal[
        "actor_capability_below_attack_complexity",
        "complexity_assessment_phase_unavailable",
    ]
    phase: AssessmentPhase = Field(
        description="Assessment phase the admission check ran against."
    )
    rule_version: Literal["1"]
    actor_capability_level: CapabilityLevel = Field(
        description="Immutable actor capability level that was checked."
    )
    required_level: CapabilityLevel | None = Field(
        description=(
            "Required level the actor fell below; ``None`` only when the "
            "requested assessment phase was unavailable (fail-closed)."
        ),
    )
    triggering_reasons: tuple[ComplexityReason, ...] = Field(
        description=(
            "Reasons that establish the required level; empty only when "
            "the requested assessment phase was unavailable."
        ),
    )
    routing: ComplexityAdmissionRouting

    @model_validator(mode="after")
    def coherent_violation(self) -> CapabilityAdmissionViolation:
        below = self.rule_id == "actor_capability_below_attack_complexity"
        if below and self.required_level is None:
            raise ValueError("below-complexity violations require a required_level")
        if below and not self.triggering_reasons:
            raise ValueError("below-complexity violations require reasons")
        if below and capability_level_rank(
            self.actor_capability_level
        ) >= capability_level_rank(self.required_level):  # type: ignore[arg-type]
            raise ValueError(
                "below-complexity violation requires actor level strictly "
                "below the required level"
            )
        if not below and self.required_level is not None:
            raise ValueError(
                "phase-unavailable violations must not carry a required_level"
            )
        if not below and self.triggering_reasons:
            raise ValueError(
                "phase-unavailable violations must not carry triggering reasons"
            )
        return self


class CapabilityAdmissionDecision(ComplexityModel):
    """Result of the fail-closed admission invariant check."""

    admitted: bool
    violation: CapabilityAdmissionViolation | None = None

    @model_validator(mode="after")
    def coherent_decision(self) -> CapabilityAdmissionDecision:
        if self.admitted != (self.violation is None):
            raise ValueError("admitted iff there is no violation")
        return self
