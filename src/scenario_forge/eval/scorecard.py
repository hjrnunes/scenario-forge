"""Strict v1 scorecard contract and non-vacuous metric helpers."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator

SCORECARD_SCHEMA_VERSION = "1"
METRIC_DEFINITION_VERSION = "1"

# Canonical qualification membership. Keeping this in the schema module lets
# validation reconstruct the aggregate without trusting serialized counts or
# IDs supplied by a producer.
QUALIFICATION_GATE_PATHS: dict[str, tuple[str, str]] = {
    "nonempty_admitted_inventory": (
        "presence_coverage",
        "nonempty_admitted_inventory",
    ),
    "inventory_count_coherence": (
        "presence_coverage",
        "manifest_evaluated_count_coherence",
    ),
    "inventory_pair_coherence": (
        "presence_coverage",
        "manifest_pair_coherence",
    ),
    "scenario_schema_validity": ("validity_grounding", "scenario_schema_validity"),
    "known_entry_point_identity": (
        "presence_coverage",
        "unknown_entry_point_count",
    ),
    "zero_stale_orphan": (
        "presence_coverage",
        "stale_or_orphan_artifact_count",
    ),
    "zero_missing_pairs": ("presence_coverage", "missing_pair_count"),
    "zero_duplicate_overwritten": (
        "presence_coverage",
        "duplicate_or_overwritten_artifact_count",
    ),
    "zero_unmanifested": (
        "presence_coverage",
        "unmanifested_artifact_count",
    ),
    "projected_step_recall": (
        "cross_artifact_agreement",
        "projected_step_recall",
    ),
    "pinned_technique_recall": (
        "cross_artifact_agreement",
        "pinned_technique_recall",
    ),
    "tree_behavior_correspondence": (
        "cross_artifact_agreement",
        "exact_tree_behavior_correspondence",
    ),
    "exact_title_duplicates": (
        "semantic_quality_diagnostics",
        "exact_normalized_title_duplicate_count",
    ),
    "zero_quarantine": ("release_qualification", "zero_quarantine"),
    "persisted_admission_traceability": (
        "release_qualification",
        "persisted_admission_traceability_outcome",
    ),
    "actor_attack_complexity": ("release_qualification", "actor_attack_complexity"),
    "capability_grounding": ("release_qualification", "capability_grounding"),
    "tool_integration_grounding": (
        "release_qualification",
        "tool_integration_grounding",
    ),
    "data_access_grounding": ("release_qualification", "data_access_grounding"),
    "catalog_taxonomy_pin_validity": (
        "release_qualification",
        "catalog_taxonomy_pin_validity",
    ),
    "resource_binding_validity": (
        "release_qualification",
        "resource_binding_validity",
    ),
    "execution_requirement_drift": (
        "release_qualification",
        "execution_requirement_drift",
    ),
    "schema_identifier_phantom_parsimony": (
        "release_qualification",
        "zero_schema_identifier_phantom_parsimony_failures",
    ),
}

REQUIRED_QUALIFICATION_GATE_IDS: frozenset[str] = frozenset(
    {
        "nonempty_admitted_inventory",
        "inventory_count_coherence",
        "inventory_pair_coherence",
        "scenario_schema_validity",
        "known_entry_point_identity",
        "zero_stale_orphan",
        "zero_missing_pairs",
        "zero_duplicate_overwritten",
        "zero_unmanifested",
        "projected_step_recall",
        "pinned_technique_recall",
        "tree_behavior_correspondence",
        "exact_title_duplicates",
        "zero_quarantine",
        "persisted_admission_traceability",
    }
)

QUALIFICATION_RATIO_GATE_IDS: frozenset[str] = frozenset(
    {
        "scenario_schema_validity",
        "projected_step_recall",
        "pinned_technique_recall",
        "tree_behavior_correspondence",
        "actor_attack_complexity",
        "capability_grounding",
        "tool_integration_grounding",
        "data_access_grounding",
        "catalog_taxonomy_pin_validity",
        "resource_binding_validity",
        "execution_requirement_drift",
        "schema_identifier_phantom_parsimony",
    }
)

UNSUPPORTED_QUALIFICATION_GATE_IDS: frozenset[str] = frozenset()

QUALIFICATION_ZERO_GATE_IDS: frozenset[str] = (
    frozenset(QUALIFICATION_GATE_PATHS)
    - QUALIFICATION_RATIO_GATE_IDS
    - UNSUPPORTED_QUALIFICATION_GATE_IDS
)


class MetricStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class MetricResult(BaseModel):
    """One typed metric observation.

    ``value`` is always a bounded ratio. Counts are represented by numerator
    (and denominator when they are rates), never overloaded into ``value``.
    """

    model_config = {"extra": "forbid", "use_enum_values": False}

    status: MetricStatus
    definition_version: Literal["1"] = METRIC_DEFINITION_VERSION
    threshold: float | None = Field(default=None, ge=0, le=1)
    numerator: int | None = Field(default=None, ge=0)
    denominator: int | None = Field(default=None, ge=0)
    value: float | None = Field(default=None, ge=0, le=1)
    evidence: list[str]
    affected_ids: list[str]

    @model_validator(mode="after")
    def _non_vacuous(self) -> MetricResult:
        if self.denominator == 0:
            if self.status is not MetricStatus.NOT_APPLICABLE or self.value is not None:
                raise ValueError(
                    "zero denominator must be not_applicable with no value"
                )
        if self.value is not None:
            if (
                self.denominator is None
                or self.denominator == 0
                or self.numerator is None
            ):
                raise ValueError(
                    "bounded values require a nonzero denominator and numerator"
                )
            expected = self.numerator / self.denominator
            if self.value != expected:
                raise ValueError("value must equal numerator / denominator")
            if self.threshold is not None:
                meets_threshold = self.value >= self.threshold
                if self.status is MetricStatus.PASS and not meets_threshold:
                    raise ValueError("pass metric is below threshold")
                if self.status is MetricStatus.FAIL and meets_threshold:
                    raise ValueError("fail metric is at or above threshold")
        if self.status is MetricStatus.ERROR and self.value is not None:
            raise ValueError("error metrics cannot claim a value")
        return self


class MetricSection(BaseModel):
    model_config = {"extra": "forbid"}
    metrics: dict[str, MetricResult]


class QualificationResult(BaseModel):
    model_config = {"extra": "forbid", "use_enum_values": False}
    status: MetricStatus
    applicable_gate_count: int = Field(ge=0)
    passed_gate_count: int = Field(ge=0)
    failed_gate_ids: list[str]
    error_gate_ids: list[str]
    not_applicable_gate_ids: list[str]
    blocking_not_applicable_gate_ids: list[str]

    @model_validator(mode="after")
    def _aggregate(self) -> QualificationResult:
        if self.passed_gate_count > self.applicable_gate_count:
            raise ValueError("passed gates cannot exceed applicable gates")
        expected = (
            MetricStatus.ERROR
            if self.error_gate_ids
            else MetricStatus.FAIL
            if self.failed_gate_ids or self.blocking_not_applicable_gate_ids
            else MetricStatus.PASS
        )
        if self.status is not expected:
            raise ValueError("qualification status does not match gate outcomes")
        return self


class ScorecardV1(BaseModel):
    """Versioned evaluation scorecard with intentionally separate lenses."""

    model_config = {"extra": "forbid"}

    schema_version: Literal["1"] = SCORECARD_SCHEMA_VERSION
    manifest_version: Literal["3"] = "3"
    run_id: str = Field(min_length=1)
    scenario_count: int = Field(ge=0)
    feature_file_count: int = Field(ge=0)
    presence_coverage: MetricSection
    validity_grounding: MetricSection
    cross_artifact_agreement: MetricSection
    semantic_quality_diagnostics: MetricSection
    release_qualification: MetricSection
    qualification: QualificationResult

    @model_validator(mode="after")
    def _qualification_is_canonical(self) -> ScorecardV1:
        gates = scorecard_qualification_gates(self)
        validate_qualification_gate_semantics(gates)
        expected = aggregate_qualification(
            gates, required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS
        )
        if self.qualification != expected:
            raise ValueError("qualification does not match canonical scorecard gates")
        return self


def ratio_metric(
    numerator: int,
    denominator: int,
    *,
    threshold: float = 1.0,
    evidence: list[str],
    affected_ids: list[str] | None = None,
    applicable: bool = True,
) -> MetricResult:
    """Build a thresholded ratio without vacuous truth."""
    if denominator == 0:
        return MetricResult(
            status=MetricStatus.NOT_APPLICABLE,
            threshold=threshold,
            numerator=numerator,
            denominator=0,
            evidence=evidence,
            affected_ids=sorted(affected_ids or []),
        )
    value = numerator / denominator
    status = (
        MetricStatus.NOT_APPLICABLE
        if not applicable
        else MetricStatus.PASS
        if value >= threshold
        else MetricStatus.FAIL
    )
    return MetricResult(
        status=status,
        threshold=threshold,
        numerator=numerator,
        denominator=denominator,
        value=value,
        evidence=evidence,
        affected_ids=sorted(affected_ids or []),
    )


def zero_gate(
    count: int, *, evidence: list[str], affected_ids: list[str] | None = None
) -> MetricResult:
    """Build a gate requiring an observed count to be zero."""
    return MetricResult(
        status=MetricStatus.PASS if count == 0 else MetricStatus.FAIL,
        numerator=count,
        evidence=evidence,
        affected_ids=sorted(affected_ids or []),
    )


def aggregate_qualification(
    gates: dict[str, MetricResult], *, required_gate_ids: frozenset[str] = frozenset()
) -> QualificationResult:
    """Exclude N/A gates, surface errors, and never average gate values."""
    failed = sorted(k for k, v in gates.items() if v.status is MetricStatus.FAIL)
    errors = sorted(k for k, v in gates.items() if v.status is MetricStatus.ERROR)
    na = sorted(k for k, v in gates.items() if v.status is MetricStatus.NOT_APPLICABLE)
    blocking_na = sorted(required_gate_ids.intersection(na))
    applicable = len(gates) - len(na)
    passed = sum(v.status is MetricStatus.PASS for v in gates.values())
    status = (
        MetricStatus.ERROR
        if errors
        else MetricStatus.FAIL
        if failed
        else MetricStatus.FAIL
        if blocking_na
        else MetricStatus.PASS
    )
    return QualificationResult(
        status=status,
        applicable_gate_count=applicable,
        passed_gate_count=passed,
        failed_gate_ids=failed,
        error_gate_ids=errors,
        not_applicable_gate_ids=na,
        blocking_not_applicable_gate_ids=blocking_na,
    )


def scorecard_qualification_gates(scorecard: ScorecardV1) -> dict[str, MetricResult]:
    """Resolve the immutable canonical gate map from scorecard sections."""
    gates: dict[str, MetricResult] = {}
    for gate_id, (section_name, metric_id) in QUALIFICATION_GATE_PATHS.items():
        section = getattr(scorecard, section_name)
        metric = section.metrics.get(metric_id)
        if metric is None:
            raise ValueError(f"scorecard missing canonical gate metric {gate_id}")
        gates[gate_id] = metric
    return gates


def validate_qualification_gate_semantics(
    gates: dict[str, MetricResult],
) -> None:
    """Reject serialized gate outcomes that contradict canonical definitions."""
    for gate_id in UNSUPPORTED_QUALIFICATION_GATE_IDS:
        if gates[gate_id].status is not MetricStatus.NOT_APPLICABLE:
            raise ValueError(f"unsupported qualification gate {gate_id} must be N/A")

    for gate_id in QUALIFICATION_RATIO_GATE_IDS:
        metric = gates[gate_id]
        if metric.status is MetricStatus.NOT_APPLICABLE and all(
            value is None
            for value in (
                metric.threshold,
                metric.numerator,
                metric.denominator,
                metric.value,
            )
        ):
            continue
        if metric.status is MetricStatus.ERROR:
            if any(
                value is not None
                for value in (
                    metric.threshold,
                    metric.numerator,
                    metric.denominator,
                    metric.value,
                )
            ):
                raise ValueError(
                    f"error qualification ratio gate {gate_id} cannot claim a value"
                )
            continue
        if metric.threshold != 1.0:
            raise ValueError(f"qualification ratio gate {gate_id} requires threshold 1")
        if metric.numerator is None or metric.denominator is None:
            raise ValueError(
                f"qualification ratio gate {gate_id} requires numerator/denominator"
            )
        expected = (
            MetricStatus.NOT_APPLICABLE
            if metric.denominator == 0
            else MetricStatus.PASS
            if metric.numerator == metric.denominator
            else MetricStatus.FAIL
        )
        if metric.status is not expected:
            raise ValueError(f"qualification ratio gate {gate_id} has forged status")

    for gate_id in QUALIFICATION_ZERO_GATE_IDS:
        metric = gates[gate_id]
        if metric.status in {MetricStatus.NOT_APPLICABLE, MetricStatus.ERROR}:
            if any(
                value is not None
                for value in (
                    metric.threshold,
                    metric.numerator,
                    metric.denominator,
                    metric.value,
                )
            ):
                raise ValueError(
                    f"N/A or error qualification zero gate {gate_id} cannot claim a value"
                )
            continue
        if (
            metric.numerator is None
            or metric.threshold is not None
            or metric.denominator is not None
            or metric.value is not None
        ):
            raise ValueError(
                f"qualification zero gate {gate_id} requires a count numerator"
            )
        expected = MetricStatus.PASS if metric.numerator == 0 else MetricStatus.FAIL
        if metric.status is not expected:
            raise ValueError(f"qualification zero gate {gate_id} has forged status")
