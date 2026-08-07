"""Strict v1 scorecard contract and non-vacuous metric helpers."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator

SCORECARD_SCHEMA_VERSION = "1"
METRIC_DEFINITION_VERSION = "1"


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
            if abs(self.value - expected) > 0.00005:
                raise ValueError("value must equal numerator / denominator")
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

    @model_validator(mode="after")
    def _aggregate(self) -> QualificationResult:
        if self.passed_gate_count > self.applicable_gate_count:
            raise ValueError("passed gates cannot exceed applicable gates")
        expected = (
            MetricStatus.ERROR
            if self.error_gate_ids
            else MetricStatus.FAIL
            if self.failed_gate_ids
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


def aggregate_qualification(gates: dict[str, MetricResult]) -> QualificationResult:
    """Exclude N/A gates, surface errors, and never average gate values."""
    failed = sorted(k for k, v in gates.items() if v.status is MetricStatus.FAIL)
    errors = sorted(k for k, v in gates.items() if v.status is MetricStatus.ERROR)
    na = sorted(k for k, v in gates.items() if v.status is MetricStatus.NOT_APPLICABLE)
    applicable = len(gates) - len(na)
    passed = sum(v.status is MetricStatus.PASS for v in gates.values())
    status = (
        MetricStatus.ERROR
        if errors
        else MetricStatus.FAIL
        if failed
        else MetricStatus.PASS
    )
    return QualificationResult(
        status=status,
        applicable_gate_count=applicable,
        passed_gate_count=passed,
        failed_gate_ids=failed,
        error_gate_ids=errors,
        not_applicable_gate_ids=na,
    )
