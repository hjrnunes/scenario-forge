"""Pydantic models for the Risk Card artifact.

Compatible with policy-mapper's RiskMatch structure but without import
dependency on the policy-mapper project.  A risk card captures a single
risk assessment from a taxonomy (e.g. IBM Risk Atlas) with its causal
chain, evidence, scoring, and mitigations.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator

from scenario_forge.models.capability_profile import ConfidenceLevel


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class EvidenceSpan(BaseModel):
    """A span of evidence supporting the risk identification."""

    text: str = Field(description="The evidence text extracted from the source document.")
    source: Optional[str] = Field(
        default=None,
        description="Source document or location of the evidence.",
    )
    relevance: Optional[float] = Field(
        default=None,
        description="Relevance score for this evidence span (0.0 - 1.0).",
        ge=0.0,
        le=1.0,
    )


class MitigationRef(BaseModel):
    """A reference to a mitigation for the identified risk."""

    mitigation_id: Optional[str] = Field(
        default=None,
        description="Identifier for the mitigation if one exists in the taxonomy.",
    )
    description: str = Field(default="", description="Description of the mitigation measure.")

    @field_validator("description", mode="before")
    @classmethod
    def _coerce_none_description(cls, v: object) -> str:
        return v if v is not None else ""

    source: Optional[str] = Field(
        default=None,
        description="Source taxonomy or framework for this mitigation.",
    )


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class RiskCard(BaseModel):
    """A risk card capturing a single risk assessment.

    Compatible with policy-mapper's RiskMatch: risk_id, risk_name,
    risk_description, taxonomy, confidence, grounding_confidence, evidence,
    scores, mitigations, threat, threat_source, vulnerability, consequence,
    impact.
    """

    # --- Identity ---

    risk_id: str = Field(
        description="Risk taxonomy ID (e.g. 'atlas-prompt-injection').",
    )
    risk_name: str = Field(
        description="Human-readable risk name.",
    )
    risk_description: str = Field(
        description="Full description of the risk.",
    )
    taxonomy: str = Field(
        description="Source taxonomy identifier (e.g. 'ibm-risk-atlas').",
    )

    # --- Confidence ---

    confidence: float = Field(
        description="Cross-encoder confidence score (0.0 - 1.0).",
        ge=0.0,
        le=1.0,
    )
    grounding_confidence: ConfidenceLevel = Field(
        description="Grounding confidence level: high, medium, or low.",
    )

    # --- Evidence ---

    evidence: list[EvidenceSpan] = Field(
        default_factory=list,
        description="Evidence spans supporting the risk identification.",
    )

    # --- Scores ---

    scores: Optional[dict[str, float]] = Field(
        default=None,
        description="Additional scores (e.g. impact, likelihood) keyed by score name.",
    )

    # --- Mitigations ---

    mitigations: list[MitigationRef] = Field(
        default_factory=list,
        description="Mitigations for the identified risk.",
    )

    # --- Causal chain ---

    threat: Optional[str] = Field(
        default=None,
        description="The threat in the causal chain (what the adversary does).",
    )
    threat_source: Optional[str] = Field(
        default=None,
        description="The source of the threat (who or what).",
    )
    vulnerability: Optional[str] = Field(
        default=None,
        description="The vulnerability exploited in the causal chain.",
    )
    consequence: Optional[str] = Field(
        default=None,
        description="The direct consequence of the risk materializing.",
    )
    impact: Optional[str] = Field(
        default=None,
        description="The broader impact if the risk materializes.",
    )
