"""Pydantic models for abstract attack patterns.

Defines the schema for attack pattern YAML entries including the
optional kill_chain and evidence fields.  These models serve as the
canonical schema definition and can be used for validation at load time
via ``validate_attack_pattern()``.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class KillChainStep(BaseModel):
    """A single step in an attack pattern's kill chain."""

    step: str = Field(
        description="Kill chain phase name (e.g. 'setup', 'delivery', 'exploitation').",
    )
    tactic: str = Field(
        description="MITRE ATLAS tactic ID (e.g. 'AML.TA0003').",
        pattern=r"^AML\.TA\d{4}$",
    )
    techniques: list[str] = Field(
        description="List of MITRE ATLAS technique IDs used in this step.",
        min_length=1,
    )
    abstract_action: str = Field(
        description="Domain-agnostic description of what the attacker does in this step.",
    )

    @field_validator("techniques", mode="after")
    @classmethod
    def _validate_technique_ids(cls, v: list[str]) -> list[str]:
        for tid in v:
            if not tid.startswith("AML.T"):
                msg = f"Technique ID must start with 'AML.T', got: {tid!r}"
                raise ValueError(msg)
        return v


class EvidenceLink(BaseModel):
    """A link to evidence supporting the attack pattern."""

    source: str = Field(
        description="Evidence source identifier (e.g. 'AML.CS0040').",
    )
    type: Literal["direct_demonstration", "variant", "enrichment"] = Field(
        description="Type of evidence: direct_demonstration, variant, or enrichment.",
    )


class PrerequisiteCapabilities(BaseModel):
    """Prerequisite capability requirements for an attack pattern."""

    min_zones: list[str] = Field(
        description="Minimum zones required for the attack pattern.",
    )
    kc_requires: Optional[dict[str, list[str]]] = Field(
        default=None,
        description="KC sub-code requirements with 'all' and/or 'any' keys.",
    )


class NistClassification(BaseModel):
    """NIST AI 100-2e2023 classification metadata."""

    attacker_goal: str = Field(description="Attacker goal classification.")
    attacker_knowledge: str = Field(description="Attacker knowledge level.")
    learning_stage: str = Field(description="Learning stage targeted.")
    attack_class: Optional[str] = Field(
        default=None,
        description="Attack class in NIST taxonomy.",
    )


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class AttackPattern(BaseModel):
    """A single abstract attack pattern entry.

    Validates the full structure of an attack pattern YAML entry including
    the optional kill_chain and evidence fields.
    """

    id: str = Field(description="Pattern ID (e.g. 'AP-T1-05').")
    threat_id: str = Field(description="Parent threat ID (e.g. 'T1').")
    name: str = Field(description="Human-readable pattern name.")
    description: str = Field(description="Domain-agnostic mechanism description.")

    nist_classification: Optional[NistClassification] = Field(
        default=None,
        description="NIST classification metadata.",
    )
    prerequisite_capabilities: PrerequisiteCapabilities = Field(
        description="Prerequisite capability requirements.",
    )

    kill_chain: Optional[list[KillChainStep]] = Field(
        default=None,
        description="Optional ordered kill chain steps for the attack pattern.",
    )
    evidence: Optional[list[EvidenceLink]] = Field(
        default=None,
        description="Optional evidence links supporting the pattern.",
    )


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------


def validate_attack_pattern(pattern_dict: dict) -> AttackPattern:
    """Validate a raw attack pattern dict against the Pydantic model.

    Args:
        pattern_dict: A single pattern entry as loaded from YAML.

    Returns:
        A validated ``AttackPattern`` instance.

    Raises:
        pydantic.ValidationError: If the dict does not conform to the schema.
    """
    return AttackPattern.model_validate(pattern_dict)
