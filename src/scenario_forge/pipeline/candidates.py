"""Candidate filtering pipeline models.

Defines the contract between seed expansion (cross-product of seeds with
entry points and ATLAS techniques), the LLM batch filter stage, and
downstream scenario generation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.seeds import ScenarioSeed


# ---------------------------------------------------------------------------
# Pre-filter: one (attack_pattern, entry_point, atlas_technique) candidate
# ---------------------------------------------------------------------------


class CandidateTriple(BaseModel):
    """One (attack_pattern, entry_point, atlas_technique) candidate before filtering."""

    seed_id: str = Field(description="Attack pattern ID, e.g. 'AP-T7-01'.")
    threat_id: str = Field(description="Parent threat ID, e.g. 'T7'.")
    threat_name: str = Field(description="Human-readable threat name.")
    attack_pattern_name: str = Field(description="Human-readable attack pattern name.")
    attack_pattern_description: str = Field(
        description="Full description of the attack pattern."
    )
    entry_point: str = Field(
        description="Entry point text, e.g. 'natural language customer queries via Klarna app (input)'.",
    )
    atlas_technique_id: str = Field(
        description="ATLAS technique ID, e.g. 'AML.T0051'."
    )
    atlas_technique_name: str = Field(
        description="Human-readable ATLAS technique name."
    )
    atlas_technique_description: str = Field(
        description="Full description of the ATLAS technique."
    )
    risk_card_ref: RiskCardRef = Field(
        description="Back-reference to the originating risk card."
    )
    owasp_llm_ids: list[str] = Field(
        description="OWASP LLM Top-10 IDs this candidate maps from."
    )


# ---------------------------------------------------------------------------
# LLM filter response models
# ---------------------------------------------------------------------------


class FilterVerdict(BaseModel):
    """Structured output for one entry in the LLM batch filter response."""

    entry_point: str = Field(description="The entry point being judged.")
    atlas_technique_id: str = Field(description="The technique being judged.")
    verdict: Literal["accept", "reject"] = Field(
        description="Whether this candidate should proceed to generation."
    )
    rationale: str = Field(
        description="One-sentence explanation of why the candidate was accepted or rejected.",
    )


class BatchFilterResponse(BaseModel):
    """Wrapper for the full batch LLM response for one seed."""

    seed_id: str = Field(description="Which seed this response is for.")
    verdicts: list[FilterVerdict] = Field(
        description="Per-candidate accept/reject verdicts."
    )


# ---------------------------------------------------------------------------
# Post-filter: seed with pinned entry point and technique
# ---------------------------------------------------------------------------


class FilteredSeed(ScenarioSeed):
    """A ScenarioSeed with pinned entry point and ATLAS technique.

    Hard assignments (not hints) produced by the candidate filter stage.
    Also carries rejection rationales for provenance display in reports.
    """

    pinned_entry_point: str = Field(
        description="The accepted entry point (hard constraint for generation).",
    )
    pinned_technique_id: str = Field(
        description="The accepted ATLAS technique ID (hard constraint for generation).",
    )
    pinned_technique_name: str = Field(
        description="Human-readable name of the pinned technique, for report display.",
    )
    rejection_rationales: list[FilterVerdict] = Field(
        default_factory=list,
        description="Sibling candidates that were rejected (for provenance tab).",
    )
