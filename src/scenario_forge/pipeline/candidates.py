"""Candidate expansion and filtering pipeline.

Cross-products scenario seeds with entry points and ATLAS techniques to
produce CandidateTriple objects, then defines models for the LLM batch
filter stage and downstream scenario generation.
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, Field

from scenario_forge.data.atlas import ATLAS_TECHNIQUE_DESCRIPTIONS, ATLAS_TECHNIQUE_NAMES
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.seeds import ScenarioSeed

logger = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# Candidate expansion: cross-product seeds x entry_points x techniques
# ---------------------------------------------------------------------------


def expand_candidates(
    seeds: list[ScenarioSeed],
    profile: CapabilityProfile,
) -> list[CandidateTriple]:
    """Cross-product each seed with all entry points and ATLAS techniques.

    For every ScenarioSeed, produces one CandidateTriple per
    (entry_point, atlas_technique) combination, carrying full context
    needed by the downstream LLM filter stage.

    Args:
        seeds: Output of ``expand_seeds()`` (Stage 3).
        profile: Capability profile with ``entry_points`` list.

    Returns:
        Flat list of CandidateTriple, one per combination.
    """
    if not profile.entry_points:
        logger.warning("Profile has no entry points — returning empty candidate list")
        return []

    candidates: list[CandidateTriple] = []

    for seed in seeds:
        if not seed.atlas_technique_ids:
            logger.warning(
                "Seed %s has no ATLAS technique IDs — skipping", seed.seed_id
            )
            continue

        for entry_point in profile.entry_points:
            for tech_id in seed.atlas_technique_ids:
                candidates.append(
                    CandidateTriple(
                        seed_id=seed.seed_id,
                        threat_id=seed.threat_id,
                        threat_name=seed.threat_name,
                        attack_pattern_name=seed.attack_pattern_name,
                        attack_pattern_description=seed.attack_pattern_description,
                        entry_point=entry_point,
                        atlas_technique_id=tech_id,
                        atlas_technique_name=ATLAS_TECHNIQUE_NAMES.get(
                            tech_id, tech_id
                        ),
                        atlas_technique_description=ATLAS_TECHNIQUE_DESCRIPTIONS.get(
                            tech_id, ""
                        ),
                        risk_card_ref=seed.risk_card_ref,
                        owasp_llm_ids=seed.owasp_llm_ids,
                    )
                )

    # Log expansion summary
    if seeds:
        tech_counts = [len(s.atlas_technique_ids) for s in seeds if s.atlas_technique_ids]
        avg_techniques = sum(tech_counts) / len(tech_counts) if tech_counts else 0.0
        logger.info(
            "%d seeds x %d entry points x avg %.1f techniques = %d candidates",
            len(seeds),
            len(profile.entry_points),
            avg_techniques,
            len(candidates),
        )

    return candidates
