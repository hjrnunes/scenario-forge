"""Candidate expansion and filtering pipeline.

Cross-products scenario seeds with entry points and ATLAS techniques to
produce CandidateTriple objects, then defines models for the LLM batch
filter stage and downstream scenario generation.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, Field

from scenario_forge.data.atlas import ATLAS_TECHNIQUE_DESCRIPTIONS, ATLAS_TECHNIQUE_NAMES
from scenario_forge.llm.client import LLMClient
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

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


# ---------------------------------------------------------------------------
# LLM batch filter: accept/reject candidates with rationale
# ---------------------------------------------------------------------------


def filter_candidates(
    candidates: list[CandidateTriple],
    seeds: list[ScenarioSeed],
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile,
) -> list[FilteredSeed]:
    """Filter candidates via one LLM call per seed.

    Groups candidates by ``seed_id``, renders a batch prompt for each seed,
    and asks the LLM to accept or reject every (entry_point, technique)
    combination with a rationale.

    Args:
        candidates: Output of :func:`expand_candidates`.
        seeds: Original :class:`ScenarioSeed` list (for full field lookup).
        client: Configured :class:`LLMClient` instance.
        use_case: Free-text system description.
        profile: Capability profile of the system under assessment.

    Returns:
        List of :class:`FilteredSeed`, one per accepted candidate.
    """
    if not candidates:
        logger.info("Filter: no candidates to filter")
        return []

    # Build seed lookup for constructing FilteredSeed with full fields
    seed_lookup: dict[str, ScenarioSeed] = {s.seed_id: s for s in seeds}

    # Group candidates by seed_id
    groups: dict[str, list[CandidateTriple]] = defaultdict(list)
    for c in candidates:
        groups[c.seed_id].append(c)

    # Render system prompt once (shared across all seeds)
    system_prompt = render_prompt(
        "filter_system.j2",
        use_case=use_case,
        profile=profile,
    )

    total_accepted = 0
    total_rejected = 0
    results: list[FilteredSeed] = []

    for seed_id, seed_candidates in groups.items():
        # Use first candidate for seed-level metadata (all share the same seed)
        first = seed_candidates[0]

        user_prompt = render_prompt(
            "filter_user.j2",
            seed_id=seed_id,
            attack_pattern_name=first.attack_pattern_name,
            attack_pattern_description=first.attack_pattern_description,
            threat_id=first.threat_id,
            threat_name=first.threat_name,
            owasp_llm_ids=first.owasp_llm_ids,
            risk_card_ref=first.risk_card_ref,
            candidates=seed_candidates,
        )

        llm_result = client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=BatchFilterResponse,
        )
        batch_response: BatchFilterResponse = llm_result.content

        # Partition verdicts
        accepted_verdicts: list[FilterVerdict] = []
        rejected_verdicts: list[FilterVerdict] = []
        for v in batch_response.verdicts:
            if v.verdict == "accept":
                accepted_verdicts.append(v)
            else:
                rejected_verdicts.append(v)

        # Build a technique-name lookup from the candidates
        tech_name_lookup: dict[str, str] = {
            c.atlas_technique_id: c.atlas_technique_name
            for c in seed_candidates
        }

        # Get original seed for full field set
        original_seed = seed_lookup.get(seed_id)
        if original_seed is None:
            logger.warning(
                "Seed %s not found in seed lookup — skipping %d accepted verdicts",
                seed_id,
                len(accepted_verdicts),
            )
            total_rejected += len(seed_candidates)
            continue

        for verdict in accepted_verdicts:
            results.append(
                FilteredSeed(
                    # ScenarioSeed fields from original seed
                    seed_id=original_seed.seed_id,
                    threat_id=original_seed.threat_id,
                    threat_name=original_seed.threat_name,
                    threat_description=original_seed.threat_description,
                    attack_pattern_name=original_seed.attack_pattern_name,
                    attack_pattern_description=original_seed.attack_pattern_description,
                    risk_card_ref=original_seed.risk_card_ref,
                    contributing_risk_cards=original_seed.contributing_risk_cards,
                    owasp_llm_ids=original_seed.owasp_llm_ids,
                    agentic_threat_ids=original_seed.agentic_threat_ids,
                    atlas_technique_ids=original_seed.atlas_technique_ids,
                    owasp_origin=original_seed.owasp_origin,
                    laaf_technique_ids=original_seed.laaf_technique_ids,
                    atlas_provenance_ids=original_seed.atlas_provenance_ids,
                    # Pinned fields from the accepted verdict
                    pinned_entry_point=verdict.entry_point,
                    pinned_technique_id=verdict.atlas_technique_id,
                    pinned_technique_name=tech_name_lookup.get(
                        verdict.atlas_technique_id, verdict.atlas_technique_id
                    ),
                    # Sibling rejections for provenance display
                    rejection_rationales=rejected_verdicts,
                )
            )

        seed_accepted = len(accepted_verdicts)
        seed_total = len(seed_candidates)
        total_accepted += seed_accepted
        total_rejected += seed_total - seed_accepted

        logger.info(
            "Seed %s: %d/%d candidates accepted",
            seed_id,
            seed_accepted,
            seed_total,
        )

    logger.info(
        "Filter: %d/%d candidates survived (%d rejected)",
        total_accepted,
        total_accepted + total_rejected,
        total_rejected,
    )

    return results
