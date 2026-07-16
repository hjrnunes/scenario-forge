"""Candidate expansion and filtering pipeline.

Cross-products scenario seeds with entry points and ATLAS techniques to
produce CandidateTriple objects, then defines models for the LLM batch
filter stage and downstream scenario generation.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations
from typing import Literal, Sequence

from pydantic import BaseModel, Field

from scenario_forge.data.atlas import ATLAS_TECHNIQUE_DESCRIPTIONS, ATLAS_TECHNIQUE_NAMES
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pre-filter: one (attack_pattern, entry_point, atlas_technique) candidate
# ---------------------------------------------------------------------------


class CandidateTriple(BaseModel):
    """One (attack_pattern, entry_point, atlas_technique_combo) candidate before filtering."""

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
    atlas_technique_ids: tuple[str, ...] = Field(
        description="ATLAS technique ID(s), e.g. ('AML.T0051',) or ('AML.T0051', 'AML.T0054')."
    )
    atlas_technique_names: tuple[str, ...] = Field(
        description="Human-readable ATLAS technique name(s)."
    )
    atlas_technique_descriptions: tuple[str, ...] = Field(
        description="Full description(s) of the ATLAS technique(s)."
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
    atlas_technique_ids: tuple[str, ...] = Field(
        description="The technique combo being judged (e.g. ('AML.T0051',) or ('AML.T0051', 'AML.T0054'))."
    )
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
    pinned_technique_ids: tuple[str, ...] = Field(
        description="The accepted ATLAS technique ID(s) (hard constraint for generation).",
    )
    pinned_technique_names: tuple[str, ...] = Field(
        description="Human-readable name(s) of the pinned technique(s), for report display.",
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
    max_techniques: int = 1,
) -> list[CandidateTriple]:
    """Cross-product each seed with all entry points and ATLAS technique combos.

    For every ScenarioSeed, produces one CandidateTriple per
    (entry_point, technique_combo) combination, carrying full context
    needed by the downstream LLM filter stage.

    When ``max_techniques=1`` (the default), behaviour is equivalent to the
    original per-technique expansion.  With ``max_techniques=2``, both
    single-technique and two-technique combos are generated (C(N,1)+C(N,2)
    per seed x entry_point).

    Args:
        seeds: Output of ``expand_seeds()`` (Stage 3).
        profile: Capability profile with ``entry_points`` list.
        max_techniques: Maximum number of techniques in a combo (default 1).

    Returns:
        Flat list of CandidateTriple, one per combination.
    """
    if not profile.entry_points:
        logger.warning("Profile has no entry points — returning empty candidate list")
        return []

    # Pre-filter: reject seeds whose required_capabilities are not met
    eligible_seeds: list[ScenarioSeed] = []
    for seed in seeds:
        if seed.required_capabilities:
            skip = False
            for cap in seed.required_capabilities:
                if cap == "multi_agent" and not profile.multi_agent:
                    logger.warning(
                        "Skipping seed %s: requires %s but profile does not support it",
                        seed.seed_id,
                        cap,
                    )
                    skip = True
                    break
                if cap == "persistent_memory" and not profile.has_persistent_memory:
                    logger.warning(
                        "Skipping seed %s: requires %s but profile does not support it",
                        seed.seed_id,
                        cap,
                    )
                    skip = True
                    break
                if cap == "tool_execution" and "tool_execution" not in profile.zones_active:
                    logger.warning(
                        "Skipping seed %s: requires %s but profile does not support it",
                        seed.seed_id,
                        cap,
                    )
                    skip = True
                    break
            if skip:
                continue
        eligible_seeds.append(seed)

    if len(eligible_seeds) < len(seeds):
        logger.info(
            "Seed capability filter: %d/%d seeds eligible (rejected %d)",
            len(eligible_seeds),
            len(seeds),
            len(seeds) - len(eligible_seeds),
        )

    candidates: list[CandidateTriple] = []

    # Filter out output-only entry points — they are not attacker-accessible
    # ingress channels. Only input and bidirectional entry points participate
    # in the candidate cross-product.
    ingress_points = [ep for ep in profile.entry_points if ep.direction != "output"]

    if not ingress_points:
        logger.warning(
            "Profile has %d entry points but none are input/bidirectional — "
            "returning empty candidate list",
            len(profile.entry_points),
        )
        return []

    output_only_count = len(profile.entry_points) - len(ingress_points)
    if output_only_count > 0:
        logger.info(
            "Entry point direction filter: %d/%d entry points are ingress-capable "
            "(%d output-only excluded)",
            len(ingress_points),
            len(profile.entry_points),
            output_only_count,
        )

    for seed in eligible_seeds:
        if not seed.atlas_technique_ids:
            logger.warning(
                "Seed %s has no ATLAS technique IDs — skipping", seed.seed_id
            )
            continue

        for entry_point in ingress_points:
            for combo_size in range(1, max_techniques + 1):
                for tech_combo in combinations(seed.atlas_technique_ids, combo_size):
                    candidates.append(
                        CandidateTriple(
                            seed_id=seed.seed_id,
                            threat_id=seed.threat_id,
                            threat_name=seed.threat_name,
                            attack_pattern_name=seed.attack_pattern_name,
                            attack_pattern_description=seed.attack_pattern_description,
                            entry_point=entry_point.name,
                            atlas_technique_ids=tech_combo,
                            atlas_technique_names=tuple(
                                ATLAS_TECHNIQUE_NAMES.get(t, t) for t in tech_combo
                            ),
                            atlas_technique_descriptions=tuple(
                                ATLAS_TECHNIQUE_DESCRIPTIONS.get(t, "")
                                for t in tech_combo
                            ),
                            risk_card_ref=seed.risk_card_ref,
                            owasp_llm_ids=seed.owasp_llm_ids,
                        )
                    )

    # Log expansion summary
    if eligible_seeds:
        tech_counts = [len(s.atlas_technique_ids) for s in eligible_seeds if s.atlas_technique_ids]
        avg_techniques = sum(tech_counts) / len(tech_counts) if tech_counts else 0.0
        logger.info(
            "%d seeds x %d ingress entry points x avg %.1f techniques "
            "(max_techniques=%d) = %d candidates",
            len(eligible_seeds),
            len(ingress_points),
            avg_techniques,
            max_techniques,
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
) -> tuple[list[FilteredSeed], list[dict]]:
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
        Tuple of (filtered_seeds, call_log_entries).  ``filtered_seeds`` has
        one :class:`FilteredSeed` per accepted candidate.  ``call_log_entries``
        contains one dict per LLM call made during filtering, using the same
        JSON schema as scenario call logs (with ``"call": "candidate_filter"``).
    """
    if not candidates:
        logger.info("Filter: no candidates to filter")
        return [], []

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

    def _filter_one_seed(
        seed_id: str,
        seed_candidates: list[CandidateTriple],
    ) -> tuple[list[FilteredSeed], int, int, LLMResult]:
        """Filter candidates for a single seed. Returns (accepted, n_accepted, n_rejected, llm_result)."""
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

        accepted_verdicts: list[FilterVerdict] = []
        rejected_verdicts: list[FilterVerdict] = []
        for v in batch_response.verdicts:
            if v.verdict == "accept":
                accepted_verdicts.append(v)
            else:
                rejected_verdicts.append(v)

        tech_names_lookup: dict[tuple[str, ...], tuple[str, ...]] = {
            c.atlas_technique_ids: c.atlas_technique_names
            for c in seed_candidates
        }

        original_seed = seed_lookup.get(seed_id)
        if original_seed is None:
            logger.warning(
                "Seed %s not found in seed lookup — skipping %d accepted verdicts",
                seed_id,
                len(accepted_verdicts),
            )
            return [], 0, len(seed_candidates), llm_result

        seed_results: list[FilteredSeed] = []
        for verdict in accepted_verdicts:
            seed_results.append(
                FilteredSeed(
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
                    pinned_entry_point=verdict.entry_point,
                    pinned_technique_ids=verdict.atlas_technique_ids,
                    pinned_technique_names=tech_names_lookup.get(
                        verdict.atlas_technique_ids,
                        verdict.atlas_technique_ids,
                    ),
                    rejection_rationales=rejected_verdicts,
                )
            )

        seed_accepted = len(accepted_verdicts)
        seed_total = len(seed_candidates)
        logger.info(
            "Seed %s: %d/%d candidates accepted",
            seed_id,
            seed_accepted,
            seed_total,
        )
        return seed_results, seed_accepted, seed_total - seed_accepted, llm_result

    total_accepted = 0
    total_rejected = 0
    results: list[FilteredSeed] = []
    call_log_entries: list[dict] = []

    max_workers = min(8, len(groups))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_filter_one_seed, sid, cands): sid
            for sid, cands in groups.items()
        }
        for future in as_completed(futures):
            seed_id = futures[future]
            try:
                seed_results, n_acc, n_rej, llm_result = future.result()
                results.extend(seed_results)
                total_accepted += n_acc
                total_rejected += n_rej
                # Build call log entry for this filter call.
                raw_content = llm_result.content
                if hasattr(raw_content, "model_dump"):
                    raw_content = raw_content.model_dump(mode="json")
                elif not isinstance(raw_content, str):
                    raw_content = str(raw_content)
                call_log_entries.append({
                    "call": "candidate_filter",
                    "seed_id": seed_id,
                    "system_prompt": llm_result.system_prompt,
                    "user_prompt": llm_result.user_prompt,
                    "response": raw_content,
                    "prompt_tokens": llm_result.prompt_tokens,
                    "completion_tokens": llm_result.completion_tokens,
                    "duration_ms": llm_result.duration_ms,
                })
            except Exception:
                logger.exception("Filter failed for seed %s", seed_id)
                total_rejected += len(groups[seed_id])

    logger.info(
        "Filter: %d/%d candidates survived (%d rejected)",
        total_accepted,
        total_accepted + total_rejected,
        total_rejected,
    )

    return results, call_log_entries


# ---------------------------------------------------------------------------
# Post-filter: cap scenarios per attack pattern
# ---------------------------------------------------------------------------


def cap_scenarios_per_pattern(
    filtered_seeds: Sequence[FilteredSeed],
    max_per_pattern: int,
) -> list[FilteredSeed]:
    """Cap the number of filtered seeds per attack pattern (seed_id).

    When a group exceeds ``max_per_pattern``, seeds are selected using
    greedy marginal coverage that balances both technique and entry-point
    diversity.

    At each selection step the candidate with the highest score is picked::

        score = (count of technique IDs NOT yet covered by selected set)
              + (1 if entry point NOT yet seen in selected set)

    Ties are broken by technique-combo size (prefer larger combos), then
    by original encounter order (lower index wins).

    This ensures dual-technique candidates float to the top early (more
    new technique ground), while single-technique candidates fill
    entry-point diversity once technique coverage is saturated.

    A warning is logged for every capped group.

    Args:
        filtered_seeds: Output of :func:`filter_candidates`.
        max_per_pattern: Maximum number of seeds to keep per ``seed_id``.

    Returns:
        A new list of :class:`FilteredSeed` with groups truncated as needed.
    """
    if max_per_pattern < 1:
        raise ValueError("max_per_pattern must be >= 1")

    # Group by seed_id (attack pattern), preserving encounter order.
    groups: dict[str, list[FilteredSeed]] = defaultdict(list)
    for fs in filtered_seeds:
        groups[fs.seed_id].append(fs)

    result: list[FilteredSeed] = []
    for seed_id, group in groups.items():
        if len(group) <= max_per_pattern:
            result.extend(group)
            continue

        # Greedy marginal-coverage selection.
        covered_techniques: set[str] = set()
        seen_entry_points: set[str] = set()
        selected: list[FilteredSeed] = []
        remaining_indices: list[int] = list(range(len(group)))

        while len(selected) < max_per_pattern and remaining_indices:
            best_idx: int | None = None
            best_score: tuple[int, int, int] = (-1, -1, -1)

            for idx in remaining_indices:
                fs = group[idx]
                new_techniques = sum(
                    1 for t in fs.pinned_technique_ids if t not in covered_techniques
                )
                new_entry_point = 1 if fs.pinned_entry_point not in seen_entry_points else 0
                marginal = new_techniques + new_entry_point
                combo_size = len(fs.pinned_technique_ids)
                # Score tuple: (marginal coverage, combo size, -index for stable ordering)
                score = (marginal, combo_size, -idx)
                if score > best_score:
                    best_score = score
                    best_idx = idx

            assert best_idx is not None  # remaining_indices is non-empty
            chosen = group[best_idx]
            selected.append(chosen)
            covered_techniques.update(chosen.pinned_technique_ids)
            seen_entry_points.add(chosen.pinned_entry_point)
            remaining_indices.remove(best_idx)

        logger.warning(
            "Capped %s from %d to %d scenarios (--max-scenarios-per-pattern)",
            seed_id,
            len(group),
            len(selected),
        )
        result.extend(selected)

    return result
