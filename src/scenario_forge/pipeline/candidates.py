"""Candidate expansion and filtering pipeline.

Cross-products scenario seeds with entry points and techniques (ATLAS or
LAAF) to produce CandidateTriple objects, then defines models for the LLM
batch filter stage and downstream scenario generation.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations
from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from scenario_forge.data.atlas import (
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_NAMES,
    TECHNIQUE_PROPERTIES,
    THREAT_PREREQUISITES,
)
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    classify_entry_point,
    compute_entry_point_id,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical candidate identity
# ---------------------------------------------------------------------------

_CANDIDATE_ID_VERSION = "v1"


def compute_candidate_id(
    seed_id: str,
    entry_point_id: str,
    technique_ids: Sequence[str],
) -> str:
    """Compute a deterministic, versioned ``candidate_id``.

    The ID is derived from ``(seed_id, entry_point_id, sorted unique
    technique IDs)`` so that the same combination always produces the
    same ID regardless of technique ordering.

    Format: ``cand:<version>:<32-char hex digest (128-bit)>``
    """
    sorted_tech = tuple(sorted(set(technique_ids)))
    identity = f"{seed_id}|{entry_point_id}|{','.join(sorted_tech)}"
    h = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"cand:{_CANDIDATE_ID_VERSION}:{h}"


# ---------------------------------------------------------------------------
# Pre-filter: one (attack_pattern, entry_point, atlas_technique) candidate
# ---------------------------------------------------------------------------


class CandidateTriple(BaseModel):
    """One (attack_pattern, entry_point, atlas_technique_combo) candidate before filtering.

    The model is frozen (immutable) so that submitted metadata cannot be
    mutated after the filter protocol has been engaged.  Supplied
    ``entry_point_id`` and ``candidate_id`` are validated against
    canonical recomputation on construction.
    """

    model_config = ConfigDict(frozen=True)

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
    controllability: str | None = Field(
        default=None,
        description="Entry point controllability: 'direct', 'indirect', or 'system'.",
    )
    direction: str | None = Field(
        default=None,
        description="Entry point data flow direction: 'input', 'output', or 'bidirectional'.",
    )
    entry_point_id: str = Field(
        description="Canonical, deterministic entry point identity (ep:v1:<hash>).",
    )
    candidate_id: str = Field(
        description="Canonical, deterministic candidate identity (cand:v1:<hash>).",
    )

    @model_validator(mode="after")
    def _validate_canonical_ids(self) -> CandidateTriple:
        """Validate that supplied IDs match canonical recomputation.

        This prevents forged or stale IDs from being used as join keys
        in the filter protocol or downstream provenance.
        """
        expected_ep_id = compute_entry_point_id(
            self.entry_point,
            self.direction or "bidirectional",
            self.controllability,
        )
        if self.entry_point_id != expected_ep_id:
            raise ValueError(
                f"entry_point_id '{self.entry_point_id}' does not match "
                f"canonical recomputation '{expected_ep_id}' for "
                f"entry_point='{self.entry_point}', "
                f"direction={self.direction}, "
                f"controllability={self.controllability}"
            )
        expected_cand_id = compute_candidate_id(
            self.seed_id, self.entry_point_id, self.atlas_technique_ids
        )
        if self.candidate_id != expected_cand_id:
            raise ValueError(
                f"candidate_id '{self.candidate_id}' does not match "
                f"canonical recomputation '{expected_cand_id}' for "
                f"seed_id='{self.seed_id}', "
                f"entry_point_id='{self.entry_point_id}', "
                f"technique_ids={self.atlas_technique_ids}"
            )
        return self


# ---------------------------------------------------------------------------
# LLM filter response models (wire protocol — opaque candidate IDs)
# ---------------------------------------------------------------------------


class FilterVerdict(BaseModel):
    """One entry in the LLM batch filter response (wire protocol).

    The LLM labels each verdict by the opaque ``candidate_id`` provided
    in the prompt.  It never echoes entry-point or technique metadata.
    """

    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(description="The opaque candidate ID being judged.")
    verdict: Literal["accept", "reject"] = Field(
        description="Whether this candidate should proceed to generation."
    )
    rationale: str = Field(
        description="One-sentence explanation of why the candidate was accepted or rejected.",
    )


class BatchFilterResponse(BaseModel):
    """Wrapper for the full batch LLM response for one seed.

    Contains only the batch ``seed_id`` and a list of
    :class:`FilterVerdict` entries keyed by opaque ``candidate_id``.
    """

    model_config = ConfigDict(extra="forbid")

    seed_id: str = Field(description="Which seed this response is for.")
    verdicts: list[FilterVerdict] = Field(
        description="Per-candidate accept/reject verdicts."
    )


class RejectionRecord(BaseModel):
    """Provenance record for a rejected candidate (enriched after reconciliation).

    Carries the canonical ``candidate_id`` alongside the display metadata
    (entry point, technique IDs) resolved from the candidate lookup, so
    the report can show what was rejected without relying on LLM-echoed
    metadata.
    """

    candidate_id: str = Field(
        description="Opaque candidate ID of the rejected candidate."
    )
    entry_point: str = Field(description="Entry point text of the rejected candidate.")
    atlas_technique_ids: tuple[str, ...] = Field(
        description="Technique combo of the rejected candidate."
    )
    rationale: str = Field(description="Rejection rationale.")


class FilterProtocolError(Exception):
    """Raised when the LLM filter response cannot be reconciled after retry.

    Carries the call log entries accumulated up to the failure point so
    the runner can persist them before failing the run.
    """

    def __init__(
        self, message: str, call_log_entries: list[dict] | None = None
    ) -> None:
        super().__init__(message)
        self.call_log_entries: list[dict] = call_log_entries or []


# ---------------------------------------------------------------------------
# Post-filter: seed with pinned entry point and technique
# ---------------------------------------------------------------------------


class FilteredSeed(ScenarioSeed):
    """A ScenarioSeed with pinned entry point and ATLAS technique.

    Hard assignments (not hints) produced by the candidate filter stage.
    Also carries canonical IDs and rejection records for provenance.
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
    entry_point_id: str = Field(
        description="Canonical entry point identity of the accepted candidate.",
    )
    candidate_id: str = Field(
        description="Canonical candidate identity of the accepted candidate.",
    )
    rejection_rationales: list[RejectionRecord] = Field(
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
                if (
                    cap == "tool_execution"
                    and "tool_execution" not in profile.zones_active
                ):
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
        # Use ATLAS technique IDs when available; fall back to LAAF IDs
        # for seeds that have only LAAF provenance (e.g. T7 misalignment
        # patterns where ATLAS techniques are semantically incorrect).
        technique_pool = seed.atlas_technique_ids or seed.laaf_technique_ids
        if not technique_pool:
            logger.warning(
                "Seed %s has no technique IDs (ATLAS or LAAF) — skipping",
                seed.seed_id,
            )
            continue

        for entry_point in ingress_points:
            ep_id = entry_point.entry_point_id
            for combo_size in range(1, max_techniques + 1):
                for tech_combo in combinations(technique_pool, combo_size):
                    candidates.append(
                        CandidateTriple(
                            seed_id=seed.seed_id,
                            threat_id=seed.threat_id,
                            threat_name=seed.threat_name,
                            attack_pattern_name=seed.attack_pattern_name,
                            attack_pattern_description=seed.attack_pattern_description,
                            entry_point=entry_point.name,
                            controllability=entry_point.controllability,
                            direction=entry_point.direction,
                            entry_point_id=ep_id,
                            candidate_id=compute_candidate_id(
                                seed.seed_id,
                                ep_id,
                                tech_combo,
                            ),
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
        tech_counts = [
            len(s.atlas_technique_ids or s.laaf_technique_ids)
            for s in eligible_seeds
            if s.atlas_technique_ids or s.laaf_technique_ids
        ]
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

    _check_candidate_collisions(candidates)
    return candidates


def _check_candidate_collisions(candidates: list[CandidateTriple]) -> None:
    """Reject candidates with same candidate_id but different identity inputs.

    Two candidates are *semantic duplicates* when they share the same
    ``candidate_id`` and the same ``(seed_id, entry_point_id, sorted
    unique technique IDs)`` — this is expected from duplicate expansion
    and is silently deduplicated elsewhere.

    Two candidates *collide* when they share the same ``candidate_id``
    but have different identity inputs (a hash collision or forged ID).
    This is rejected because the filter protocol cannot distinguish them.

    Args:
        candidates: List of candidates to check.

    Raises:
        ValueError: If two candidates with different identity inputs
            produce the same ``candidate_id``.
    """
    seen: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    for c in candidates:
        identity = (
            c.seed_id,
            c.entry_point_id,
            tuple(sorted(set(c.atlas_technique_ids))),
        )
        if c.candidate_id in seen:
            existing = seen[c.candidate_id]
            if existing != identity:
                raise ValueError(
                    f"Candidate collision: candidate_id '{c.candidate_id}' "
                    f"maps to different identity inputs "
                    f"({identity} vs {existing}). "
                    f"Remove or disambiguate one of them."
                )
            # Semantic duplicate — not an error here, just a debug log.
            logger.debug(
                "Semantic duplicate candidate_id '%s' in expansion",
                c.candidate_id,
            )
        else:
            seen[c.candidate_id] = identity


# ---------------------------------------------------------------------------
# LLM batch filter: accept/reject candidates with rationale
# ---------------------------------------------------------------------------


def _reconcile_filter_response(
    batch_response: BatchFilterResponse,
    expected_seed_id: str,
    submitted_candidate_ids: set[str],
) -> tuple[bool, str | None]:
    """Reconcile an LLM filter response against the exact submitted ID set.

    Checks (order-independent):
    - ``seed_id`` matches the expected seed.
    - Exactly one verdict per submitted candidate ID.
    - No unknown IDs, no duplicate IDs, no omitted IDs.

    Args:
        batch_response: Parsed LLM response.
        expected_seed_id: The seed_id that was submitted.
        submitted_candidate_ids: The exact set of candidate IDs submitted.

    Returns:
        ``(True, None)`` if the response is valid, otherwise
        ``(False, error_message)`` describing the reconciliation failure.
    """
    if batch_response.seed_id != expected_seed_id:
        return False, (
            f"Expected seed_id '{expected_seed_id}' but response has "
            f"'{batch_response.seed_id}'"
        )

    response_ids = [v.candidate_id for v in batch_response.verdicts]
    response_id_set = set(response_ids)

    # Duplicate IDs
    if len(response_ids) != len(response_id_set):
        from collections import Counter

        duplicates = sorted(
            cid for cid, count in Counter(response_ids).items() if count > 1
        )
        return False, f"Duplicate candidate IDs in response: {duplicates}"

    # Unknown IDs
    unknown = sorted(response_id_set - submitted_candidate_ids)
    if unknown:
        return False, f"Unknown candidate IDs in response: {unknown}"

    # Omitted IDs
    omitted = sorted(submitted_candidate_ids - response_id_set)
    if omitted:
        return False, f"Missing candidate IDs in response: {omitted}"

    return True, None


def _build_call_log_entry(
    seed_id: str,
    llm_result: LLMResult,
    attempt: int,
) -> dict:
    """Build a call log dict for one filter LLM call."""
    raw_content = llm_result.content
    if hasattr(raw_content, "model_dump"):
        raw_content = raw_content.model_dump(mode="json")
    elif not isinstance(raw_content, str):
        raw_content = str(raw_content)
    return {
        "call": "candidate_filter",
        "seed_id": seed_id,
        "attempt": attempt,
        "system_prompt": llm_result.system_prompt,
        "user_prompt": llm_result.user_prompt,
        "response": raw_content,
        "prompt_tokens": llm_result.prompt_tokens,
        "completion_tokens": llm_result.completion_tokens,
        "duration_ms": llm_result.duration_ms,
    }


def filter_candidates(
    candidates: list[CandidateTriple],
    seeds: list[ScenarioSeed],
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile,
) -> tuple[list[FilteredSeed], list[dict]]:
    """Filter candidates via one LLM call per seed (with retry-on-malformed).

    Groups candidates by ``seed_id``, renders a batch prompt for each seed
    labelling candidates by opaque ``candidate_id``, and asks the LLM to
    accept or reject every candidate with a rationale.

    Each response is atomically reconciled against the exact submitted ID
    set: expected seed, exactly one verdict per submitted ID, no
    unknown/duplicate/omitted IDs (order-independent).  Malformed batches
    are discarded and retried exactly once.  A second failure raises
    :class:`FilterProtocolError` (failing the run with no partial
    candidate output) while retaining call/protocol evidence.

    The LLM is never authoritative for metadata — entry-point and
    technique metadata are resolved from the candidate lookup by
    ``candidate_id``.

    Args:
        candidates: Output of :func:`expand_candidates`.
        seeds: Original :class:`ScenarioSeed` list (for full field lookup).
        client: Configured :class:`LLMClient` instance.
        use_case: Free-text system description.
        profile: Capability profile of the system under assessment.

    Returns:
        Tuple of (filtered_seeds, call_log_entries).

    Raises:
        FilterProtocolError: If a seed's response cannot be reconciled
            after one retry.
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
    ) -> tuple[list[FilteredSeed], int, int, list[dict]]:
        """Filter candidates for a single seed.

        Returns (accepted, n_accepted, n_rejected, call_log_entries).
        Raises FilterProtocolError on irreconcilable response.
        """
        # Reject duplicate candidate IDs in the submitted input — this
        # indicates a bug in candidate expansion or rule-based pruning.
        raw_ids = [c.candidate_id for c in seed_candidates]
        if len(set(raw_ids)) != len(seed_candidates):
            from collections import Counter

            id_counts = Counter(raw_ids)
            dupes = sorted(cid for cid, count in id_counts.items() if count > 1)
            raise FilterProtocolError(
                f"Duplicate candidate IDs in submitted input for seed "
                f"{seed_id}: {dupes}",
                call_log_entries=[],
            )

        # Deep-validated submission snapshot: reconstruct each candidate
        # through model_validate so forged model_copy(update=...) objects
        # are rejected and nested mutable collections are not shared with
        # the originals.  The prompt and candidate lookup are both derived
        # from this snapshot so application-resolved metadata cannot change
        # after submission.
        submitted_snapshot: list[CandidateTriple] = [
            CandidateTriple.model_validate(c.model_dump(mode="python"))
            for c in seed_candidates
        ]

        first = submitted_snapshot[0]
        submitted_ids: set[str] = {c.candidate_id for c in submitted_snapshot}

        # Build candidate_id → CandidateTriple lookup from the snapshot.
        candidate_lookup: dict[str, CandidateTriple] = {
            c.candidate_id: c for c in submitted_snapshot
        }

        user_prompt = render_prompt(
            "filter_user.j2",
            seed_id=seed_id,
            attack_pattern_name=first.attack_pattern_name,
            attack_pattern_description=first.attack_pattern_description,
            threat_id=first.threat_id,
            threat_name=first.threat_name,
            owasp_llm_ids=first.owasp_llm_ids,
            risk_card_ref=first.risk_card_ref,
            candidates=submitted_snapshot,
        )

        seed_call_logs: list[dict] = []
        batch_response: BatchFilterResponse | None = None
        reconciliation_error: str | None = None

        for attempt in (1, 2):
            try:
                llm_result = client.complete(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format=BatchFilterResponse,
                )
            except Exception as exc:
                # Infrastructure/parse exception — record a synthetic
                # call log entry since we have no LLMResult.
                seed_call_logs.append(
                    {
                        "call": "candidate_filter",
                        "seed_id": seed_id,
                        "attempt": attempt,
                        "system_prompt": system_prompt,
                        "user_prompt": user_prompt,
                        "response": None,
                        "error": f"Exception during complete(): {exc}",
                        "prompt_tokens": None,
                        "completion_tokens": None,
                        "duration_ms": None,
                    }
                )
                reconciliation_error = f"Exception during complete(): {exc}"
                if attempt == 1:
                    logger.warning(
                        "Filter call failed for seed %s (attempt 1): %s — retrying",
                        seed_id,
                        exc,
                    )
                    continue
                break

            seed_call_logs.append(_build_call_log_entry(seed_id, llm_result, attempt))

            # Validate llm_result.content as BatchFilterResponse inside
            # each attempt so wrong content types and validation errors
            # are caught and retried.
            try:
                raw_content = llm_result.content
                if raw_content is None:
                    raise ValueError("LLM returned None content (refusal or empty)")
                if isinstance(raw_content, BatchFilterResponse):
                    batch_response = raw_content
                elif isinstance(raw_content, dict):
                    batch_response = BatchFilterResponse.model_validate(raw_content)
                elif isinstance(raw_content, str):
                    # Some clients may return raw JSON strings.
                    batch_response = BatchFilterResponse.model_validate(
                        json.loads(raw_content)
                    )
                else:
                    # Wrong content type — try to coerce via model_validate.
                    batch_response = BatchFilterResponse.model_validate(raw_content)
            except (
                ValidationError,
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ) as exc:
                batch_response = None
                reconciliation_error = (
                    f"Failed to parse LLM content as BatchFilterResponse: {exc}"
                )
                if attempt == 1:
                    logger.warning(
                        "Filter content validation failed for seed %s "
                        "(attempt 1): %s — retrying",
                        seed_id,
                        reconciliation_error,
                    )
                    continue
                break

            try:
                ok, err = _reconcile_filter_response(
                    batch_response,
                    seed_id,
                    submitted_ids,
                )
            except Exception as exc:
                ok = False
                err = f"Reconciliation exception: {exc}"

            if ok:
                reconciliation_error = None
                break
            reconciliation_error = err
            if attempt == 1:
                logger.warning(
                    "Filter reconciliation failed for seed %s (attempt 1): "
                    "%s — retrying",
                    seed_id,
                    err,
                )
                # Discard malformed batch and retry.
                continue

        if reconciliation_error is not None or batch_response is None:
            raise FilterProtocolError(
                f"Filter protocol failure for seed {seed_id} after retry: "
                f"{reconciliation_error}",
                call_log_entries=seed_call_logs,
            )

        # Reconciliation passed — resolve metadata from candidate lookup.
        # Wrap post-reconciliation work so unexpected exceptions carry
        # accumulated seed_call_logs rather than empty evidence.
        try:
            accepted_verdicts: list[FilterVerdict] = []
            rejected_verdicts: list[FilterVerdict] = []
            for v in batch_response.verdicts:
                if v.verdict == "accept":
                    accepted_verdicts.append(v)
                else:
                    rejected_verdicts.append(v)

            # Build enriched rejection records from candidate lookup.
            rejection_records: list[RejectionRecord] = []
            for v in rejected_verdicts:
                cand = candidate_lookup.get(v.candidate_id)
                if cand is not None:
                    rejection_records.append(
                        RejectionRecord(
                            candidate_id=v.candidate_id,
                            entry_point=cand.entry_point,
                            atlas_technique_ids=cand.atlas_technique_ids,
                            rationale=v.rationale,
                        )
                    )

            original_seed = seed_lookup.get(seed_id)
            if original_seed is None:
                logger.warning(
                    "Seed %s not found in seed lookup — skipping %d accepted verdicts",
                    seed_id,
                    len(accepted_verdicts),
                )
                return [], 0, len(seed_candidates), seed_call_logs

            seed_results: list[FilteredSeed] = []
            for verdict in accepted_verdicts:
                cand = candidate_lookup.get(verdict.candidate_id)
                if cand is None:
                    # Should not happen after reconciliation, but guard anyway.
                    logger.error(
                        "Candidate %s not in lookup after reconciliation — skipping",
                        verdict.candidate_id,
                    )
                    continue
                seed_results.append(
                    FilteredSeed(
                        **original_seed.model_dump(),
                        pinned_entry_point=cand.entry_point,
                        pinned_technique_ids=cand.atlas_technique_ids,
                        pinned_technique_names=cand.atlas_technique_names,
                        entry_point_id=cand.entry_point_id,
                        candidate_id=cand.candidate_id,
                        rejection_rationales=rejection_records,
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
            return (
                seed_results,
                seed_accepted,
                seed_total - seed_accepted,
                seed_call_logs,
            )
        except Exception as exc:
            raise FilterProtocolError(
                f"Unexpected post-reconciliation failure for seed {seed_id}: {exc}",
                call_log_entries=seed_call_logs,
            ) from exc

    total_accepted = 0
    total_rejected = 0
    results: list[FilteredSeed] = []
    call_log_entries: list[dict] = []
    protocol_errors: list[FilterProtocolError] = []

    max_workers = min(8, len(groups))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_filter_one_seed, sid, cands): sid
            for sid, cands in groups.items()
        }
        for future in as_completed(futures):
            seed_id = futures[future]
            try:
                seed_results, n_acc, n_rej, seed_logs = future.result()
                results.extend(seed_results)
                total_accepted += n_acc
                total_rejected += n_rej
                call_log_entries.extend(seed_logs)
            except FilterProtocolError as exc:
                logger.error("Filter protocol failure for seed %s: %s", seed_id, exc)
                protocol_errors.append(exc)
            except Exception as exc:
                # Any unexpected exception from _filter_one_seed is an
                # infrastructure/protocol failure, not an ordinary rejection.
                # Convert to FilterProtocolError so the run fails cleanly
                # with evidence rather than silently dropping a seed.
                # Preserve any call logs the exception already carries.
                logger.exception("Filter infrastructure failure for seed %s", seed_id)
                if isinstance(exc, FilterProtocolError):
                    protocol_errors.append(exc)
                else:
                    protocol_errors.append(
                        FilterProtocolError(
                            f"Filter infrastructure failure for seed {seed_id}: {exc}",
                            call_log_entries=[],
                        )
                    )

    if protocol_errors:
        # Collect all call logs (including from successful seeds) so the
        # runner can persist them before failing the run.
        all_logs = list(call_log_entries)
        for err in protocol_errors:
            all_logs.extend(err.call_log_entries)
        first_err = protocol_errors[0]
        raise FilterProtocolError(str(first_err), call_log_entries=all_logs)

    logger.info(
        "Filter: %d/%d candidates survived (%d rejected)",
        total_accepted,
        total_accepted + total_rejected,
        total_rejected,
    )

    return results, call_log_entries


# ---------------------------------------------------------------------------
# Rule-based candidate pre-filter
# ---------------------------------------------------------------------------
#
# Deterministic rules that reject structurally impossible candidates
# BEFORE the LLM filter.  Each rule takes a technique ID, entry point
# name, entry point type, and capability profile; returns (reject,
# rationale).  Rules REJECT ONLY -- they never accept.  All non-rejected
# candidates pass to the LLM filter.
#
# The old DIRECT_ONLY_TECHNIQUES / apply_technique_entry_point_filter
# post-filter is absorbed here as _rule_direct_vs_indirect.
#
# Entry point controllability classification (classify_entry_point) and
# keyword constants are imported from scenario_forge.models.capability_profile.


def is_indirect_entry_point(
    entry_point_name: str,
    direction: str,
    controllability: str | None = None,
) -> bool:
    """Return True if the entry point is an indirect channel.

    Convenience wrapper around :func:`classify_entry_point` for backward
    compatibility.
    """
    return (
        classify_entry_point(entry_point_name, direction, controllability) == "indirect"
    )


# Legacy constant preserved for backward compatibility in tests.
# The rule engine now uses TECHNIQUE_PROPERTIES instead.
DIRECT_ONLY_TECHNIQUES: frozenset[str] = frozenset(
    {
        tid
        for tid, props in TECHNIQUE_PROPERTIES.items()
        if props.get("requires_direct_access")
    }
)


def _get_technique_name(technique_id: str) -> str:
    """Look up human-readable name for a technique ID."""
    return ATLAS_TECHNIQUE_NAMES.get(technique_id, technique_id)


# --- Rule functions ---
#
# Each rule takes (technique_id, entry_point_name, ep_type, profile) and
# returns (reject: bool, rationale: str | None).  Rationale is a
# fixed-format template string when reject=True, None otherwise.


def _rule_supply_chain_mismatch(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0048/T0010 supply chain attacks are incompatible with runtime entry points."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("target_layer") != "supply_chain":
        return False, None
    if ep_type in ("direct", "indirect"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"supply chain attacks target the model development pipeline, "
            f"not runtime inputs."
        )
    return False, None


def _rule_entry_point_not_interactive(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """System-controlled entry points are not attacker-accessible."""
    if ep_type != "system":
        return False, None
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if "system" in props.get("incompatible_entry_types", set()):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"system-controlled entry points are not attacker-accessible."
        )
    return False, None


def _rule_wrong_zone_direction(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Output-direction entry points cannot serve as attack ingress."""
    if ep_type != "system":
        return False, None
    # Check if the entry point name suggests output-only semantics.
    name_lower = entry_point_name.lower()
    output_signals = ("output", "response", "reply", "outbound", "emit")
    if not any(sig in name_lower for sig in output_signals):
        return False, None
    return True, (
        f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
        f"is incompatible with entry point type {ep_type} -- "
        f"output-direction entry points cannot be attack ingress channels."
    )


def _rule_technique_incompatible(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Technique's incompatible_entry_types includes this entry point type."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    incompatible = props.get("incompatible_entry_types", set())
    if ep_type in incompatible:
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"technique cannot target this entry point type."
        )
    return False, None


def _rule_direct_vs_indirect(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0051.000 requires direct access; T0051.001 requires indirect."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("requires_direct_access") and ep_type == "indirect":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"technique requires direct attacker access to the prompt interface."
        )
    # T0051.001 and similar indirect-only techniques: reject on direct EPs.
    if technique_id == "AML.T0051.001" and ep_type == "direct":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"indirect prompt injection requires a non-user-facing data channel."
        )
    return False, None


def _rule_preparatory_technique(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """T0043/T0044/T0016/T0021 are pre-attack prep, not entry-point-exploitable."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    if props.get("is_preparatory"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"preparatory techniques are pre-attack steps that do not "
            f"directly exploit runtime entry points."
        )
    return False, None


def _rule_technique_targets_wrong_layer(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Technique targets an infrastructure layer incompatible with the entry point."""
    props = TECHNIQUE_PROPERTIES.get(technique_id)
    if props is None:
        return False, None
    target_layer = props.get("target_layer")
    if target_layer is None:
        return False, None

    # Tool schema injection via direct user chat interface.
    if target_layer == "tool_schema" and ep_type == "direct":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"tool schema injection targets tool metadata trust boundaries, "
            f"not direct user chat interfaces."
        )
    # Training-layer techniques via runtime entry points.
    if target_layer == "training" and ep_type in ("direct", "indirect"):
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"training pipeline attacks target the model development process, "
            f"not runtime inputs."
        )
    # Embedding manipulation via direct user input.
    if target_layer == "embedding" and ep_type == "direct":
        return True, (
            f"Rejected: {technique_id} ({_get_technique_name(technique_id)}) "
            f"is incompatible with entry point type {ep_type} -- "
            f"embedding manipulation targets vector stores, not direct "
            f"user input channels."
        )
    return False, None


# Ordered list of all per-technique rules.  Evaluated top-to-bottom; first rejection wins.
_ALL_RULES = [
    _rule_supply_chain_mismatch,
    _rule_entry_point_not_interactive,
    _rule_wrong_zone_direction,
    _rule_technique_incompatible,
    _rule_direct_vs_indirect,
    _rule_preparatory_technique,
    _rule_technique_targets_wrong_layer,
]


# --- Threat-level prerequisite rules ---
#
# These check whether a candidate's OWASP threat (threat_id) has zone or
# capability prerequisites that the profile does not satisfy.  Unlike
# per-technique rules, these operate at the candidate level and reject
# the entire candidate regardless of technique.


def _rule_seed_profile_compatibility(
    seed_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject seeds that are structurally infeasible for the given profile.

    AP-T9-05 "false attribution via identity proxy" requires persistent
    memory for cross-user identity manipulation.  Without persistent
    session state, the attack pattern is infeasible.
    """
    if seed_id == "AP-T9-05" and not profile.has_persistent_memory:
        return True, (
            f"Rejected: seed {seed_id} (false attribution via identity proxy) "
            f"requires persistent memory for cross-user identity manipulation, "
            f"but profile has has_persistent_memory=False."
        )
    return False, None


def _rule_threat_requires_zone(
    threat_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject if the profile is missing zones required by the threat.

    Checks both ``required_zones`` (all must be present) and
    ``required_zones_any`` (at least one must be present).
    """
    prereqs = THREAT_PREREQUISITES.get(threat_id)
    if prereqs is None:
        return False, None

    active = set(profile.zones_active)

    # AND semantics: all required_zones must be active
    required = prereqs.get("required_zones", [])
    missing = [z for z in required if z not in active]
    if missing:
        return True, (
            f"Rejected: threat {threat_id} requires zone(s) "
            f"{missing} but profile only has {sorted(active)}."
        )

    # OR semantics: at least one of required_zones_any must be active
    any_of = prereqs.get("required_zones_any", [])
    if any_of and not active.intersection(any_of):
        return True, (
            f"Rejected: threat {threat_id} requires at least one of "
            f"zone(s) {any_of} but profile only has {sorted(active)}."
        )

    return False, None


def _rule_threat_requires_capability(
    threat_id: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Reject if the profile is missing capabilities required by the threat."""
    prereqs = THREAT_PREREQUISITES.get(threat_id)
    if prereqs is None:
        return False, None

    required_caps = prereqs.get("required_capabilities", [])
    if not required_caps:
        return False, None

    _CAP_GETTERS: dict[str, str] = {
        "has_persistent_memory": "has_persistent_memory",
        "multi_agent": "multi_agent",
        "hitl": "hitl",
    }

    missing = []
    for cap in required_caps:
        attr = _CAP_GETTERS.get(cap)
        if attr is None:
            continue
        if not getattr(profile, attr, False):
            missing.append(cap)

    if missing:
        return True, (
            f"Rejected: threat {threat_id} requires capability(ies) "
            f"{missing} but profile does not have them."
        )

    return False, None


# --- Rule-based filter orchestration ---


def _run_rules_on_technique(
    technique_id: str,
    entry_point_name: str,
    ep_type: str,
    profile: CapabilityProfile,
) -> tuple[bool, str | None]:
    """Run all rules on a single (technique, entry_point) pair.

    Returns (True, rationale) on first rejection, (False, None) if all pass.
    """
    for rule in _ALL_RULES:
        reject, rationale = rule(technique_id, entry_point_name, ep_type, profile)
        if reject:
            return True, rationale
    return False, None


def apply_rule_based_filter(
    candidates: list[CandidateTriple],
    profile: CapabilityProfile,
) -> tuple[list[CandidateTriple], list[CandidateTriple], list[RejectionRecord]]:
    """Run deterministic rules on candidates, rejecting structural impossibilities.

    For each candidate, every technique in its combo is checked against all
    rules.  If ALL techniques in a combo are rejected, the entire candidate
    is rejected.  If some but not all techniques are rejected, the combo is
    pruned to keep only compatible techniques (the candidate survives with
    the reduced combo).

    Args:
        candidates: Output of :func:`expand_candidates`.
        profile: Capability profile (provides entry-point directions).

    Returns:
        Tuple of (rule_passed, rule_rejected, rejection_verdicts).
        ``rule_passed`` candidates proceed to the LLM filter.
        ``rule_rejected`` candidates are dropped with rationales.
        ``rejection_verdicts`` are RejectionRecord objects for provenance.
    """
    if not candidates:
        return [], [], []

    rule_passed: list[CandidateTriple] = []
    rule_rejected: list[CandidateTriple] = []
    rejection_verdicts: list[RejectionRecord] = []

    for candidate in candidates:
        # --- Seed-level compatibility checks (reject entire candidate) ---
        threat_reject, threat_rationale = _rule_seed_profile_compatibility(
            candidate.seed_id,
            profile,
        )

        # --- Threat-level prerequisite checks (reject entire candidate) ---
        if not threat_reject:
            threat_reject, threat_rationale = _rule_threat_requires_zone(
                candidate.threat_id,
                profile,
            )
        if not threat_reject:
            threat_reject, threat_rationale = _rule_threat_requires_capability(
                candidate.threat_id,
                profile,
            )
        if threat_reject:
            rule_rejected.append(candidate)
            rejection_verdicts.append(
                RejectionRecord(
                    candidate_id=candidate.candidate_id,
                    entry_point=candidate.entry_point,
                    atlas_technique_ids=candidate.atlas_technique_ids,
                    rationale=threat_rationale or "Threat prerequisite not met.",
                )
            )
            continue

        # Use the candidate's own direction and controllability, not a
        # name-keyed profile lookup — same-name EPs with different
        # canonical identities must not overwrite each other.
        direction = candidate.direction or "bidirectional"
        ctrl = candidate.controllability
        ep_type = classify_entry_point(candidate.entry_point, direction, ctrl)

        # Check each technique in the combo.
        compatible_ids: list[str] = []
        compatible_names: list[str] = []
        compatible_descs: list[str] = []
        combo_rationales: list[str] = []

        for tid, tname, tdesc in zip(
            candidate.atlas_technique_ids,
            candidate.atlas_technique_names,
            candidate.atlas_technique_descriptions,
        ):
            reject, rationale = _run_rules_on_technique(
                tid,
                candidate.entry_point,
                ep_type,
                profile,
            )
            if reject:
                combo_rationales.append(rationale)  # type: ignore[arg-type]
            else:
                compatible_ids.append(tid)
                compatible_names.append(tname)
                compatible_descs.append(tdesc)

        if not compatible_ids:
            # All techniques rejected -- reject the entire candidate.
            rule_rejected.append(candidate)
            rejection_verdicts.append(
                RejectionRecord(
                    candidate_id=candidate.candidate_id,
                    entry_point=candidate.entry_point,
                    atlas_technique_ids=candidate.atlas_technique_ids,
                    rationale=combo_rationales[0]
                    if combo_rationales
                    else "Rule-rejected.",
                )
            )
            continue

        if len(compatible_ids) < len(candidate.atlas_technique_ids):
            # Partial pruning: some techniques removed from combo.
            pruned = set(candidate.atlas_technique_ids) - set(compatible_ids)
            logger.info(
                "Rule pre-filter: pruned %s from combo for %s",
                pruned,
                candidate.entry_point,
            )
            new_candidate_id = compute_candidate_id(
                candidate.seed_id,
                candidate.entry_point_id,
                compatible_ids,
            )
            # Reconstruct the pruned candidate through model_validate so
            # canonical IDs are re-validated and nested collections are
            # not shared with the original.  Using model_validate instead
            # of model_copy(update=...) ensures the new candidate_id is
            # checked against the canonical recomputation.
            candidate = CandidateTriple.model_validate(
                candidate.model_dump(mode="python")
                | {
                    "atlas_technique_ids": tuple(compatible_ids),
                    "atlas_technique_names": tuple(compatible_names),
                    "atlas_technique_descriptions": tuple(compatible_descs),
                    "candidate_id": new_candidate_id,
                }
            )

        rule_passed.append(candidate)

    if rule_rejected:
        logger.info(
            "Rule pre-filter: %d/%d candidates rejected, %d passed to LLM filter",
            len(rule_rejected),
            len(rule_rejected) + len(rule_passed),
            len(rule_passed),
        )

    # Re-check for candidate collisions after rule pruning — pruning
    # techniques may cause two formerly-distinct candidates to converge
    # to the same candidate_id.
    _check_candidate_collisions(rule_passed)

    return rule_passed, rule_rejected, rejection_verdicts


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
                new_entry_point = 1 if fs.entry_point_id not in seen_entry_points else 0
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
            seen_entry_points.add(chosen.entry_point_id)
            remaining_indices.remove(best_idx)

        logger.warning(
            "Capped %s from %d to %d scenarios (--max-scenarios-per-pattern)",
            seed_id,
            len(group),
            len(selected),
        )
        result.extend(selected)

    return result
