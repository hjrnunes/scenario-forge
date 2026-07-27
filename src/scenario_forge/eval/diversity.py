"""Batch diversity metrics for scenario evaluation.

Measures how well a batch of scenarios covers the threat landscape:
- Entry point entropy (Shannon entropy, normalized)
- Zone coverage (fraction of 5 Schneider zones used)
- Actor type entropy
- Capability level distribution evenness
- Pairwise title uniqueness
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from scenario_forge.models.capability_profile import (
    ZONE_NAMES,
    CapabilityProfile,
)


def _shannon_entropy(values: list[str], normalize: bool = True) -> float:
    """Compute Shannon entropy of a discrete distribution.

    Args:
        values: List of category values.
        normalize: If True, normalize by log2(n_categories) to get [0, 1].

    Returns:
        Entropy value. Returns 0.0 for empty or single-value lists.
    """
    if not values:
        return 0.0

    counts = Counter(values)
    n = len(values)
    n_categories = len(counts)

    if n_categories <= 1:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    if normalize:
        max_entropy = math.log2(n_categories)
        if max_entropy > 0:
            entropy /= max_entropy

    return entropy


def _jaccard_tokens(a: str, b: str, stopwords: set[str] | None = None) -> float:
    """Jaccard similarity of token sets from two strings.

    Args:
        a: First string.
        b: Second string.
        stopwords: Optional set of tokens to exclude before comparison.
    """
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if stopwords:
        tokens_a -= stopwords
        tokens_b -= stopwords
    if not tokens_a and not tokens_b:
        return 1.0
    union = tokens_a | tokens_b
    if not union:
        return 1.0
    return len(tokens_a & tokens_b) / len(union)


def _extract_domain_stopwords(titles: list[str], threshold: float = 0.5) -> set[str]:
    """Extract domain stopwords — words appearing in more than *threshold* of titles.

    These are common domain vocabulary (e.g. "Policy", "Agent", "Attack") that
    inflate Jaccard similarity without indicating genuine duplication.
    """
    if not titles:
        return set()

    word_counts: Counter[str] = Counter()
    for title in titles:
        unique_words = set(title.lower().split())
        word_counts.update(unique_words)

    n = len(titles)
    return {word for word, count in word_counts.items() if count / n > threshold}


def entry_point_entropy(
    scenarios: list[dict[str, Any]],
    expected_entry_points: int | None = None,
    profile: CapabilityProfile | None = None,
) -> float | dict[str, Any]:
    """Shannon entropy of entry points across scenarios (normalized).

    Extracts entry point identity from each scenario.  Prefers the
    canonical ``entry_point_id`` from ``candidate_filter`` provenance;
    falls back to ``narrative.entry_point`` resolved against the profile
    for scenarios without provenance.

    When *expected_entry_points* is given as an integer count and
    *profile* is provided, coverage is computed as exact canonical set
    arithmetic: ``len(used_ids & expected_ids) / len(expected_ids)``
    where ``expected_ids`` are the canonical ingress entry-point IDs
    from the profile.  Unknown IDs do not inflate coverage.

    When *profile* is not provided, falls back to the integer-count
    approach (clamped to [0, 1]).

    Args:
        scenarios: List of scenario dicts.
        expected_entry_points: If provided, also compute entry_point_coverage.
        profile: If provided, use canonical profile entry-point IDs for
            exact set-based coverage.

    Returns:
        float (entropy) when expected_entry_points is None, otherwise a dict
        with 'entropy' and 'entry_point_coverage'.
    """
    # Build a normalized-name → set-of-entry_point_ids lookup from the
    # profile for fallback resolution of narrative display names.  Using
    # a set per name avoids collapsing same-name entry points with
    # different canonical identities.  Normalization uses the same
    # canonical name function as entry_point_id computation.
    from scenario_forge.models.capability_profile import _canonical_entry_point_name

    ep_name_to_ids: dict[str, set[str]] = {}
    if profile is not None:
        for ep in profile.entry_points:
            key = _canonical_entry_point_name(ep.name)
            ep_name_to_ids.setdefault(key, set()).add(ep.entry_point_id)

    used_ids: set[str] = set()
    entry_point_list: list[str] = []
    for s in scenarios:
        # Prefer canonical entry_point_id from provenance.
        cf = s.get("candidate_filter") or {}
        ep_id = cf.get("entry_point_id")
        if ep_id:
            used_ids.add(ep_id)
            entry_point_list.append(ep_id)
        else:
            ep = s.get("narrative", {}).get("entry_point", "")
            if ep:
                # Resolve display name to canonical ID(s) when possible.
                # Unique match: credit the single ID.
                # Ambiguous match (multiple IDs): unresolved — credit none.
                # Unknown name without profile: use canonical name as identity.
                matched_ids = ep_name_to_ids.get(_canonical_entry_point_name(ep))
                if matched_ids and len(matched_ids) == 1:
                    resolved = next(iter(matched_ids))
                    used_ids.add(resolved)
                    entry_point_list.append(resolved)
                elif profile is None:
                    # No profile — fall back to canonical name as identity.
                    canonical = _canonical_entry_point_name(ep)
                    used_ids.add(canonical)
                    entry_point_list.append(canonical)
                # Ambiguous or unknown with profile — do not inflate coverage.

    entropy = round(_shannon_entropy(entry_point_list), 4)

    if expected_entry_points is None:
        return entropy

    if profile is not None:
        # Exact canonical set arithmetic.
        expected_ids = {
            ep.entry_point_id for ep in profile.entry_points if ep.direction != "output"
        }
        # Only count IDs that are in the expected set — unknown IDs
        # must not inflate coverage.
        covered_ids = used_ids & expected_ids
        covered = len(covered_ids)
        raw_coverage = covered / len(expected_ids) if expected_ids else 0.0
    else:
        actual_unique = len(set(entry_point_list))
        raw_coverage = (
            actual_unique / expected_entry_points if expected_entry_points > 0 else 0.0
        )

    coverage = round(min(1.0, max(0.0, raw_coverage)), 4)
    result: dict[str, Any] = {
        "entropy": entropy,
        "entry_point_coverage": coverage,
    }
    if profile is not None:
        expected_ids = {
            ep.entry_point_id for ep in profile.entry_points if ep.direction != "output"
        }
        covered_ids = used_ids & expected_ids
        result["covered_entry_point_count"] = len(covered_ids)
        result["expected_entry_point_count"] = len(expected_ids)
        result["covered_entry_point_ids"] = sorted(covered_ids)
        result["expected_entry_point_ids"] = sorted(expected_ids)
    return result


def zone_coverage(
    scenarios: list[dict[str, Any]],
    active_zones: set[str] | None = None,
) -> float | dict[str, Any]:
    """Fraction of zones represented across all scenarios.

    Args:
        scenarios: List of scenario dicts.
        active_zones: If provided, compute coverage as fraction of *active*
            zones used (not all 5) and flag scenarios referencing zones
            outside the active set. Returns a dict instead of a bare float.

    Returns:
        float (raw coverage vs 5 zones) when active_zones is None, otherwise
        a dict with 'raw_coverage', 'active_zone_coverage', and
        'out_of_scope_zone_violations'.
    """
    all_zones: set[str] = set()
    for s in scenarios:
        zones = s.get("narrative", {}).get("zone_sequence", [])
        all_zones.update(str(z) for z in zones)

    valid_zone_names = set(ZONE_NAMES)
    raw_coverage = round(len(all_zones & valid_zone_names) / len(ZONE_NAMES), 4)

    if active_zones is None:
        return raw_coverage

    # Contextualized coverage against active zones
    covered_active = all_zones & active_zones
    active_coverage = (
        round(len(covered_active) / len(active_zones), 4) if active_zones else 0.0
    )

    # Find scenarios referencing zones outside the active set
    violations: list[dict[str, Any]] = []
    for s in scenarios:
        scenario_id = s.get("scenario_id", "unknown")
        zones = {str(z) for z in s.get("narrative", {}).get("zone_sequence", [])}
        out_of_scope = zones - active_zones
        if out_of_scope:
            violations.append(
                {
                    "scenario_id": scenario_id,
                    "out_of_scope_zones": sorted(out_of_scope),
                }
            )

    return {
        "raw_coverage": raw_coverage,
        "active_zone_coverage": active_coverage,
        "out_of_scope_zone_violations": violations,
    }


def goal_category_entropy(scenarios: list[dict[str, Any]]) -> float:
    """Shannon entropy of goal categories across scenarios (normalized)."""
    goal_categories = []
    for s in scenarios:
        ap = s.get("actor_profile")
        if ap and isinstance(ap, dict):
            gc = ap.get("goal_category", "")
            if gc:
                goal_categories.append(gc)
    return round(_shannon_entropy(goal_categories), 4)


def actor_type_entropy(scenarios: list[dict[str, Any]]) -> float:
    """Shannon entropy of actor types across scenarios (normalized)."""
    actor_types = []
    for s in scenarios:
        ap = s.get("actor_profile")
        if ap and isinstance(ap, dict):
            at = ap.get("actor_type", "")
            if at:
                actor_types.append(at)
    return round(_shannon_entropy(actor_types), 4)


def capability_level_evenness(scenarios: list[dict[str, Any]]) -> float:
    """Evenness of capability level distribution (normalized Shannon entropy).

    Capability levels: novice, intermediate, advanced, expert.
    """
    levels = []
    for s in scenarios:
        ap = s.get("actor_profile")
        if ap and isinstance(ap, dict):
            cl = ap.get("capability_level", "")
            if cl:
                levels.append(cl)
    return round(_shannon_entropy(levels), 4)


def title_uniqueness(scenarios: list[dict[str, Any]], top_k: int = 5) -> float:
    """Pairwise title uniqueness: 1 - mean of top-k Jaccard similarities.

    Before computing Jaccard, extracts "domain stopwords" — words appearing in
    more than 50% of titles — and excludes them.  This prevents common domain
    vocabulary (e.g. "Policy", "Agent", "Manipulation") from penalizing batches
    whose titles are genuinely diverse.

    Uses the mean of the top-k most similar pairs rather than a single max,
    so that one duplicate pair penalizes the score but does not drive it to 0.0
    on its own.  When fewer than *top_k* pairs exist, all pairs are averaged.

    Returns 1.0 if all titles are completely distinct, lower if duplicates exist.
    Returns 1.0 for 0 or 1 scenarios.
    """
    titles = []
    for s in scenarios:
        title = s.get("narrative", {}).get("title", "")
        if title:
            titles.append(title)

    if len(titles) <= 1:
        return 1.0

    domain_stopwords = _extract_domain_stopwords(titles)

    similarities: list[float] = []
    for i in range(len(titles)):
        for j in range(i + 1, len(titles)):
            sim = _jaccard_tokens(titles[i], titles[j], stopwords=domain_stopwords)
            similarities.append(sim)

    # Take the top-k highest similarities and average them.
    similarities.sort(reverse=True)
    k = min(top_k, len(similarities))
    mean_top_k = sum(similarities[:k]) / k

    return round(1.0 - mean_top_k, 4)


def score_diversity(
    scenarios: list[dict[str, Any]],
    *,
    expected_entry_points: int | None = None,
    active_zones: set[str] | None = None,
    profile: CapabilityProfile | None = None,
) -> dict[str, Any]:
    """Compute all batch diversity metrics.

    Args:
        scenarios: List of scenario dicts (parsed YAML).
        expected_entry_points: Number of entry points from the capability
            profile. When provided, entry_point_entropy includes a
            coverage ratio alongside the raw entropy.
        active_zones: Set of active Schneider zones from the capability
            profile. When provided, zone_coverage includes contextualized
            coverage and out-of-scope violation detection.
        profile: When provided, entry_point_entropy uses exact canonical
            set arithmetic against the profile's ingress entry-point IDs
            and returns numerator/denominator evidence.

    Returns:
        Dict with entry_point_entropy, zone_coverage, actor_type_entropy,
        capability_level_evenness, and title_uniqueness.  When context
        parameters are supplied the entropy/coverage values are dicts with
        both raw and contextualized metrics.
    """
    return {
        "entry_point_entropy": entry_point_entropy(
            scenarios,
            expected_entry_points=expected_entry_points,
            profile=profile,
        ),
        "zone_coverage": zone_coverage(scenarios, active_zones=active_zones),
        "actor_type_entropy": actor_type_entropy(scenarios),
        "goal_category_entropy": goal_category_entropy(scenarios),
        "capability_level_evenness": capability_level_evenness(scenarios),
        "title_uniqueness": title_uniqueness(scenarios),
    }
