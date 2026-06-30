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

from scenario_forge.models.capability_profile import ZONE_NAMES


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
) -> float | dict[str, Any]:
    """Shannon entropy of entry points across scenarios (normalized).

    Extracts narrative.entry_point from each scenario.

    Args:
        scenarios: List of scenario dicts.
        expected_entry_points: If provided, also compute entry_point_coverage
            (actual unique / expected). When set, returns a dict instead of
            a bare float.

    Returns:
        float (entropy) when expected_entry_points is None, otherwise a dict
        with 'entropy' and 'entry_point_coverage'.
    """
    entry_points = []
    for s in scenarios:
        ep = s.get("narrative", {}).get("entry_point", "")
        if ep:
            entry_points.append(ep.lower().strip())

    entropy = round(_shannon_entropy(entry_points), 4)

    if expected_entry_points is None:
        return entropy

    actual_unique = len(set(entry_points))
    coverage = (
        round(actual_unique / expected_entry_points, 4)
        if expected_entry_points > 0
        else 0.0
    )
    return {
        "entropy": entropy,
        "entry_point_coverage": coverage,
    }


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


def title_uniqueness(scenarios: list[dict[str, Any]]) -> float:
    """Pairwise title uniqueness: 1 - max Jaccard similarity of title token sets.

    Before computing Jaccard, extracts "domain stopwords" — words appearing in
    more than 50% of titles — and excludes them.  This prevents common domain
    vocabulary (e.g. "Policy", "Agent", "Manipulation") from penalizing batches
    whose titles are genuinely diverse.

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

    max_sim = 0.0
    for i in range(len(titles)):
        for j in range(i + 1, len(titles)):
            sim = _jaccard_tokens(titles[i], titles[j], stopwords=domain_stopwords)
            max_sim = max(max_sim, sim)

    return round(1.0 - max_sim, 4)


def score_diversity(
    scenarios: list[dict[str, Any]],
    *,
    expected_entry_points: int | None = None,
    active_zones: set[str] | None = None,
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

    Returns:
        Dict with entry_point_entropy, zone_coverage, actor_type_entropy,
        capability_level_evenness, and title_uniqueness.  When context
        parameters are supplied the entropy/coverage values are dicts with
        both raw and contextualized metrics.
    """
    return {
        "entry_point_entropy": entry_point_entropy(
            scenarios, expected_entry_points=expected_entry_points
        ),
        "zone_coverage": zone_coverage(scenarios, active_zones=active_zones),
        "actor_type_entropy": actor_type_entropy(scenarios),
        "capability_level_evenness": capability_level_evenness(scenarios),
        "title_uniqueness": title_uniqueness(scenarios),
    }
