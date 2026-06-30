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


def entry_point_entropy(scenarios: list[dict[str, Any]]) -> float:
    """Shannon entropy of entry points across scenarios (normalized).

    Extracts narrative.entry_point from each scenario.
    """
    entry_points = []
    for s in scenarios:
        ep = s.get("narrative", {}).get("entry_point", "")
        if ep:
            entry_points.append(ep.lower().strip())
    return round(_shannon_entropy(entry_points), 4)


def zone_coverage(scenarios: list[dict[str, Any]]) -> float:
    """Fraction of the 5 Schneider zones represented across all scenarios."""
    all_zones: set[int] = set()
    for s in scenarios:
        zones = s.get("narrative", {}).get("zone_sequence", [])
        all_zones.update(zones)
    return round(len(all_zones & {1, 2, 3, 4, 5}) / 5, 4)


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


def score_diversity(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute all batch diversity metrics.

    Args:
        scenarios: List of scenario dicts (parsed YAML).

    Returns:
        Dict with entry_point_entropy, zone_coverage, actor_type_entropy,
        capability_level_evenness, and title_uniqueness.
    """
    return {
        "entry_point_entropy": entry_point_entropy(scenarios),
        "zone_coverage": zone_coverage(scenarios),
        "actor_type_entropy": actor_type_entropy(scenarios),
        "capability_level_evenness": capability_level_evenness(scenarios),
        "title_uniqueness": title_uniqueness(scenarios),
    }
