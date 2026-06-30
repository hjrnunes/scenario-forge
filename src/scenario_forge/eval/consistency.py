"""Cross-layer consistency metrics for scenario evaluation.

Measures alignment between the three generated layers:
- Narrative (zone_sequence, entry_point, steps)
- Attack tree (node zones, threat_ids, tree structure)
- Gherkin feature file (zone annotations, Background, steps)
"""

from __future__ import annotations

import re
from typing import Any

from scenario_forge.models.capability_profile import ZONE_DISPLAY_NAMES, ZONE_NAMES


def _jaccard(a: set, b: set) -> float:
    """Jaccard similarity of two sets. Returns 1.0 if both are empty."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def _collect_tree_zones(node: dict[str, Any]) -> set[str]:
    """Recursively collect all zone values from attack tree nodes."""
    zones: set[str] = set()
    zone = node.get("zone")
    if zone is not None:
        zones.add(str(zone))
    for child in node.get("children") or []:
        zones |= _collect_tree_zones(child)
    return zones


def _collect_tree_leaves(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Recursively collect all leaf nodes from the attack tree."""
    children = node.get("children") or []
    if not children:
        return [node]
    leaves: list[dict[str, Any]] = []
    for child in children:
        leaves.extend(_collect_tree_leaves(child))
    return leaves


def _extract_gherkin_zones(gherkin_text: str) -> set[str]:
    """Extract zone annotations from Gherkin text.

    Supports both legacy integer annotations (e.g. ``# Zone 2``) and
    string zone names (e.g. ``# Zone reasoning``).  Legacy integers are
    mapped to the canonical string name via ``ZONE_NAMES``.
    """
    _INT_TO_NAME = dict(enumerate(ZONE_NAMES, 1))
    zones: set[str] = set()
    # Match "# Zone <word_or_number>"
    for match in re.finditer(r"#\s*[Zz]one\s+(\S+)", gherkin_text):
        token = match.group(1)
        # Legacy integer form
        if token.isdigit():
            name = _INT_TO_NAME.get(int(token))
            if name:
                zones.add(name)
        elif token in set(ZONE_NAMES):
            zones.add(token)
        # Also accept display names written as-is (e.g. "Input")
        else:
            for zn, display in ZONE_DISPLAY_NAMES.items():
                if token.lower() in display.lower():
                    zones.add(zn)
                    break
    return zones


def _normalize_entry_point(ep: str) -> str:
    """Normalize entry point text for fuzzy matching."""
    return re.sub(r"[^a-z0-9]+", " ", ep.lower()).strip()


def zone_alignment(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> float:
    """Jaccard similarity of zone sets across narrative, attack tree, and Gherkin.

    Computes pairwise Jaccard between:
    - narrative.zone_sequence zones
    - attack tree node zones (recursive)
    - Gherkin zone annotations (if gherkin_text provided)

    Returns the average pairwise Jaccard similarity.
    """
    narrative = scenario.get("narrative", {})
    narrative_zones = set(narrative.get("zone_sequence", []))

    tree_root = scenario.get("attack_tree", {}).get("root", {})
    tree_zones = _collect_tree_zones(tree_root)

    pairs: list[float] = [_jaccard(narrative_zones, tree_zones)]

    if gherkin_text is not None:
        gherkin_zones = _extract_gherkin_zones(gherkin_text)
        if gherkin_zones:  # Only count if gherkin has zone annotations
            pairs.append(_jaccard(narrative_zones, gherkin_zones))
            pairs.append(_jaccard(tree_zones, gherkin_zones))

    return sum(pairs) / len(pairs) if pairs else 1.0


def entry_point_agreement(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> int:
    """Check if the narrative entry_point appears in the Gherkin Background or attack tree root.

    Returns 1 if found in at least one location, 0 otherwise.
    """
    narrative = scenario.get("narrative", {})
    entry_point = narrative.get("entry_point", "")
    if not entry_point:
        return 0

    ep_norm = _normalize_entry_point(entry_point)

    # Check attack tree root label
    tree_root = scenario.get("attack_tree", {}).get("root", {})
    root_label = _normalize_entry_point(tree_root.get("label", ""))
    root_desc = _normalize_entry_point(tree_root.get("description", "") or "")

    # Check if entry point keywords appear in root
    ep_tokens = set(ep_norm.split())
    root_tokens = set(root_label.split()) | set(root_desc.split())

    # At least half the entry point tokens should appear
    if ep_tokens and len(ep_tokens & root_tokens) >= len(ep_tokens) * 0.4:
        return 1

    # Check Gherkin Background
    if gherkin_text:
        bg_match = re.search(
            r"Background:.*?(?=Scenario|$)", gherkin_text, re.DOTALL | re.IGNORECASE
        )
        if bg_match:
            bg_norm = _normalize_entry_point(bg_match.group())
            bg_tokens = set(bg_norm.split())
            if ep_tokens and len(ep_tokens & bg_tokens) >= len(ep_tokens) * 0.4:
                return 1

    return 0


def step_node_correspondence(scenario: dict[str, Any]) -> float:
    """Ratio of narrative steps with a plausible mapping to attack tree leaves.

    A narrative step is considered mapped if a leaf node exists in the same zone
    and shares at least one significant word with the step action.
    """
    narrative = scenario.get("narrative", {})
    steps = narrative.get("steps", [])
    if not steps:
        return 0.0

    tree_root = scenario.get("attack_tree", {}).get("root", {})
    leaves = _collect_tree_leaves(tree_root)

    # Build a mapping of zone -> set of leaf label tokens
    zone_leaf_tokens: dict[str, set[str]] = {}
    for leaf in leaves:
        z = leaf.get("zone")
        if z is not None:
            label_tokens = set(_normalize_entry_point(leaf.get("label", "")).split())
            desc_tokens = set(
                _normalize_entry_point(leaf.get("description", "") or "").split()
            )
            zone_leaf_tokens.setdefault(z, set()).update(label_tokens | desc_tokens)

    # Stopwords to exclude from matching
    stopwords = {
        "the",
        "a",
        "an",
        "to",
        "in",
        "of",
        "and",
        "or",
        "is",
        "for",
        "with",
        "on",
        "at",
        "by",
        "from",
        "that",
        "this",
        "it",
        "as",
    }

    mapped = 0
    for step in steps:
        step_zone = step.get("zone")
        step_action = _normalize_entry_point(step.get("action", ""))
        step_tokens = set(step_action.split()) - stopwords

        if step_zone in zone_leaf_tokens:
            leaf_tokens = zone_leaf_tokens[step_zone] - stopwords
            if step_tokens and leaf_tokens and (step_tokens & leaf_tokens):
                mapped += 1

    return mapped / len(steps)


def score_consistency(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> dict[str, Any]:
    """Compute all cross-layer consistency metrics for a single scenario.

    Returns:
        Dict with zone_alignment, entry_point_agreement, step_node_correspondence,
        and an overall mean score.
    """
    za = zone_alignment(scenario, gherkin_text)
    epa = entry_point_agreement(scenario, gherkin_text)
    snc = step_node_correspondence(scenario)

    return {
        "zone_alignment": round(za, 4),
        "entry_point_agreement": epa,
        "step_node_correspondence": round(snc, 4),
        "mean": round((za + epa + snc) / 3, 4),
    }
