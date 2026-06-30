"""Gherkin well-formedness metrics for scenario evaluation.

Evaluates the structural quality of generated .feature files:
- Parse success (regex-based validation)
- Step count and keyword balance
- Background presence
- Zone annotation rate on When steps
- Tag consistency across a batch
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any


# Gherkin step keyword pattern
_STEP_RE = re.compile(
    r"^\s*(Given|When|Then|And|But)\s+", re.MULTILINE
)

# Background section
_BACKGROUND_RE = re.compile(r"^\s*Background:", re.MULTILINE)

# Scenario section
_SCENARIO_RE = re.compile(r"^\s*Scenario:", re.MULTILINE)

# Feature declaration
_FEATURE_RE = re.compile(r"^\s*Feature:", re.MULTILINE)

# Zone annotation on steps (typically as comments)
_ZONE_COMMENT_RE = re.compile(r"#\s*[Zz]one\s+\d+")

# Tags (e.g. @misaligned-and-deceptive-behavior)
_TAG_RE = re.compile(r"@([\w-]+)")

# When keyword steps
_WHEN_RE = re.compile(r"^\s*When\s+", re.MULTILINE)


def parse_success(gherkin_text: str) -> bool:
    """Check if the Gherkin text has basic well-formed structure.

    Validates:
    - Has a Feature: declaration
    - Has at least one Scenario: section
    - Has at least one step keyword (Given/When/Then)
    """
    has_feature = bool(_FEATURE_RE.search(gherkin_text))
    has_scenario = bool(_SCENARIO_RE.search(gherkin_text))
    has_steps = bool(_STEP_RE.search(gherkin_text))

    return has_feature and has_scenario and has_steps


def step_count(gherkin_text: str) -> int:
    """Count total number of Gherkin steps."""
    return len(_STEP_RE.findall(gherkin_text))


def has_background(gherkin_text: str) -> bool:
    """Check if the Gherkin text has a Background section."""
    return bool(_BACKGROUND_RE.search(gherkin_text))


def step_keyword_balance(gherkin_text: str) -> dict[str, int]:
    """Count steps by keyword (Given/When/Then/And/But)."""
    keywords = _STEP_RE.findall(gherkin_text)
    counts = Counter(keywords)
    return {
        "Given": counts.get("Given", 0),
        "When": counts.get("When", 0),
        "Then": counts.get("Then", 0),
        "And": counts.get("And", 0),
        "But": counts.get("But", 0),
    }


def zone_annotation_rate(gherkin_text: str) -> float:
    """Fraction of When steps that have a zone annotation comment.

    Looks for lines containing a When step that also have (on the same or
    preceding line) a '# Zone N' comment.
    """
    lines = gherkin_text.split("\n")
    when_count = 0
    annotated_count = 0

    for i, line in enumerate(lines):
        if _WHEN_RE.match(line):
            when_count += 1
            # Check this line and the preceding line for zone annotation
            if _ZONE_COMMENT_RE.search(line):
                annotated_count += 1
            elif i > 0 and _ZONE_COMMENT_RE.search(lines[i - 1]):
                annotated_count += 1

    if when_count == 0:
        return 0.0
    return annotated_count / when_count


def extract_tags(gherkin_text: str) -> list[str]:
    """Extract all tags from Gherkin text."""
    return _TAG_RE.findall(gherkin_text)


def _normalize_tag(tag: str) -> str:
    """Normalize a tag for comparison (lowercase, collapse separators, strip plurals).

    Strips filler words (and/or/the), collapses plural suffixes, and sorts
    remaining segments so word-order variants collapse to the same key.
    """
    norm = tag.lower().replace("_", "-")

    # Split into segments, strip filler words
    segments = [s for s in norm.split("-") if s not in ("and", "or", "the")]

    # Simple plural normalization on each segment
    normalized_segments: list[str] = []
    for seg in segments:
        if seg.endswith("ies") and len(seg) > 4:
            seg = seg[:-3] + "y"
        elif seg.endswith("ses") and len(seg) > 4:
            seg = seg[:-2]
        elif seg.endswith("s") and not seg.endswith("ss") and len(seg) > 2:
            seg = seg[:-1]
        normalized_segments.append(seg)

    # Sort segments so word-order variants collapse
    normalized_segments.sort()
    return "-".join(normalized_segments)


def tag_consistency(gherkin_texts: list[str]) -> dict[str, Any]:
    """Detect tag variants for the same threat across a batch.

    Groups tags by normalized form and flags groups with multiple
    distinct surface forms.

    Returns:
        Dict with 'inconsistent_groups' count and 'details' list.
    """
    # Collect all unique tags and map normalized -> {surface forms}
    norm_to_surfaces: dict[str, set[str]] = {}
    for text in gherkin_texts:
        for tag in extract_tags(text):
            norm = _normalize_tag(tag)
            norm_to_surfaces.setdefault(norm, set()).add(tag)

    inconsistent: list[dict[str, Any]] = []
    for norm, surfaces in sorted(norm_to_surfaces.items()):
        if len(surfaces) > 1:
            inconsistent.append({
                "normalized": norm,
                "variants": sorted(surfaces),
            })

    return {
        "inconsistent_groups": len(inconsistent),
        "details": inconsistent,
    }


def score_gherkin_single(gherkin_text: str) -> dict[str, Any]:
    """Compute Gherkin metrics for a single .feature file.

    Returns:
        Dict with parse_success, step_count, has_background,
        keyword_balance, zone_annotation_rate.
    """
    return {
        "parse_success": parse_success(gherkin_text),
        "step_count": step_count(gherkin_text),
        "has_background": has_background(gherkin_text),
        "keyword_balance": step_keyword_balance(gherkin_text),
        "zone_annotation_rate": round(zone_annotation_rate(gherkin_text), 4),
    }


def score_gherkin(gherkin_texts: list[str]) -> dict[str, Any]:
    """Compute aggregate Gherkin metrics across a batch.

    Args:
        gherkin_texts: List of Gherkin feature file contents.

    Returns:
        Dict with parse_success_rate, mean_step_count, tag_consistency,
        and per-file details.
    """
    if not gherkin_texts:
        return {
            "parse_success_rate": 0.0,
            "mean_step_count": 0.0,
            "background_rate": 0.0,
            "mean_zone_annotation_rate": 0.0,
            "tag_consistency": {"inconsistent_groups": 0, "details": []},
        }

    singles = [score_gherkin_single(text) for text in gherkin_texts]
    n = len(singles)

    parse_ok = sum(1 for s in singles if s["parse_success"])
    total_steps = sum(s["step_count"] for s in singles)
    bg_count = sum(1 for s in singles if s["has_background"])
    zone_rates = [s["zone_annotation_rate"] for s in singles]

    return {
        "parse_success_rate": round(parse_ok / n, 4),
        "mean_step_count": round(total_steps / n, 2),
        "background_rate": round(bg_count / n, 4),
        "mean_zone_annotation_rate": round(sum(zone_rates) / n, 4),
        "tag_consistency": tag_consistency(gherkin_texts),
    }
