"""Post-generation coverage analysis.

Compares generated scenarios against the capability profile and threat surface
to flag coverage gaps:
  - Entry points with zero scenarios targeting them
  - Active zones with zero scenarios traversing them
  - In-scope threats that produced no scenarios

Also provides attacker model diversity analysis (scenario-forge-cw9).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import ScenarioEnvelope
from scenario_forge.pipeline.threats import ThreatSurface

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Coverage gap analysis (scenario-forge-n63)
# ---------------------------------------------------------------------------


@dataclass
class CoverageGaps:
    """Structured result of coverage gap analysis."""

    uncovered_entry_points: list[str] = field(default_factory=list)
    uncovered_zones: list[int] = field(default_factory=list)
    uncovered_threats: list[str] = field(default_factory=list)

    @property
    def has_gaps(self) -> bool:
        return bool(
            self.uncovered_entry_points
            or self.uncovered_zones
            or self.uncovered_threats
        )

    def to_dict(self) -> dict:
        return {
            "uncovered_entry_points": self.uncovered_entry_points,
            "uncovered_zones": self.uncovered_zones,
            "uncovered_threats": self.uncovered_threats,
        }


def analyze_coverage_gaps(
    profile: CapabilityProfile,
    threat_surface: ThreatSurface,
    scenarios: list[ScenarioEnvelope],
) -> CoverageGaps:
    """Compare generated scenarios against the profile and threat surface.

    Identifies:
      1. Entry points from the profile that no scenario targets.
      2. Active zones from the profile that no scenario traverses.
      3. In-scope threats from the threat surface that produced no scenarios.

    Args:
        profile: The capability profile from Stage 1.
        threat_surface: The threat surface from Stage 2.
        scenarios: The generated scenario envelopes from Stage 4.

    Returns:
        CoverageGaps with lists of uncovered entry points, zones, and threats.
    """
    # Collect entry points used across all scenarios.
    used_entry_points: set[str] = set()
    traversed_zones: set[int] = set()
    covered_threat_ids: set[str] = set()

    for envelope in scenarios:
        used_entry_points.add(envelope.narrative.entry_point)
        traversed_zones.update(envelope.narrative.zone_sequence)
        covered_threat_ids.update(envelope.faceting.taxonomy_chain.agentic_threat_ids)

    # 1. Uncovered entry points
    uncovered_entry_points = [
        ep for ep in profile.entry_points if ep not in used_entry_points
    ]

    # 2. Uncovered active zones
    uncovered_zones = sorted(
        z for z in profile.zones_active if z not in traversed_zones
    )

    # 3. Uncovered in-scope threats
    in_scope_threat_ids: set[str] = set()
    for entry in threat_surface.entries:
        in_scope_threat_ids.update(entry.agentic_threat_ids)

    uncovered_threats = sorted(
        t for t in in_scope_threat_ids if t not in covered_threat_ids
    )

    gaps = CoverageGaps(
        uncovered_entry_points=uncovered_entry_points,
        uncovered_zones=uncovered_zones,
        uncovered_threats=uncovered_threats,
    )

    # Log warnings for any gaps found.
    if gaps.uncovered_entry_points:
        logger.warning(
            "Coverage gap: %d entry point(s) with zero scenarios: %s",
            len(gaps.uncovered_entry_points),
            gaps.uncovered_entry_points,
        )
    if gaps.uncovered_zones:
        logger.warning(
            "Coverage gap: %d active zone(s) with zero scenarios: %s",
            len(gaps.uncovered_zones),
            gaps.uncovered_zones,
        )
    if gaps.uncovered_threats:
        logger.warning(
            "Coverage gap: %d in-scope threat(s) with zero scenarios: %s",
            len(gaps.uncovered_threats),
            gaps.uncovered_threats,
        )

    return gaps


# ---------------------------------------------------------------------------
# Attacker model diversity analysis (scenario-forge-cw9)
# ---------------------------------------------------------------------------

# Keyword -> attacker model classification.
# Order matters: first match wins during classification.
_ATTACKER_MODEL_KEYWORDS: dict[str, list[str]] = {
    "insider": [
        "insider",
        "disgruntled employee",
        "malicious employee",
        "rogue employee",
        "trusted insider",
        "internal actor",
    ],
    "supply_chain": [
        "supply chain",
        "compromised vendor",
        "third-party",
        "third party",
        "vendor compromise",
        "upstream dependency",
        "dependency confusion",
    ],
    "social_engineer": [
        "social engineer",
        "phishing",
        "pretexting",
        "spear-phishing",
        "impersonat",
        "vishing",
    ],
    "privileged_user": [
        "privileged user",
        "malicious admin",
        "admin abuse",
        "privileged access",
        "elevated privilege",
        "system administrator",
    ],
    "external_attacker": [
        "external attacker",
        "remote attacker",
        "adversary",
        "threat actor",
        "attacker",
        "hacker",
        "malicious user",
        "unauthorized",
    ],
}

# Threshold: flag if this fraction or more of scenarios share one model.
_MONOTONE_THRESHOLD = 0.8


@dataclass
class AttackerDiversityResult:
    """Result of attacker model diversity analysis."""

    model_counts: dict[str, int] = field(default_factory=dict)
    dominant_model: str | None = None
    dominant_fraction: float = 0.0
    is_flagged: bool = False

    def to_dict(self) -> dict:
        return {
            "model_counts": self.model_counts,
            "dominant_model": self.dominant_model,
            "dominant_fraction": round(self.dominant_fraction, 3),
            "is_flagged": self.is_flagged,
        }


def classify_attacker_model(text: str) -> str:
    """Classify a text snippet into an attacker model category.

    Scans for keyword matches in priority order. Returns the first matching
    category, or ``"unknown"`` if no keywords match.

    Args:
        text: Narrative text to classify (summary + step actions).

    Returns:
        Attacker model category string.
    """
    lower = text.lower()
    for model, keywords in _ATTACKER_MODEL_KEYWORDS.items():
        for kw in keywords:
            if kw in lower:
                return model
    return "unknown"


def _extract_scenario_text(envelope: ScenarioEnvelope) -> str:
    """Extract classifiable text from a scenario envelope.

    Combines the narrative summary and all step actions into a single string
    for attacker model classification.
    """
    parts = [envelope.narrative.summary]
    for step in envelope.narrative.steps:
        parts.append(step.action)
    return " ".join(parts)


def analyze_attacker_diversity(
    scenarios: list[ScenarioEnvelope],
) -> AttackerDiversityResult:
    """Analyze attacker model diversity across generated scenarios.

    Classifies each scenario's dominant attacker model by scanning narrative
    text for keyword patterns, then flags when >80% of scenarios share the
    same model.

    Args:
        scenarios: The generated scenario envelopes.

    Returns:
        AttackerDiversityResult with counts, dominant model, and flag status.
    """
    if not scenarios:
        return AttackerDiversityResult()

    model_counts: dict[str, int] = {}
    for envelope in scenarios:
        text = _extract_scenario_text(envelope)
        model = classify_attacker_model(text)
        model_counts[model] = model_counts.get(model, 0) + 1

    # Find the dominant model.
    dominant_model = max(model_counts, key=model_counts.get)  # type: ignore[arg-type]
    dominant_count = model_counts[dominant_model]
    dominant_fraction = dominant_count / len(scenarios)
    is_flagged = dominant_fraction > _MONOTONE_THRESHOLD

    if is_flagged:
        logger.warning(
            "Attacker model diversity: %.0f%% of scenarios use '%s' "
            "(threshold: %.0f%%). Consider varying threat actor models.",
            dominant_fraction * 100,
            dominant_model,
            _MONOTONE_THRESHOLD * 100,
        )

    return AttackerDiversityResult(
        model_counts=model_counts,
        dominant_model=dominant_model,
        dominant_fraction=dominant_fraction,
        is_flagged=is_flagged,
    )


# ---------------------------------------------------------------------------
# Combined output
# ---------------------------------------------------------------------------


def write_coverage_report(
    coverage_gaps: CoverageGaps,
    output_dir: Path,
    attacker_diversity: AttackerDiversityResult | None = None,
) -> Path:
    """Write coverage analysis results to coverage-gaps.json.

    Args:
        coverage_gaps: Result from analyze_coverage_gaps.
        output_dir: Pipeline output directory.
        attacker_diversity: Optional result from analyze_attacker_diversity.

    Returns:
        Path to the written coverage-gaps.json file.
    """
    report: dict = {
        "coverage_gaps": coverage_gaps.to_dict(),
    }
    if attacker_diversity is not None:
        report["attacker_diversity"] = attacker_diversity.to_dict()
    path = output_dir / "coverage-gaps.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Coverage report written to %s", path)
    return path
