"""Post-generation coverage analysis.

Compares generated scenarios against the capability profile and threat surface
to flag coverage gaps:
  - Entry points with zero scenarios targeting them
  - Active zones with zero scenarios traversing them
  - In-scope threats that produced no scenarios
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
# Output
# ---------------------------------------------------------------------------


def write_coverage_report(
    coverage_gaps: CoverageGaps,
    output_dir: Path,
) -> Path:
    """Write coverage analysis results to coverage-gaps.json.

    Args:
        coverage_gaps: Result from analyze_coverage_gaps.
        output_dir: Pipeline output directory.

    Returns:
        Path to the written coverage-gaps.json file.
    """
    report: dict = {
        "coverage_gaps": coverage_gaps.to_dict(),
    }
    path = output_dir / "coverage-gaps.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Coverage report written to %s", path)
    return path
