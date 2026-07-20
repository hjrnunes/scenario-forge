"""Diversity tracking for the scenario generation loop.

Encapsulates the 6 Counter objects and prior-titles list used to compute
diversity hints (preferred actor, excluded actors, preferred capability
level, excluded patterns, selected goals) for each scenario seed.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from scenario_forge.models.scenario import ACTOR_TYPES, ScenarioEnvelope
from scenario_forge.pipeline.generate import (
    compute_compatible_goal_ids,
    extract_narrative_keywords,
    extract_structural_pattern,
    get_overused_patterns,
    get_overused_structural_patterns,
    select_attack_goal,
)

_CAP_LEVELS: tuple[str, ...] = ("novice", "intermediate", "advanced", "expert")


class DiversityHints:
    """Container for the diversity hints computed for a single seed."""

    __slots__ = (
        "excluded_patterns",
        "excluded_structural_patterns",
        "preferred_actor_type",
        "excluded_actor_types",
        "preferred_capability_level",
        "selected_goal",
    )

    def __init__(
        self,
        excluded_patterns: list[str] | None,
        excluded_structural_patterns: list[str] | None,
        preferred_actor_type: str,
        excluded_actor_types: list[str] | None,
        preferred_capability_level: str,
        selected_goal: dict[str, Any] | None,
    ) -> None:
        self.excluded_patterns = excluded_patterns
        self.excluded_structural_patterns = excluded_structural_patterns
        self.preferred_actor_type = preferred_actor_type
        self.excluded_actor_types = excluded_actor_types
        self.preferred_capability_level = preferred_capability_level
        self.selected_goal = selected_goal


class DiversityTracker:
    """Tracks diversity counters and computes hints for the generation loop.

    Encapsulates the six Counter objects and the ``prior_titles`` list that
    were previously managed inline in the runner's Stage 4 loop.
    """

    def __init__(self) -> None:
        self.entry_point_usage: Counter[str] = Counter()
        self.pattern_usage: Counter[str] = Counter()
        self.structural_usage: Counter[str] = Counter()
        self.actor_type_usage: Counter[str] = Counter()
        self.capability_level_usage: Counter[str] = Counter()
        self.goal_usage: Counter[str] = Counter()
        self.prior_titles: list[str] = []

    # ------------------------------------------------------------------
    # Diversity hint computation
    # ------------------------------------------------------------------

    def get_excluded_patterns(self) -> list[str] | None:
        """Return overused attack-pattern keywords, or ``None``."""
        return get_overused_patterns(self.pattern_usage) or None

    def get_excluded_structural_patterns(self) -> list[str] | None:
        """Return overused structural attack patterns, or ``None``."""
        return get_overused_structural_patterns(self.structural_usage) or None

    def get_preferred_actor(self, total_seeds: int) -> str:
        """Return the least-used actor type as preferred."""
        _ = total_seeds  # available for future fair-share logic
        return min(ACTOR_TYPES, key=lambda t: self.actor_type_usage.get(t, 0))

    def get_excluded_actors(self, total_seeds: int) -> list[str] | None:
        """Return actor types that exceed their fair-share ceiling, or ``None``."""
        num_actor_types = len(ACTOR_TYPES)
        actor_fair_share = (
            math.ceil(total_seeds / num_actor_types) if total_seeds else 1
        )
        excluded = [
            t
            for t in ACTOR_TYPES
            if self.actor_type_usage.get(t, 0) > actor_fair_share
        ]
        return excluded or None

    def get_preferred_capability_level(self) -> str:
        """Return the least-used capability level as preferred."""
        return min(
            _CAP_LEVELS,
            key=lambda c: self.capability_level_usage.get(c, 0),
        )

    def select_goal(
        self,
        seed_threat_id: str,
        available_goals: list[dict[str, Any]],
        zones_active: list[str],
        kc_subcodes: list[str] | None,
        total_seeds: int,
    ) -> dict[str, Any] | None:
        """Select an attack goal for the given seed using fair-share diversity.

        Narrows the sub-goal pool with architectural and threat-specific
        exclusions, then delegates to ``select_attack_goal``.

        Returns ``None`` when no goals are available or all are excluded.
        """
        if not available_goals:
            return None

        seed_goals = compute_compatible_goal_ids(
            threat_id=seed_threat_id,
            sub_goals=available_goals,
            zones_active=zones_active,
            kc_subcodes=kc_subcodes,
        )
        try:
            return select_attack_goal(
                seed_goals,
                self.goal_usage,
                total_seeds,
                threat_id=seed_threat_id,
            )
        except ValueError:
            return None  # No goals available -- proceed without goal diversity

    def get_diversity_hints(
        self,
        seed_threat_id: str,
        total_seeds: int,
        available_goals: list[dict[str, Any]],
        zones_active: list[str],
        kc_subcodes: list[str] | None,
    ) -> DiversityHints:
        """Compute all diversity hints for a single seed in one call.

        This is the primary interface for the generation loop -- it replaces
        the ~60 lines of inline diversity computation that were previously
        in runner.py.
        """
        return DiversityHints(
            excluded_patterns=self.get_excluded_patterns(),
            excluded_structural_patterns=self.get_excluded_structural_patterns(),
            preferred_actor_type=self.get_preferred_actor(total_seeds),
            excluded_actor_types=self.get_excluded_actors(total_seeds),
            preferred_capability_level=self.get_preferred_capability_level(),
            selected_goal=self.select_goal(
                seed_threat_id=seed_threat_id,
                available_goals=available_goals,
                zones_active=zones_active,
                kc_subcodes=kc_subcodes,
                total_seeds=total_seeds,
            ),
        )

    # ------------------------------------------------------------------
    # Counter updates after generation
    # ------------------------------------------------------------------

    def update(
        self,
        envelope: ScenarioEnvelope,
        attack_pattern_name: str,
    ) -> None:
        """Update all diversity counters after a scenario is generated.

        Args:
            envelope: The generated scenario envelope.
            attack_pattern_name: Attack pattern name from the filtered seed
                (used for keyword extraction).
        """
        # Title diversity
        self.prior_titles.append(envelope.narrative.title)

        # Entry point usage
        self.entry_point_usage[envelope.narrative.entry_point] += 1

        # Actor type and capability level
        if envelope.actor_profile is not None:
            self.actor_type_usage[envelope.actor_profile.actor_type] += 1
            self.capability_level_usage[
                envelope.actor_profile.capability_level
            ] += 1
            # Goal category usage
            if envelope.actor_profile.goal_category is not None:
                self.goal_usage[envelope.actor_profile.goal_category] += 1

        # Attack pattern keyword diversity
        keywords = extract_narrative_keywords(
            envelope.narrative,
            attack_pattern_name=attack_pattern_name,
        )
        self.pattern_usage.update(keywords)

        # Structural attack pattern diversity
        structural_pattern = extract_structural_pattern(envelope.narrative)
        self.structural_usage[structural_pattern] += 1
