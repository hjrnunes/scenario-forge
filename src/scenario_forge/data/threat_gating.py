"""Threat gating logic for scenario-forge.

Determines which OWASP Agentic Threats are in scope for a given
capability profile, based on the threat_scope_mapping rules defined
in data/schemas/capability-profile.yaml.

Gating categories:
  - Always in scope: T6, T7, T8, T15
  - Memory-gated (has_persistent_memory): T1, T5
  - Tool-execution-gated (tool_execution zone active): T2, T3, T4, T11, T16, T17
  - Auth-gated (tool_execution zone active): T9
  - HITL-gated (hitl=true): T10
  - Multi-agent-gated (multi_agent=true): T12, T13, T14

Attack-pattern filtering evaluates ``prerequisite_capabilities`` defined
in each AP-* attack pattern to apply additional checks within gated threats
(e.g. shared writable memory, vector store, tool execution zone).  Each
attack pattern carries a ``threat_id`` field linking it to an OWASP threat,
so patterns are grouped by threat and filtered per-threat against the
capability profile.
"""

from __future__ import annotations

import logging
from pathlib import Path
from pydantic import BaseModel, Field

from scenario_forge.data.loaders import (
    build_threat_to_patterns_index,
    load_agentic_threats,
    load_attack_patterns,
)
from scenario_forge.models import CapabilityProfile, MemoryScope, MemoryType

logger = logging.getLogger(__name__)

# Default path to OWASP Agentic Threats data
_DEFAULT_THREATS_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


class ThreatScopeEntry(BaseModel):
    """A threat that is in scope for the assessed system."""

    threat_id: str = Field(description="Threat ID (e.g. 'T2')")
    threat_name: str = Field(description="Human-readable threat name")
    attack_pattern_ids: list[str] = Field(
        default_factory=list,
        description="Attack pattern IDs applicable to this system (e.g. ['AP-T2-01', 'AP-T2-03'])",
    )
    gating_reason: str = Field(
        description="Why this threat is in scope (e.g. 'always in scope', 'has_persistent_memory is true')",
    )


class OutOfScopeEntry(BaseModel):
    """A group of threats that are out of scope, with the reason."""

    threat_ids: list[str] = Field(description="Threat IDs that are out of scope")
    reason: str = Field(description="Why these threats are out of scope")


class ThreatScope(BaseModel):
    """The complete threat scope determination for a capability profile."""

    in_scope: list[ThreatScopeEntry] = Field(default_factory=list)
    out_of_scope: list[OutOfScopeEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Gating categories
# ---------------------------------------------------------------------------

_ALWAYS_IN_SCOPE = ["T6", "T7", "T8", "T15"]
_MEMORY_GATED = ["T1", "T5"]
_TOOL_EXECUTION_GATED = ["T2", "T3", "T4", "T11", "T16", "T17"]
_AUTH_GATED = ["T9"]
_HITL_GATED = ["T10"]
_MULTI_AGENT_GATED = ["T12", "T13", "T14"]


# ---------------------------------------------------------------------------
# Attack-pattern filtering helpers
# ---------------------------------------------------------------------------


def _has_shared_writable_memory(profile: CapabilityProfile) -> bool:
    """Check if the profile has shared memory that the agent can write to.

    Like ``_has_vector_store``, falls back to ``has_persistent_memory``
    when ``memory_mechanisms`` is ``None`` (Stage 1 data only) to avoid
    premature filtering.
    """
    if profile.memory_mechanisms is None:
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        return False
    return any(
        m.scope == MemoryScope.shared and m.writable_by_agent
        for m in profile.memory_mechanisms
    )


def _has_vector_store(profile: CapabilityProfile) -> bool:
    """Check if the profile includes a vector_store memory mechanism.

    When ``memory_mechanisms`` is populated (Stage 2 data), this performs
    an exact check for a ``vector_store`` entry.  When it is ``None``
    (Stage 1 data only, where the LLM prompt explicitly forbids
    populating Stage 2 fields), the function falls back to
    ``has_persistent_memory`` as a conservative proxy: if the system has
    persistent memory at all, a vector store is plausible and we should
    not silently filter out the attack pattern.  This avoids the premature-
    gating bug where ``memory_mechanisms`` was always ``None`` after
    Stage 1, causing ``_has_vector_store()`` to always return ``False``
    and silently dropping attack patterns like AP-T2-05.
    """
    if profile.memory_mechanisms is None:
        # Stage 1 only — no detailed memory data yet.
        # Fall back to the broad has_persistent_memory flag so we don't
        # prematurely filter attack patterns that require a vector store.
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        # Explicitly empty list (Stage 2 said "no memory mechanisms")
        return False
    return any(m.type == MemoryType.vector_store for m in profile.memory_mechanisms)


def _evaluate_prerequisite_capabilities(
    prereqs: dict,
    profile: CapabilityProfile,
) -> bool:
    """Evaluate a pattern's prerequisite_capabilities against a profile.

    Each field in prereqs is a gate; ALL must pass for the attack pattern
    to be included.  Unknown fields are silently ignored (forward-compat).

    Returns:
        True if all prerequisites are satisfied, False otherwise.
    """
    # min_zones: every listed zone must be in profile.zones_active
    min_zones = prereqs.get("min_zones")
    if min_zones is not None:
        for zone in min_zones:
            if zone not in profile.zones_active:
                return False

    # requires_persistent_memory
    if prereqs.get("requires_persistent_memory") and not profile.has_persistent_memory:
        return False

    # requires_shared_writable_memory
    if prereqs.get(
        "requires_shared_writable_memory"
    ) and not _has_shared_writable_memory(profile):
        return False

    # requires_vector_store
    if prereqs.get("requires_vector_store") and not _has_vector_store(profile):
        return False

    # requires_tool_execution
    if (
        prereqs.get("requires_tool_execution")
        and "tool_execution" not in profile.zones_active
    ):
        return False

    # requires_multi_agent
    if prereqs.get("requires_multi_agent") and not profile.multi_agent:
        return False

    # requires_hitl
    if prereqs.get("requires_hitl") and not profile.hitl:
        return False

    return True


def _filter_attack_patterns(
    patterns: list[dict],
    profile: CapabilityProfile,
) -> list[str]:
    """Filter attack patterns by prerequisite_capabilities against a profile.

    For each pattern that defines ``prerequisite_capabilities``, evaluates
    those capabilities against the profile.  Patterns whose prerequisites
    are not met are excluded from the returned list.  Patterns without
    prerequisites are always included.

    Args:
        patterns: List of attack pattern dicts (each must have an ``id`` key).
        profile: The capability profile to evaluate against.

    Returns:
        List of surviving pattern IDs (e.g. ``['AP-T7-01', 'AP-T7-03']``).
    """
    surviving: list[str] = []

    for pattern in patterns:
        pid = pattern.get("id", "unknown")
        prereqs = pattern.get("prerequisite_capabilities")
        if prereqs is None:
            surviving.append(pid)
            continue

        if _evaluate_prerequisite_capabilities(prereqs, profile):
            surviving.append(pid)
            logger.info(
                "Gating PASSED %s: prerequisite_capabilities satisfied",
                pid,
            )
        else:
            logger.warning(
                "Gating FILTERED %s: prerequisite_capabilities not met",
                pid,
            )

    return surviving


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------


def determine_threat_scope(
    profile: CapabilityProfile,
    threats_path: str | Path | None = None,
) -> ThreatScope:
    """Determine which threats are in scope for a given capability profile.

    Loads the OWASP Agentic Threats YAML to get threat names, then loads
    AP-* attack patterns (grouped by ``threat_id``) and filters each
    group's patterns by ``prerequisite_capabilities`` against the profile.

    Args:
        profile: The capability profile to evaluate.
        threats_path: Path to the agentic threats YAML. Defaults to the
            bundled data file.

    Returns:
        ThreatScope with in_scope and out_of_scope entries.
    """
    path = Path(threats_path) if threats_path else _DEFAULT_THREATS_PATH
    threats = load_agentic_threats(path)

    # Load attack patterns and group by threat_id for data-driven gating
    patterns = load_attack_patterns()
    threat_to_patterns = build_threat_to_patterns_index(patterns)
    logger.info(
        "Loaded %d attack patterns across %d threats for data-driven gating",
        len(patterns),
        len(threat_to_patterns),
    )

    in_scope: list[ThreatScopeEntry] = []
    out_of_scope_groups: dict[str, list[str]] = {}

    zone_3_active = "tool_execution" in profile.zones_active

    def _add_in_scope(threat_id: str, reason: str) -> None:
        threat = threats[threat_id]
        # Get AP-* pattern IDs for this threat, resolve to full dicts
        pattern_ids = threat_to_patterns.get(threat_id, [])
        all_patterns = [patterns[pid] for pid in pattern_ids if pid in patterns]
        filtered_ids = _filter_attack_patterns(all_patterns, profile)
        dropped = set(pattern_ids) - set(filtered_ids)
        logger.info(
            "Threat %s (%s) IN SCOPE: %s — %d/%d attack patterns kept%s",
            threat_id,
            threat["name"],
            reason,
            len(filtered_ids),
            len(pattern_ids),
            f" (dropped: {sorted(dropped)})" if dropped else "",
        )
        in_scope.append(
            ThreatScopeEntry(
                threat_id=threat_id,
                threat_name=threat["name"],
                attack_pattern_ids=filtered_ids,
                gating_reason=reason,
            )
        )

    def _add_out_of_scope(threat_ids: list[str], reason: str) -> None:
        logger.warning(
            "Threats %s OUT OF SCOPE: %s",
            threat_ids,
            reason,
        )
        out_of_scope_groups[reason] = threat_ids

    # --- Always in scope ---
    for tid in _ALWAYS_IN_SCOPE:
        _add_in_scope(
            tid, "always in scope — any LLM/agent system with input and reasoning zones"
        )

    # --- Memory-gated ---
    if profile.has_persistent_memory:
        for tid in _MEMORY_GATED:
            _add_in_scope(tid, "has_persistent_memory is true")
    else:
        _add_out_of_scope(
            _MEMORY_GATED,
            "has_persistent_memory is false — no memory to poison or cascade hallucinations into",
        )

    # --- Tool-execution-gated ---
    if zone_3_active:
        for tid in _TOOL_EXECUTION_GATED:
            _add_in_scope(tid, "tool_execution zone is active")
    else:
        _add_out_of_scope(
            _TOOL_EXECUTION_GATED,
            "tool_execution zone not active — no tool execution capability",
        )

    # --- Auth-gated (T9 — separated for future auth-awareness refinement) ---
    if zone_3_active:
        for tid in _AUTH_GATED:
            _add_in_scope(tid, "tool_execution zone is active — auth-gated threat")
    else:
        _add_out_of_scope(
            _AUTH_GATED,
            "tool_execution zone not active — no tool execution for auth-related threats",
        )

    # --- HITL-gated ---
    if profile.hitl:
        for tid in _HITL_GATED:
            _add_in_scope(tid, "hitl is true — human-in-the-loop checkpoints exist")
    else:
        _add_out_of_scope(
            _HITL_GATED,
            "hitl is false — no human-in-the-loop to overwhelm",
        )

    # --- Multi-agent-gated ---
    if profile.multi_agent:
        for tid in _MULTI_AGENT_GATED:
            _add_in_scope(tid, "multi_agent is true — inter-agent communication exists")
    else:
        _add_out_of_scope(
            _MULTI_AGENT_GATED,
            "multi_agent is false — no inter-agent communication",
        )

    # Build out_of_scope list
    out_of_scope = [
        OutOfScopeEntry(threat_ids=ids, reason=reason)
        for reason, ids in out_of_scope_groups.items()
    ]

    return ThreatScope(in_scope=in_scope, out_of_scope=out_of_scope)
