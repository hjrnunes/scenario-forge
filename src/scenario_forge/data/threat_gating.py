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

Sub-scenario filtering applies additional checks within gated threats
(e.g. T1-S4 requires shared writable memory, T2-S4 requires persistent
memory, T2-S5 requires a vector store).
"""

from __future__ import annotations

import logging
from pathlib import Path
from pydantic import BaseModel, Field

from scenario_forge.data.loaders import (
    build_pattern_provenance_index,
    load_agentic_threats,
    load_attack_pattern_provenance,
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
    applicable_sub_scenarios: list[str] = Field(
        default_factory=list,
        description="Sub-scenario IDs applicable to this system (e.g. ['T2-S1', 'T2-S3'])",
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
# Sub-scenario filtering helpers
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
    not silently filter out the sub-scenario.  This avoids the premature-
    gating bug where ``memory_mechanisms`` was always ``None`` after
    Stage 1, causing ``_has_vector_store()`` to always return ``False``
    and silently dropping sub-scenarios like T2-S5.
    """
    if profile.memory_mechanisms is None:
        # Stage 1 only — no detailed memory data yet.
        # Fall back to the broad has_persistent_memory flag so we don't
        # prematurely filter sub-scenarios that require a vector store.
        return profile.has_persistent_memory
    if not profile.memory_mechanisms:
        # Explicitly empty list (Stage 2 said "no memory mechanisms")
        return False
    return any(m.type == MemoryType.vector_store for m in profile.memory_mechanisms)


def _build_sub_scenario_to_pattern(
    patterns: dict[str, dict],
    prov_index: dict[str, dict[str, list[str]]],
) -> dict[str, dict]:
    """Build a reverse lookup from OWASP sub-scenario ID to attack pattern.

    Uses the provenance index to find which pattern maps to each
    owasp-agentic sub-scenario via ``skos:exactMatch``.

    Returns:
        Dict mapping sub-scenario IDs (e.g. 'T7-S1') to their
        corresponding attack pattern dicts.
    """
    sub_to_pattern: dict[str, dict] = {}
    for pid, sources in prov_index.items():
        owasp_ids = sources.get("owasp-agentic", [])
        pattern = patterns.get(pid)
        if pattern is None:
            continue
        for sub_id in owasp_ids:
            sub_to_pattern[sub_id] = pattern
    return sub_to_pattern


def _evaluate_prerequisite_capabilities(
    prereqs: dict,
    profile: CapabilityProfile,
) -> bool:
    """Evaluate a pattern's prerequisite_capabilities against a profile.

    Each field in prereqs is a gate; ALL must pass for the sub-scenario
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
    if prereqs.get("requires_shared_writable_memory") and not _has_shared_writable_memory(profile):
        return False

    # requires_vector_store
    if prereqs.get("requires_vector_store") and not _has_vector_store(profile):
        return False

    # requires_tool_execution
    if prereqs.get("requires_tool_execution") and "tool_execution" not in profile.zones_active:
        return False

    # requires_multi_agent
    if prereqs.get("requires_multi_agent") and not profile.multi_agent:
        return False

    # requires_hitl
    if prereqs.get("requires_hitl") and not profile.hitl:
        return False

    return True


def _get_all_sub_scenarios(threat: dict) -> list[str]:
    """Extract all sub-scenario IDs from a threat dict."""
    scenarios = threat.get("scenarios", [])
    return [s["id"] for s in scenarios]


def _filter_sub_scenarios(
    threat_id: str,
    all_sub_scenarios: list[str],
    profile: CapabilityProfile,
    sub_scenario_to_pattern: dict[str, dict] | None = None,
) -> list[str]:
    """Apply sub-scenario gating rules for specific threats.

    Uses a two-tier approach:
      1. **Data-driven**: If ``sub_scenario_to_pattern`` is provided and a
         sub-scenario has an associated pattern with ``prerequisite_capabilities``,
         evaluate those capabilities against the profile.
      2. **Hardcoded fallback**: For sub-scenarios without a pattern or without
         ``prerequisite_capabilities``, fall back to the original rules:
           - T1-S4: only if shared writable memory exists
           - T2-S4: only if has_persistent_memory is true
           - T2-S5: only if vector_store is in memory_mechanisms
           - T15-S1, T15-S2: only if tool_execution zone is active
    """
    excluded: set[str] = set()

    # Track which sub-scenarios were handled by data-driven evaluation
    data_driven_handled: set[str] = set()

    # --- Tier 1: Data-driven evaluation ---
    if sub_scenario_to_pattern:
        for sub_id in all_sub_scenarios:
            pattern = sub_scenario_to_pattern.get(sub_id)
            if pattern is None:
                continue
            prereqs = pattern.get("prerequisite_capabilities")
            if prereqs is None:
                continue

            data_driven_handled.add(sub_id)
            if not _evaluate_prerequisite_capabilities(prereqs, profile):
                excluded.add(sub_id)
                logger.warning(
                    "Gating FILTERED %s (data-driven): prerequisite_capabilities "
                    "not met (pattern=%s)",
                    sub_id,
                    pattern.get("id", "unknown"),
                )
            else:
                logger.info(
                    "Gating PASSED %s (data-driven): prerequisite_capabilities "
                    "satisfied (pattern=%s)",
                    sub_id,
                    pattern.get("id", "unknown"),
                )

    # --- Tier 2: Hardcoded fallback for sub-scenarios not handled above ---
    if threat_id == "T1":
        if "T1-S4" not in data_driven_handled:
            has_swm = _has_shared_writable_memory(profile)
            if not has_swm:
                excluded.add("T1-S4")
                logger.warning(
                    "Gating FILTERED T1-S4: _has_shared_writable_memory=False "
                    "(memory_mechanisms=%s, has_persistent_memory=%s)",
                    "present" if profile.memory_mechanisms is not None else "None",
                    profile.has_persistent_memory,
                )
            else:
                logger.info(
                    "Gating PASSED T1-S4: _has_shared_writable_memory=True "
                    "(memory_mechanisms=%s, has_persistent_memory=%s)",
                    "present" if profile.memory_mechanisms is not None else "None",
                    profile.has_persistent_memory,
                )

    elif threat_id == "T2":
        if "T2-S4" not in data_driven_handled:
            if not profile.has_persistent_memory:
                excluded.add("T2-S4")
                logger.warning(
                    "Gating FILTERED T2-S4: has_persistent_memory=False",
                )
            else:
                logger.info(
                    "Gating PASSED T2-S4: has_persistent_memory=True",
                )

        if "T2-S5" not in data_driven_handled:
            has_vs = _has_vector_store(profile)
            if not has_vs:
                excluded.add("T2-S5")
                logger.warning(
                    "Gating FILTERED T2-S5: _has_vector_store=False "
                    "(memory_mechanisms=%s, has_persistent_memory=%s)",
                    "present" if profile.memory_mechanisms is not None else "None",
                    profile.has_persistent_memory,
                )
            else:
                logger.info(
                    "Gating PASSED T2-S5: _has_vector_store=True "
                    "(memory_mechanisms=%s, has_persistent_memory=%s)",
                    "present" if profile.memory_mechanisms is not None else "None",
                    profile.has_persistent_memory,
                )

    elif threat_id == "T15":
        unflagged_t15 = {"T15-S1", "T15-S2"} - data_driven_handled
        if unflagged_t15:
            zone_3_active = "tool_execution" in profile.zones_active
            if not zone_3_active:
                excluded.update(unflagged_t15)
                logger.warning(
                    "Gating FILTERED %s: tool_execution zone not active "
                    "(zones_active=%s) — both seeds assume indirect prompt "
                    "injection via external content ingestion",
                    sorted(unflagged_t15),
                    profile.zones_active,
                )
            else:
                logger.info(
                    "Gating PASSED %s: tool_execution zone active (zones_active=%s)",
                    sorted(unflagged_t15),
                    profile.zones_active,
                )

    return [s for s in all_sub_scenarios if s not in excluded]


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------


def determine_threat_scope(
    profile: CapabilityProfile,
    threats_path: str | Path | None = None,
) -> ThreatScope:
    """Determine which threats are in scope for a given capability profile.

    Loads the OWASP Agentic Threats YAML to get threat names and
    sub-scenarios, then applies the gating rules from the capability
    profile schema.

    Args:
        profile: The capability profile to evaluate.
        threats_path: Path to the agentic threats YAML. Defaults to the
            bundled data file.

    Returns:
        ThreatScope with in_scope and out_of_scope entries.
    """
    path = Path(threats_path) if threats_path else _DEFAULT_THREATS_PATH
    threats = load_agentic_threats(path)

    # Load attack patterns and provenance once for data-driven gating
    sub_scenario_to_pattern: dict[str, dict] = {}
    try:
        patterns = load_attack_patterns()
        prov_mappings = load_attack_pattern_provenance()
        prov_index = build_pattern_provenance_index(prov_mappings)
        sub_scenario_to_pattern = _build_sub_scenario_to_pattern(patterns, prov_index)
        logger.info(
            "Loaded %d attack patterns, mapped %d sub-scenarios for data-driven gating",
            len(patterns),
            len(sub_scenario_to_pattern),
        )
    except Exception:
        logger.debug(
            "Could not load attack patterns for data-driven gating; "
            "falling back to hardcoded rules only",
            exc_info=True,
        )

    in_scope: list[ThreatScopeEntry] = []
    out_of_scope_groups: dict[str, list[str]] = {}

    zone_3_active = "tool_execution" in profile.zones_active

    def _add_in_scope(threat_id: str, reason: str) -> None:
        threat = threats[threat_id]
        all_subs = _get_all_sub_scenarios(threat)
        filtered_subs = _filter_sub_scenarios(
            threat_id, all_subs, profile, sub_scenario_to_pattern
        )
        dropped = set(all_subs) - set(filtered_subs)
        logger.info(
            "Threat %s (%s) IN SCOPE: %s — %d/%d sub-scenarios kept%s",
            threat_id,
            threat["name"],
            reason,
            len(filtered_subs),
            len(all_subs),
            f" (dropped: {sorted(dropped)})" if dropped else "",
        )
        in_scope.append(
            ThreatScopeEntry(
                threat_id=threat_id,
                threat_name=threat["name"],
                applicable_sub_scenarios=filtered_subs,
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
        _add_in_scope(tid, "always in scope — any LLM/agent system with input and reasoning zones")

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
