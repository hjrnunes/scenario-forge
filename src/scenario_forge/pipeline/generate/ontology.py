"""Taxonomy/ontology context builders for LLM prompts."""

from __future__ import annotations

import logging

from scenario_forge.models.capability_profile import (
    KC_SUBCODE_NAMES,
    KCX_SUBCODES,
    CapabilityProfile,
)

from scenario_forge.pipeline.generate.constants import (
    _ATLAS_TECHNIQUE_DESCRIPTIONS,
    _ATLAS_TECHNIQUE_NAMES,
    _OWASP_LLM_NAMES,
)

logger = logging.getLogger(__name__)


def _lookup_entry_point_direction(
    profile: CapabilityProfile,
    entry_point_name: str | None,
) -> str | None:
    """Look up the direction for a named entry point in the capability profile.

    Returns the direction string ('input', 'output', or 'bidirectional'),
    or ``None`` if *entry_point_name* is ``None`` or not found in the profile.
    """
    if entry_point_name is None:
        return None
    for ep in profile.entry_points:
        if ep.name == entry_point_name:
            return ep.direction
    logger.warning(
        "Entry point '%s' not found in profile entry_points; "
        "direction lookup returning None",
        entry_point_name,
    )
    return None


def _lookup_entry_point_controllability(
    profile: CapabilityProfile,
    entry_point_name: str | None,
) -> str | None:
    """Look up the controllability for a named entry point in the capability profile.

    Returns the controllability string ('direct', 'indirect', or 'system'),
    or ``None`` if *entry_point_name* is ``None`` or not found in the profile.
    """
    if entry_point_name is None:
        return None
    for ep in profile.entry_points:
        if ep.name == entry_point_name:
            return ep.controllability
    logger.warning(
        "Entry point '%s' not found in profile entry_points; "
        "controllability lookup returning None",
        entry_point_name,
    )
    return None


def _format_taxonomy_ids(ids: list[str], name_map: dict[str, str]) -> str:
    """Format a list of taxonomy IDs as 'ID: Name' entries, comma-separated.

    Falls back to the raw ID if no name is found in the lookup dict.
    """
    parts = []
    for tid in ids:
        name = name_map.get(tid)
        if name:
            parts.append(f"{tid}: {name}")
        else:
            parts.append(tid)
    return ", ".join(parts) if parts else "none"


def build_kc_definitions_block(kc_subcodes: list[str]) -> str:
    """Build a formatted KC/KCX definitions block for LLM prompts.

    Takes a list of KC sub-codes from the capability profile and produces
    a human-readable definition list.  Each code is paired with its short
    definition from :data:`KC_SUBCODE_NAMES` (for standard KC codes) or
    :data:`KCX_SUBCODES` (for scenario-forge KCX extensions).

    Returns an empty string when *kc_subcodes* is empty.

    Example output::

        - KC1.1: Large Language Model (LLM)
        - KC3.2: ReAct -- interleaved reasoning and action
        - KCX-PMEM: Persistent memory architecture (cross-session state)
    """
    if not kc_subcodes:
        return ""
    lines: list[str] = []
    for code in kc_subcodes:
        name = KC_SUBCODE_NAMES.get(code)
        if name is None:
            # Try KCX definitions
            name = KCX_SUBCODES.get(code)
        if name is not None:
            lines.append(f"- {code}: {name}")
        else:
            # Unknown code -- include raw for transparency
            lines.append(f"- {code}")
    return "\n".join(lines)


def _build_technique_context_block(technique_ids: list[str]) -> str:
    """Build a shared ATLAS technique context block for LLM prompts.

    Produces a consistent section containing ID, name, and description
    for each technique. Returns an empty string when no IDs are provided.
    """
    if not technique_ids:
        return ""
    lines = ["## ATLAS Technique Context"]
    for tid in technique_ids:
        name = _ATLAS_TECHNIQUE_NAMES.get(tid, tid)
        desc = _ATLAS_TECHNIQUE_DESCRIPTIONS.get(tid, "")
        entry = f"- **{tid}** — {name}"
        if desc:
            entry += f": {desc}"
        lines.append(entry)
    return "\n".join(lines) + "\n"


def _build_ontology_context(
    entry_point_name: str,
    entry_point_direction: str | None,
    zones: list[str],
    technique_ids: list[str],
    entry_point_controllability: str | None = None,
) -> str:
    """Build a focused ontology context block for LLM prompts.

    Provides the LLM with only the specific entry point, zones, and
    techniques assigned to THIS scenario seed -- not the full profile.
    This reduces prompt noise and anchors generation to the pinned
    taxonomy elements, mitigating orphan technique hallucination.

    Returns an empty string when *entry_point_name* is empty and no
    technique IDs are provided.
    """
    lines: list[str] = []
    lines.append("## Ontology Context")
    lines.append(
        "The following taxonomy elements are pinned for THIS scenario. "
        "Use ONLY these elements -- do not introduce others."
    )

    # -- Entry point section --
    lines.append("")
    lines.append("### Pinned Entry Point")
    qualifiers: list[str] = []
    if entry_point_direction:
        qualifiers.append(f"direction: {entry_point_direction}")
    if entry_point_controllability:
        qualifiers.append(f"controllability: {entry_point_controllability}")
    qualifier_label = f" ({', '.join(qualifiers)})" if qualifiers else ""
    lines.append(f"- {entry_point_name}{qualifier_label}")

    # -- Active zones section --
    if zones:
        lines.append("")
        lines.append("### Active Zones")
        lines.append(
            "The target system has these architectural zones. "
            "Attack steps MUST only reference these zones."
        )
        for zone in zones:
            lines.append(f"- {zone}")

    # -- Pinned techniques section --
    if technique_ids:
        lines.append("")
        lines.append("### Pinned Techniques")
        lines.append(
            "Use ONLY these ATLAS techniques. Do NOT reference, invent, "
            "or introduce any technique IDs not listed here."
        )
        for tid in technique_ids:
            name = _ATLAS_TECHNIQUE_NAMES.get(tid, tid)
            desc = _ATLAS_TECHNIQUE_DESCRIPTIONS.get(tid, "")
            entry = f"- **{tid}** -- {name}"
            if desc:
                entry += f": {desc}"
            lines.append(entry)

    lines.append("")
    return "\n".join(lines) + "\n"


def format_owasp_llm_ids(owasp_llm_ids: list[str]) -> str:
    """Format OWASP LLM IDs using the standard name map."""
    return _format_taxonomy_ids(owasp_llm_ids, _OWASP_LLM_NAMES)
