"""Call 1: Narrative generation logic."""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any, Optional

from pydantic import BaseModel, Field

from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import ActorProfile, NarrativeLayer, NarrativeStep
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

from scenario_forge.pipeline.generate.constants import _OWASP_LLM_NAMES
from scenario_forge.pipeline.generate.diversity import _format_structural_exclusions
from scenario_forge.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _format_taxonomy_ids,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
    build_kc_definitions_block,
)
from scenario_forge.pipeline.generate.zones import _enforce_zones_narrative

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Intermediate models for structured output
# ---------------------------------------------------------------------------


class Call1Step(BaseModel):
    step_number: int
    zone: str
    action: str
    effect: str
    control_point: Optional[str] = None


class Call1Response(BaseModel):
    title: str
    summary: str
    entry_point: str
    zone_sequence: list[str] = Field(
        min_length=1,
        description=(
            "Ordered attack propagation path through zones, including"
            " revisitations. E.g. [input, reasoning, tool_execution,"
            " reasoning] not just [input, reasoning, tool_execution]."
        ),
    )
    steps: list[Call1Step] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Non-Latin script sanitization
# ---------------------------------------------------------------------------


def _is_latin_or_common(char: str) -> bool:
    """Return True if a character is Latin, Common, or Inherited script."""
    # ASCII printable and whitespace are always kept
    if char.isascii():
        return True
    # Use Unicode character name to detect Latin letters
    name = unicodedata.name(char, "")
    # Common punctuation/symbols/digits — keep
    cat = unicodedata.category(char)
    if cat[0] in ("P", "S", "N", "Z"):
        return True
    # Latin letters (accented, extended) have "LATIN" in their Unicode name
    if "LATIN" in name:
        return True
    return False


def _sanitize_non_latin(text: str) -> str:
    """Remove non-Latin script characters that leak into English output.

    CJK, Cyrillic, Arabic, and other non-Latin characters are stripped.
    Accented Latin characters (French/Spanish/etc.) are preserved.
    ASCII and common punctuation/symbols are always preserved.
    Multiple consecutive spaces left after removal are collapsed.

    Returns the cleaned text.
    """
    if not text:
        return text
    cleaned = "".join(ch for ch in text if _is_latin_or_common(ch))
    # Collapse runs of spaces (but preserve newlines and other whitespace)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    # Strip leading/trailing space from each line
    cleaned = "\n".join(line.strip() for line in cleaned.split("\n"))
    return cleaned.strip()


def _sanitize_narrative(narrative: NarrativeLayer) -> NarrativeLayer:
    """Apply non-Latin sanitization to narrative text fields.

    Logs a warning when sanitization modifies any field.
    Returns a (possibly modified) copy of the narrative.
    """
    changed = False
    title = _sanitize_non_latin(narrative.title)
    summary = _sanitize_non_latin(narrative.summary)

    if title != narrative.title or summary != narrative.summary:
        changed = True

    new_steps = []
    for step in narrative.steps:
        action = _sanitize_non_latin(step.action)
        effect = _sanitize_non_latin(step.effect)
        if action != step.action or effect != step.effect:
            changed = True
        new_steps.append(
            NarrativeStep(
                step_number=step.step_number,
                zone=step.zone,
                action=action,
                effect=effect,
                control_point=step.control_point,
            )
        )

    if changed:
        logger.warning(
            "Sanitized non-Latin characters from narrative fields "
            "(CJK/Cyrillic/Arabic leak from LLM output)"
        )
        return NarrativeLayer(
            title=title,
            summary=summary,
            entry_point=narrative.entry_point,
            zone_sequence=narrative.zone_sequence,
            steps=new_steps,
        )
    return narrative


# ---------------------------------------------------------------------------
# Zone sequence derivation
# ---------------------------------------------------------------------------


def _derive_zone_sequence(steps: list[Call1Step] | list[NarrativeStep]) -> list[str]:
    """Derive zone_sequence from step zone fields.

    Preserves traversal order including revisitations (non-consecutive
    duplicates), but collapses consecutive duplicate zones.

    Example:
        [input, input, reasoning, reasoning, tool_execution]
        -> [input, reasoning, tool_execution]

        [input, reasoning, tool_execution, reasoning]
        -> [input, reasoning, tool_execution, reasoning]  (revisit preserved)
    """
    sequence: list[str] = []
    for step in steps:
        if not sequence or sequence[-1] != step.zone:
            sequence.append(step.zone)
    return sequence


def _map_call1_to_narrative(resp: Call1Response) -> NarrativeLayer:
    steps = [
        NarrativeStep(
            step_number=s.step_number,
            zone=s.zone,
            action=s.action,
            effect=s.effect,
            control_point=s.control_point,
        )
        for s in resp.steps
    ]
    # Derive zone_sequence from step zones rather than using the LLM's
    # zone_sequence field, which tends to collapse return traversals.
    zone_sequence = _derive_zone_sequence(resp.steps)
    return NarrativeLayer(
        title=resp.title,
        summary=resp.summary,
        entry_point=resp.entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# Context builder and LLM call
# ---------------------------------------------------------------------------


def build_call1_context(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    use_case: str,
    actor_profile: ActorProfile | None = None,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    prior_titles: list[str] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 1 (Narrative).

    Pure data-preparation function that constructs all template variables
    needed by ``call1_user.j2``.  No LLM calls.

    Returns:
        Dict mapping template variable names to their values.
    """
    # Build entry point diversity guidance section
    diversity_section = ""
    if pinned_entry_point:
        # Hard constraint from candidate filter — overrides soft hints
        diversity_section = (
            "\n## Entry Point Guidance\n"
            f"- You MUST use this entry point: {pinned_entry_point}. "
            "This is a hard constraint, not a suggestion.\n"
        )
    elif preferred_entry_point or excluded_entry_points:
        diversity_lines = ["\n## Entry Point Guidance"]
        if preferred_entry_point:
            diversity_lines.append(
                f"- Preferred entry point: {preferred_entry_point} "
                "(use this unless it would be unnatural for the attack)"
            )
        if excluded_entry_points:
            diversity_lines.append(
                f"- Avoid these overused entry points: {excluded_entry_points}"
            )
        diversity_section = "\n".join(diversity_lines) + "\n"

    # Build title diversity section when prior titles exist
    if prior_titles:
        title_list = "\n".join(
            f"  {i}. {t}" for i, t in enumerate(prior_titles, 1)
        )
        diversity_section += (
            "\n## Previously Generated Titles (avoid duplication)\n"
            "The following titles have already been used in this generation "
            "run. Your title MUST be substantially different — do not reuse "
            "the same structure, key phrases, or \"[Mechanism] for [Goal]\" "
            "pattern:\n"
            f"{title_list}\n"
        )

    # Build attack pattern diversity section
    pattern_section = ""
    if excluded_patterns:
        pattern_section = (
            "\n## Attack Pattern Diversity\n"
            "Avoid these attack patterns which are already well-represented "
            "in this batch:\n"
            f"- Overused patterns: {', '.join(excluded_patterns)}\n"
            "Find a DIFFERENT attack approach. Use a different vulnerability "
            "mechanism, a different propagation path, or a different impact "
            "chain. Creativity and variety are essential.\n"
        )

    # Build structural pattern diversity section
    structural_section = ""
    if excluded_structural_patterns:
        structural_section = _format_structural_exclusions(excluded_structural_patterns)

    # Build actor profile section for narrative grounding
    actor_section = ""
    if actor_profile is not None:
        resources_str = ", ".join(actor_profile.resources)
        actor_section = (
            "\n## Actor Profile (ground the narrative in this actor)\n"
            "The narrative's attacker must match this actor's capability level, "
            "resources, and motivations.\n"
            f"- Actor type: {actor_profile.actor_type}\n"
            f"- Capability level: {actor_profile.capability_level}\n"
            f"- Beliefs about the target:\n"
            + "".join(f"  - {b}\n" for b in actor_profile.beliefs)
            + "- Desires:\n"
            + "".join(f"  - {d}\n" for d in actor_profile.desires)
            + "- Intentions:\n"
            + "".join(f"  - {i}\n" for i in actor_profile.intentions)
            + f"- Resources: {resources_str}\n"
        )

    # Build goal category section for narrative grounding
    goal_section = ""
    if actor_profile is not None and actor_profile.goal_category:
        goal_section = (
            "\n## Attack Goal Guidance (SHOULD)\n"
            f"**Category:** {actor_profile.goal_category_parent}\n"
            f"**Specific Goal:** {actor_profile.goal_category}: "
            f"{actor_profile.goal_category_name}\n\n"
            "The narrative's terminal attack outcome SHOULD align with this goal "
            "when it is compatible with the seed attack pattern's mechanism. "
            "If satisfying this goal would require abandoning the seed's core "
            "attack mechanism, prioritise seed fidelity — the goal is a guiding "
            "preference, not a hard override. The seed's 'Seed Attack Objective "
            "Fidelity (MANDATORY)' constraint always takes precedence.\n"
        )

    # Resolve creativity-vs-simplicity conflict for novice actors
    if (
        diversity_section
        and actor_profile is not None
        and actor_profile.capability_level == "novice"
    ):
        diversity_section += (
            "\n\n**Capability-level priority:** The actor is a NOVICE. "
            "Diversity constraints are secondary to capability-level constraints. "
            "Do NOT generate a complex attack just because simpler patterns have "
            "been excluded. Instead, use a DIFFERENT simple pattern or a different "
            "angle on the same simple technique."
        )

    # Build technique context — pin to specific techniques if set
    tech_ids_for_narrative = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context_1 = _build_technique_context_block(tech_ids_for_narrative)
    if pinned_technique_ids:
        technique_framing_1 = (
            "You MUST use these ATLAS technique(s) in the narrative. "
            "Reference them in narrative step actions and annotate with the ID "
            "in square brackets, e.g. [AML.T0054]. This is a hard constraint.\n"
        )
    else:
        technique_framing_1 = (
            "Reference these techniques in narrative step actions where applicable. "
            "Annotate technique usage with the ID in square brackets, "
            "e.g. [AML.T0054].\n"
            if seed.atlas_technique_ids
            else ""
        )

    owasp_llm_formatted = _format_taxonomy_ids(seed.owasp_llm_ids, _OWASP_LLM_NAMES)

    # Look up entry point direction and controllability from the capability profile
    pinned_entry_point_direction = _lookup_entry_point_direction(
        profile, pinned_entry_point
    )
    pinned_entry_point_controllability = _lookup_entry_point_controllability(
        profile, pinned_entry_point
    )

    # Build KC/KCX definition block for the prompt
    kc_definitions = build_kc_definitions_block(profile.kc_subcodes)

    # Build focused ontology context block for this seed
    ontology_context = _build_ontology_context(
        entry_point_name=pinned_entry_point or "",
        entry_point_direction=pinned_entry_point_direction,
        zones=profile.zones_active,
        technique_ids=list(tech_ids_for_narrative) if tech_ids_for_narrative else [],
        entry_point_controllability=pinned_entry_point_controllability,
    )

    return {
        "use_case": use_case,
        "seed": seed,
        "profile": profile,
        "owasp_llm_formatted": owasp_llm_formatted,
        "technique_context": technique_context_1,
        "technique_framing": technique_framing_1,
        "actor_section": actor_section,
        "goal_section": goal_section,
        "diversity_section": diversity_section,
        "pattern_section": pattern_section,
        "structural_section": structural_section,
        "pinned_entry_point": pinned_entry_point,
        "pinned_entry_point_direction": pinned_entry_point_direction,
        "kc_definitions": kc_definitions,
        "ontology_context": ontology_context,
    }


def _call_narrative(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    actor_profile: ActorProfile | None = None,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    prior_titles: list[str] | None = None,
) -> tuple[NarrativeLayer, LLMResult]:
    """Generate an attack narrative for a scenario seed (Call 1).

    Delegates context building to :func:`build_call1_context`, then renders
    templates, calls the LLM, and post-processes the narrative.

    Returns:
        Tuple of (NarrativeLayer, LLMResult).
    """
    ctx = build_call1_context(
        seed=seed,
        profile=profile,
        use_case=use_case,
        actor_profile=actor_profile,
        preferred_entry_point=preferred_entry_point,
        excluded_entry_points=excluded_entry_points,
        excluded_patterns=excluded_patterns,
        excluded_structural_patterns=excluded_structural_patterns,
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=pinned_technique_ids,
        prior_titles=prior_titles,
    )

    result = client.complete(
        system_prompt=render_prompt("call1_system.j2"),
        user_prompt=render_prompt("call1_user.j2", **ctx),
        response_format=Call1Response,
    )
    narrative = _map_call1_to_narrative(result.content)
    narrative = _sanitize_narrative(narrative)
    narrative = _enforce_zones_narrative(narrative, profile.zones_active)
    return narrative, result
