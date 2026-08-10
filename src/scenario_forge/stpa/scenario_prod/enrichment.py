"""Deterministic envelope enrichment — system_context and consumer_hints.

Two pure functions that compute enrichment blocks from SP1 data and
Stage 6 artifacts without any LLM calls:

- :func:`compute_system_context` — resolves SP1 data into a
  :class:`SystemContext` block.
- :func:`compute_consumer_hints` — computes rule-based
  :class:`ConsumerHints` for adapter filtering.
"""

from __future__ import annotations

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.models.control_structure import ControlStructure, Responsibility
from scenario_forge.stpa.models.scenario_envelope import ConsumerHints, SystemContext
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

__all__ = ["compute_consumer_hints", "compute_system_context"]

# Keywords in attack-tree leaf text that indicate tool execution.
_TOOL_KEYWORDS: tuple[str, ...] = (
    "tool",
    "execute",
    "call",
    "invoke",
    "api",
    "command",
    "function",
    "script",
)

# Phrases in narrative text that indicate multi-turn interaction.
_MULTI_TURN_PHRASES: tuple[str, ...] = (
    "subsequent turn",
    "second message",
    "follow-up request",
    "follow up request",
    "multi-turn",
    "multi turn",
    "later turn",
    "next turn",
    "repeated interaction",
    "over multiple turns",
    "across turns",
    "second turn",
    "third turn",
    "subsequent message",
    "follow-up message",
)

# garak_testability mapping from primary attack zone.
_GARAK_TESTABILITY: dict[str, str] = {
    "input": "high",
    "reasoning": "medium",
    "tool_execution": "low",
    "memory": "low",
    "inter_agent": "low",
}


def compute_system_context(
    capability_profile: CapabilityProfile,
    control_structure: ControlStructure,
    spec: ScenarioSpec,
) -> SystemContext:
    """Resolve SP1 data into a :class:`SystemContext` block.

    Looks up ``target_responsibility_description`` and
    ``target_control_action_description`` from the control structure
    using the spec's ``target_controller`` (resp_id) and
    ``target_control_action`` (ca_id).  Inlines tool names,
    active zones, and boolean flags from the capability profile.

    Args:
        capability_profile: The SP1 capability profile.
        control_structure: The SP1 control structure.
        spec: The scenario spec providing target controller/action IDs.

    Returns:
        A populated :class:`SystemContext`.
    """
    resp = _find_responsibility(control_structure, spec.target_controller)
    resp_desc = resp.description if resp else ""
    ca_desc = _find_control_action_description(resp, spec.target_control_action)

    tool_names = _extract_tool_names(capability_profile)

    return SystemContext(
        target_responsibility_description=resp_desc,
        target_control_action_description=ca_desc,
        tool_inventory=tool_names,
        active_zones=list(capability_profile.zones_active),
        multi_agent=capability_profile.multi_agent,
        has_persistent_memory=capability_profile.has_persistent_memory,
    )


def compute_consumer_hints(
    capability_profile: CapabilityProfile,
    attack_tree: dict,
    narrative: str,
    primary_attack_zone: str,
) -> ConsumerHints:
    """Compute deterministic consumer hints for adapter filtering.

    All fields are rule-based — no LLM calls.

    Args:
        capability_profile: The SP1 capability profile.
        attack_tree: The Stage 6 attack tree dict.
        narrative: The Stage 6 narrative text.
        primary_attack_zone: The primary attack zone for this scenario
            (e.g. ``"input"``, ``"tool_execution"``).

    Returns:
        A populated :class:`ConsumerHints`.
    """
    requires_tool_execution = _tree_mentions_tools(attack_tree)
    requires_multi_turn = _narrative_indicates_multi_turn(narrative)
    requires_multi_agent = capability_profile.multi_agent
    requires_persistent_state = capability_profile.has_persistent_memory

    garak = _garak_testability(primary_attack_zone)
    midojo = _midojo_testability(
        primary_attack_zone,
        requires_tool_execution,
        requires_multi_agent,
        requires_persistent_state,
    )

    return ConsumerHints(
        primary_attack_zone=primary_attack_zone,
        requires_tool_execution=requires_tool_execution,
        requires_multi_turn=requires_multi_turn,
        requires_multi_agent=requires_multi_agent,
        requires_persistent_state=requires_persistent_state,
        garak_testability=garak,
        midojo_testability=midojo,
    )


def _tree_mentions_tools(attack_tree: dict) -> bool:
    """Check attack tree leaves for tool-related keywords."""
    leaves = attack_tree.get("leaves", [])
    if not isinstance(leaves, list):
        return False
    for leaf in leaves:
        text = _extract_leaf_text(leaf)
        if _contains_any_keyword(text, _TOOL_KEYWORDS):
            return True
    return False


def _extract_leaf_text(leaf: object) -> str:
    """Extract text from a leaf node (str or dict).

    Returns the raw text without case conversion — callers that need
    case-insensitive matching should use :func:`_contains_any_keyword`.
    """
    if isinstance(leaf, str):
        return leaf
    if isinstance(leaf, dict):
        return _extract_text_from_dict(leaf)
    return ""


def _extract_text_from_dict(leaf: dict) -> str:
    """Extract the first string value from known text keys in a dict leaf."""
    for key in ("label", "text", "description", "name"):
        val = leaf.get(key)
        if isinstance(val, str):
            return val
    return ""


def _find_responsibility(
    control_structure: ControlStructure, resp_id: str
) -> Responsibility | None:
    """Find a responsibility by ID in the control structure."""
    for resp in control_structure.responsibilities:
        if resp.resp_id == resp_id:
            return resp
    return None


def _find_control_action_description(
    responsibility: Responsibility | None, ca_id: str
) -> str:
    """Find a control action description by ID within a responsibility."""
    if responsibility is None:
        return ""
    for ca in responsibility.control_actions:
        if ca.ca_id == ca_id:
            return ca.description
    return ""


def _extract_tool_names(capability_profile: CapabilityProfile) -> list[str]:
    """Extract tool names from the capability profile inventory."""
    if capability_profile.tool_inventory:
        return [entry.name for entry in capability_profile.tool_inventory]
    return []


def _contains_any_keyword(text: str, keywords: tuple[str, ...]) -> bool:
    """Check if *text* contains any of *keywords* (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _narrative_indicates_multi_turn(narrative: str) -> bool:
    """Check narrative for multi-turn indicator phrases."""
    if not narrative:
        return False
    return _contains_any_keyword(narrative, _MULTI_TURN_PHRASES)


def _garak_testability(primary_attack_zone: str) -> str:
    """Rule-based garak testability from primary attack zone.

    - ``input`` zone → ``high``
    - ``reasoning`` zone → ``medium``
    - ``tool_execution`` / ``memory`` / ``inter_agent`` zones → ``low``
    """
    return _GARAK_TESTABILITY.get(primary_attack_zone, "low")


def _midojo_testability(
    primary_attack_zone: str,
    requires_tool_execution: bool,
    requires_multi_agent: bool,
    requires_persistent_state: bool,
) -> str:
    """Rule-based midojo testability.

    - ``high`` if ``requires_tool_execution`` is True AND ``tool_execution``
      is the primary attack zone.
    - ``medium`` if ``requires_multi_agent`` OR ``requires_persistent_state``
      is True.
    - ``low`` otherwise.
    """
    if requires_tool_execution and primary_attack_zone == "tool_execution":
        return "high"
    if requires_multi_agent or requires_persistent_state:
        return "medium"
    return "low"


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T15:21:09Z","module_hash":"0554f6eccdfba699d15ea312153051f0e662e99695a5740c8076fb989b54116c","functions":[{"id":"func/compute_system_context","name":"compute_system_context","line":62,"end_line":96,"hash":"b0bd14513341b263e8685480c1aac7870a5fd40d4e65f12d585b86940ed6b710"},{"id":"func/compute_consumer_hints","name":"compute_consumer_hints","line":99,"end_line":140,"hash":"bf6bf49d1d33cdef0a5f1dff8e5ebfdfcaf98bb0b2dfcfb2a0f30ef07c58b4c3"},{"id":"func/_tree_mentions_tools","name":"_tree_mentions_tools","line":143,"end_line":152,"hash":"0f640a092f136bac81d23e0074d7eea971a0d8f795deb52d2f65cbe413aaabe8"},{"id":"func/_extract_leaf_text","name":"_extract_leaf_text","line":155,"end_line":165,"hash":"54d3bd8bd52f4012a992ed084d8a6693d140f6443f394962c79d0f0e0fba2a22"},{"id":"func/_extract_text_from_dict","name":"_extract_text_from_dict","line":168,"end_line":174,"hash":"019a70443ed4b05a24803d43aa5f485576e674085f2e5d73caf76b372f3cadd9"},{"id":"func/_find_responsibility","name":"_find_responsibility","line":177,"end_line":184,"hash":"a52336533b8bd7b341be8aac49f180f3b56c1635b09ac1752ca81406cbb7fde6"},{"id":"func/_find_control_action_description","name":"_find_control_action_description","line":187,"end_line":196,"hash":"d8d80be4f1c0da6fee606820834ec7889bfbad911411e04ba4f28c5493ad98a4"},{"id":"func/_extract_tool_names","name":"_extract_tool_names","line":199,"end_line":203,"hash":"55e2f3d20494ddadf5a026f49436d642326a7c260e2ce1af7d3fc0403be763bd"},{"id":"func/_contains_any_keyword","name":"_contains_any_keyword","line":206,"end_line":209,"hash":"33c678b9d8651fbe1692ebd00cccb34fbca969c00b99d0b00d3ec6245bd58685"},{"id":"func/_narrative_indicates_multi_turn","name":"_narrative_indicates_multi_turn","line":212,"end_line":216,"hash":"c50d887e94be7fc1e90538ea5736cf689c91eb5eccd933336c522b1aae263a7e"},{"id":"func/_garak_testability","name":"_garak_testability","line":219,"end_line":226,"hash":"b3c1e2e009a7b10d64dfe7af1b6b00531c22fb614a201ac8170ca9af4bf94ccb"},{"id":"func/_midojo_testability","name":"_midojo_testability","line":229,"end_line":247,"hash":"6b457c14f3e15d45ada96100ebf1c6679c2bccefd8a2506ac94193eb0c15b559"}]}
# mutate4py-manifest-end
