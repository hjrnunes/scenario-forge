"""Deterministic control-structure ID normalization.

High-level SP1 policy: after an LLM payload is decoded and before
``ControlStructure`` validation, assign canonical IDs from structural
position and rewrite references to those IDs.

This module is a leaf.  It depends on the boundary schema and the
standard library only — never on LLM clients, files, or Stage 2
orchestration.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    ReferenceType,
)

SourceIdEntry = tuple[str, str]
NamespaceEntries = dict[str, list[SourceIdEntry]]

_NAMESPACE_NAMES = (
    "responsibility",
    "responsibility_constraint",
    "process_model_part",
    "control_action",
    "feedback_channel",
    "controlled_process",
    "coordination_link",
    "coordination_mechanism",
)
_RESPONSIBILITY_CHILD_SPECS = (
    (
        "responsibility_constraints",
        "rc_id",
        "RC",
        "responsibility_constraint",
    ),
    ("process_model_parts", "pm_id", "PM", "process_model_part"),
    ("control_actions", "ca_id", "CA", "control_action"),
    ("feedback_channels", "fb_id", "FB", "feedback_channel"),
)
_TYPED_REFERENCE_FIELDS = (
    ("process_model_parts", "feedback_source"),
    ("control_actions", "target"),
    ("feedback_channels", "source"),
)
_TYPED_REFERENCE_NAMESPACES = {
    "responsibility": "responsibility",
    "controlled_process": "controlled_process",
}


@dataclass(frozen=True)
class ControlStructureNormalization:
    """Normalized control-structure payload and source-ID mappings.

    ``payload`` is a deep copy of the decoded input, with IDs assigned from
    structural positions and references rewritten to those IDs.  ``mapping``
    contains only source IDs that occur exactly once in the payload; callers
    can use it when they need a flat old-to-new lookup.  ``mappings`` keeps
    the same information grouped by element namespace.
    """

    payload: dict[str, Any]
    mapping: dict[str, str]
    mappings: dict[str, dict[str, str]]

    @property
    def old_to_new(self) -> dict[str, str]:
        """Alias for the flat source-ID mapping."""
        return self.mapping


def _payload_dict(payload: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    """Return a deep-copied dictionary for a decoded payload."""
    if isinstance(payload, BaseModel):
        value = payload.model_dump(mode="python", exclude_none=False)
    elif isinstance(payload, Mapping):
        value = payload
    else:
        raise TypeError(
            "Control-structure payload must be a mapping or Pydantic model, "
            f"got {type(payload).__name__}."
        )
    return copy.deepcopy(dict(value))


def _empty_namespace_entries() -> NamespaceEntries:
    """Return empty source-ID buckets in canonical namespace order."""
    return {namespace: [] for namespace in _NAMESPACE_NAMES}


def _collect_child_source_ids(
    children: Any,
    parent_index: int,
    id_key: str,
    prefix: str,
) -> list[SourceIdEntry]:
    """Collect source IDs from one responsibility child collection."""
    if not isinstance(children, list):
        return []
    entries: list[SourceIdEntry] = []
    for child_index, child in enumerate(children, start=1):
        entry = _child_source_id_entry(
            child,
            child_index,
            parent_index,
            id_key,
            prefix,
        )
        if entry is not None:
            entries.append(entry)
    return entries


def _child_source_id_entry(
    child: Any,
    child_index: int,
    parent_index: int,
    id_key: str,
    prefix: str,
) -> SourceIdEntry | None:
    """Return one child source-ID entry when its ID is a string."""
    if not isinstance(child, dict):
        return None
    old_id = child.get(id_key)
    if not isinstance(old_id, str):
        return None
    return old_id, f"{prefix}-{parent_index}-{child_index}"


def _collect_responsibility_source_ids(
    responsibility: dict[str, Any],
    responsibility_index: int,
) -> NamespaceEntries:
    """Collect a responsibility and its child source IDs."""
    entries: NamespaceEntries = {"responsibility": []}
    old_resp_id = responsibility.get("resp_id")
    if isinstance(old_resp_id, str):
        entries["responsibility"].append(
            (old_resp_id, f"RESP-{responsibility_index}")
        )

    for child_key, id_key, prefix, namespace in _RESPONSIBILITY_CHILD_SPECS:
        entries[namespace] = _collect_child_source_ids(
            responsibility.get(child_key, []),
            responsibility_index,
            id_key,
            prefix,
        )
    return entries


def _collect_controlled_process_source_ids(
    payload: dict[str, Any],
    entries: NamespaceEntries,
) -> None:
    """Append controlled-process source IDs to *entries*."""
    processes = payload.get("controlled_processes", [])
    if not isinstance(processes, list):
        return
    for process_index, process in enumerate(processes, start=1):
        old_id = _string_id(process, "cp_id")
        if old_id is not None:
            entries["controlled_process"].append(
                (old_id, f"CP-{process_index}")
            )


def _collect_coordination_source_ids(
    payload: dict[str, Any],
    entries: NamespaceEntries,
) -> None:
    """Append coordination-link and mechanism source IDs to *entries*."""
    links = payload.get("coordination_links", [])
    if not isinstance(links, list):
        return
    for link_index, link in enumerate(links, start=1):
        _collect_coordination_link_source_ids(link, link_index, entries)


def _string_id(value: Any, key: str) -> str | None:
    """Return a mapping value when *value[key]* is a string."""
    if isinstance(value, dict) and isinstance(value.get(key), str):
        return value[key]
    return None


def _collect_coordination_link_source_ids(
    link: Any,
    link_index: int,
    entries: NamespaceEntries,
) -> None:
    """Collect source IDs from one coordination link."""
    link_id = _string_id(link, "link_id")
    if link_id is not None:
        entries["coordination_link"].append((link_id, f"CL-{link_index}"))
    if not isinstance(link, dict):
        return
    mechanism = link.get("coordination_mechanism")
    mechanism_id = _string_id(mechanism, "cm_id")
    if mechanism_id is not None:
        entries["coordination_mechanism"].append(
            (mechanism_id, f"CM-{link_index}")
        )


def _source_id_entries(
    payload: dict[str, Any],
) -> NamespaceEntries:
    """Collect ``(source_id, canonical_id)`` entries by namespace."""
    entries = _empty_namespace_entries()
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return entries

    for resp_index, resp in enumerate(responsibilities, start=1):
        if not isinstance(resp, dict):
            continue
        responsibility_entries = _collect_responsibility_source_ids(
            resp, resp_index
        )
        for namespace, source_entries in responsibility_entries.items():
            entries[namespace].extend(source_entries)

    _collect_controlled_process_source_ids(payload, entries)
    _collect_coordination_source_ids(payload, entries)
    return entries


def _unique_source_map(entries: list[tuple[str, str]]) -> dict[str, str]:
    """Return a map for source IDs that occur once in one namespace."""
    counts: dict[str, int] = {}
    result: dict[str, str] = {}
    for old_id, _new_id in entries:
        counts[old_id] = counts.get(old_id, 0) + 1
    for old_id, new_id in entries:
        if counts[old_id] == 1:
            result[old_id] = new_id
    return result


def _flat_unique_source_map(
    namespace_entries: dict[str, list[tuple[str, str]]],
) -> dict[str, str]:
    """Return source IDs that occur exactly once across all namespaces."""
    occurrences: dict[str, list[str]] = {}
    for entries in namespace_entries.values():
        for old_id, new_id in entries:
            occurrences.setdefault(old_id, []).append(new_id)
    unique: dict[str, str] = {}
    for old_id, new_ids in occurrences.items():
        if len(new_ids) == 1:
            unique[old_id] = new_ids[0]
    return unique


def _set_responsibility_canonical_ids(
    responsibilities: list[Any],
) -> None:
    """Replace responsibility and child IDs with structural IDs."""
    for resp_index, resp in enumerate(responsibilities, start=1):
        if not isinstance(resp, dict):
            continue
        resp["resp_id"] = f"RESP-{resp_index}"
        _set_responsibility_child_canonical_ids(resp, resp_index)


def _set_responsibility_child_canonical_ids(
    responsibility: dict[str, Any],
    responsibility_index: int,
) -> None:
    """Replace IDs in one responsibility's child collections."""
    for child_key, id_key, prefix, _namespace in _RESPONSIBILITY_CHILD_SPECS:
        children = responsibility.get(child_key, [])
        if not isinstance(children, list):
            continue
        for child_index, child in enumerate(children, start=1):
            if isinstance(child, dict):
                child[id_key] = (
                    f"{prefix}-{responsibility_index}-{child_index}"
                )


def _set_controlled_process_canonical_ids(processes: list[Any]) -> None:
    """Replace controlled-process IDs with structural IDs."""
    for process_index, process in enumerate(processes, start=1):
        if isinstance(process, dict):
            process["cp_id"] = f"CP-{process_index}"


def _set_coordination_canonical_ids(links: list[Any]) -> None:
    """Replace coordination-link and mechanism IDs with structural IDs."""
    for link_index, link in enumerate(links, start=1):
        if not isinstance(link, dict):
            continue
        link["link_id"] = f"CL-{link_index}"
        mechanism = link.get("coordination_mechanism")
        if isinstance(mechanism, dict):
            mechanism["cm_id"] = f"CM-{link_index}"


def _set_canonical_ids(payload: dict[str, Any]) -> None:
    """Replace element IDs in *payload* with structural IDs."""
    responsibilities = payload.get("responsibilities", [])
    if isinstance(responsibilities, list):
        _set_responsibility_canonical_ids(responsibilities)

    controlled_processes = payload.get("controlled_processes", [])
    if isinstance(controlled_processes, list):
        _set_controlled_process_canonical_ids(controlled_processes)

    coordination_links = payload.get("coordination_links", [])
    if isinstance(coordination_links, list):
        _set_coordination_canonical_ids(coordination_links)


def _reference_type_value(value: Any) -> str | None:
    """Return the string value of an ElementRef type."""
    if isinstance(value, ReferenceType):
        return value.value
    if isinstance(value, str):
        return value
    return None


def _ref_items(
    responsibility: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Yield typed references nested in one responsibility."""
    for child_key, ref_key in _TYPED_REFERENCE_FIELDS:
        children = responsibility.get(child_key, [])
        if not isinstance(children, list):
            continue
        for child in children:
            if not isinstance(child, dict):
                continue
            reference = child.get(ref_key)
            if isinstance(reference, dict):
                yield reference


def _fix_type(reference: dict[str, Any]) -> None:
    """Infer a missing ElementRef type from its source ID."""
    reference_type = _reference_type_value(reference.get("type"))
    if reference_type in _TYPED_REFERENCE_NAMESPACES:
        return
    source_id = reference.get("id")
    if not isinstance(source_id, str):
        return
    if source_id.startswith("RESP-"):
        reference["type"] = "responsibility"
    elif source_id.startswith("CP-"):
        reference["type"] = "controlled_process"


def _repair_element_ref_types(payload: dict[str, Any]) -> None:
    """Infer missing ElementRef types from their source ID prefixes."""
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return
    for responsibility in responsibilities:
        if not isinstance(responsibility, dict):
            continue
        for reference in _ref_items(responsibility):
            _fix_type(reference)


def _rewrite_typed_reference(
    reference: Any,
    maps: dict[str, dict[str, str]],
) -> None:
    """Rewrite an ElementRef ID when its typed source ID is unambiguous."""
    if not isinstance(reference, dict):
        return
    namespace = _TYPED_REFERENCE_NAMESPACES.get(
        _reference_type_value(reference.get("type"))
    )
    if namespace is None:
        return
    old_id = reference.get("id")
    if isinstance(old_id, str) and old_id in maps[namespace]:
        reference["id"] = maps[namespace][old_id]


def _rewrite_local_pm_reference(
    feedback_channel: dict[str, Any],
    local_pm_map: dict[str, str],
) -> None:
    """Rewrite a feedback channel's locally scoped ``updates`` reference."""
    old_id = feedback_channel.get("updates")
    if isinstance(old_id, str) and old_id in local_pm_map:
        feedback_channel["updates"] = local_pm_map[old_id]


def _rewrite_responsibility_references(
    responsibility: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
    local_pm_map: dict[str, str],
) -> None:
    """Rewrite typed and locally scoped references in one responsibility."""
    _rewrite_typed_responsibility_references(responsibility, namespace_maps)
    _rewrite_feedback_channel_references(responsibility, local_pm_map)


def _rewrite_typed_responsibility_references(
    responsibility: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
) -> None:
    """Rewrite ElementRefs nested in a single responsibility."""
    for reference in _ref_items(responsibility):
        _rewrite_typed_reference(reference, namespace_maps)


def _rewrite_feedback_channel_references(
    responsibility: dict[str, Any],
    local_pm_map: dict[str, str],
) -> None:
    """Rewrite locally scoped PM references in a responsibility's feedback."""
    feedback_channels = responsibility.get("feedback_channels", [])
    if not isinstance(feedback_channels, list):
        return
    for feedback_channel in feedback_channels:
        if isinstance(feedback_channel, dict):
            _rewrite_local_pm_reference(feedback_channel, local_pm_map)


def _rewrite_coordination_references(
    links: list[Any],
    namespace_maps: dict[str, dict[str, str]],
) -> None:
    """Rewrite coordination references using their source-ID namespaces."""
    resp_map = namespace_maps["responsibility"]
    pm_map = namespace_maps["process_model_part"]
    reference_maps = (
        ("source", resp_map),
        ("target", resp_map),
        ("shared_pm", pm_map),
    )
    for link in links:
        if not isinstance(link, dict):
            continue
        for field_name, source_map in reference_maps:
            old_id = link.get(field_name)
            if isinstance(old_id, str) and old_id in source_map:
                link[field_name] = source_map[old_id]


def _build_source_id_maps(
    payload: dict[str, Any],
) -> tuple[NamespaceEntries, dict[str, dict[str, str]]]:
    """Collect source IDs and build unique maps for each namespace."""
    entries = _source_id_entries(payload)
    maps = {
        namespace: _unique_source_map(source_entries)
        for namespace, source_entries in entries.items()
    }
    return entries, maps


def _build_local_pm_maps(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Build per-responsibility maps for locally scoped PM references."""
    local_maps: list[dict[str, str]] = []
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return local_maps

    for resp_index, resp in enumerate(responsibilities, start=1):
        if not isinstance(resp, dict):
            local_maps.append({})
            continue
        entries = _collect_child_source_ids(
            resp.get("process_model_parts", []),
            resp_index,
            "pm_id",
            "PM",
        )
        local_maps.append(_unique_source_map(entries))
    return local_maps


def normalize_control_structure_payload(
    payload: Mapping[str, Any] | BaseModel,
) -> ControlStructureNormalization:
    """Assign canonical IDs and rewrite references in a decoded payload.

    The pass is deliberately performed on dictionaries, before
    :class:`ControlStructure` validation.  It therefore repairs malformed
    source IDs, duplicate IDs, and cross-namespace ID collisions without
    changing list order or non-ID fields.  Locally scoped feedback updates
    are resolved within their responsibility; typed responsibility/process
    references and coordination-link references use unique global source
    IDs.  Ambiguous source IDs are left unchanged so normal validation
    reports them as unresolved.
    """
    normalized = _payload_dict(payload)
    namespace_entries, namespace_maps = _build_source_id_maps(normalized)

    # Keep the source maps available before replacing IDs.  PM maps are
    # intentionally local for feedback updates, because the same PM source
    # ID is valid in separate responsibilities.
    local_pm_maps = _build_local_pm_maps(normalized)

    # Capture reference values before IDs are overwritten.
    _repair_element_ref_types(normalized)
    _rewrite_references_before_id_replacement(
        normalized,
        namespace_maps,
        local_pm_maps,
    )
    _set_canonical_ids(normalized)
    _repair_empty_descriptions(normalized)

    return ControlStructureNormalization(
        payload=normalized,
        mapping=_flat_unique_source_map(namespace_entries),
        mappings=namespace_maps,
    )


def _rewrite_references_before_id_replacement(
    payload: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
    local_pm_maps: list[dict[str, str]],
) -> None:
    """Rewrite references while their source IDs still match the maps."""
    _rewrite_responsibility_references_in_payload(
        payload,
        namespace_maps,
        local_pm_maps,
    )
    coordination_links = payload.get("coordination_links", [])
    if isinstance(coordination_links, list):
        _rewrite_coordination_references(coordination_links, namespace_maps)


def _rewrite_responsibility_references_in_payload(
    payload: dict[str, Any],
    namespace_maps: dict[str, dict[str, str]],
    local_pm_maps: list[dict[str, str]],
) -> None:
    """Rewrite references nested under every responsibility."""
    responsibilities = payload.get("responsibilities", [])
    if not isinstance(responsibilities, list):
        return
    for resp_index, resp in enumerate(responsibilities):
        if not isinstance(resp, dict):
            continue
        if resp_index < len(local_pm_maps):
            local_pm_map = local_pm_maps[resp_index]
        else:
            local_pm_map = {}
        _rewrite_responsibility_references(
            resp,
            namespace_maps,
            local_pm_map,
        )


_DESC_TYPES = {
    "responsibility": ("Responsibility", "resp_id"),
    "responsibility_constraint": (
        "Responsibility constraint",
        "rc_id",
    ),
    "process_model_part": ("Process model part", "pm_id"),
    "control_action": ("Control action", "ca_id"),
    "controlled_process": ("Controlled process", "cp_id"),
    "coordination_link": ("Coordination link", "link_id"),
    "coordination_mechanism": ("Coordination mechanism", "cm_id"),
}


def _set_empty_description(
    element: Any,
    element_type: str,
) -> None:
    """Set a placeholder description for one canonicalized element."""
    if not isinstance(element, dict) or element.get("description") != "":
        return
    type_name, id_key = _DESC_TYPES[element_type]
    element["description"] = f"{type_name} {element.get(id_key)}"


def _fb_text(feedback_channel: dict[str, Any]) -> str:
    """Build a context-based placeholder for one feedback channel."""
    updates = feedback_channel.get("updates")
    if not updates:
        return f"Feedback channel {feedback_channel.get('fb_id')}"

    source = feedback_channel.get("source")
    if isinstance(source, dict):
        source_type = _reference_type_value(source.get("type"))
        source_id = source.get("id")
        if source_type and source_id:
            return (
                f"Feedback from {source_type.replace('_', ' ')} {source_id} "
                f"updating process model part {updates}"
            )
    return f"Feedback updating process model part {updates}"


def _set_feedback_description(feedback_channel: Any) -> None:
    """Set a context-based placeholder for one empty feedback description."""
    if (
        not isinstance(feedback_channel, dict)
        or feedback_channel.get("description") != ""
    ):
        return
    feedback_channel["description"] = _fb_text(feedback_channel)


def _fix_children(children: Any, element_type: str) -> None:
    """Repair descriptions in one responsibility child collection."""
    if not isinstance(children, list):
        return
    for child in children:
        if element_type == "feedback_channel":
            _set_feedback_description(child)
        else:
            _set_empty_description(child, element_type)


def _fix_resps(responsibilities: Any) -> None:
    """Repair descriptions in responsibilities and their children."""
    if not isinstance(responsibilities, list):
        return
    for responsibility in responsibilities:
        if not isinstance(responsibility, dict):
            continue
        _set_empty_description(responsibility, "responsibility")
        for child_key, _id_key, _prefix, element_type in (
            _RESPONSIBILITY_CHILD_SPECS
        ):
            _fix_children(responsibility.get(child_key, []), element_type)


def _fix_list(elements: Any, element_type: str) -> None:
    """Repair descriptions in one top-level element collection."""
    if not isinstance(elements, list):
        return
    for element in elements:
        _set_empty_description(element, element_type)


def _fix_links(links: Any) -> None:
    """Repair coordination-link and mechanism descriptions."""
    if not isinstance(links, list):
        return
    for link in links:
        _set_empty_description(link, "coordination_link")
        if isinstance(link, dict):
            _set_empty_description(
                link.get("coordination_mechanism"),
                "coordination_mechanism",
            )


def _repair_empty_descriptions(payload: dict[str, Any]) -> None:
    """Repair only empty descriptions after IDs and references are canonical."""
    _fix_resps(payload.get("responsibilities", []))
    _fix_list(payload.get("controlled_processes", []), "controlled_process")
    _fix_links(payload.get("coordination_links", []))


def validate_normalized_control_structure(
    payload: Mapping[str, Any] | BaseModel,
) -> ControlStructure:
    """Normalize a decoded structure, then run ControlStructure validation."""
    normalized = normalize_control_structure_payload(payload)
    return ControlStructure.model_validate(normalized.payload)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-14T11:03:17Z","module_hash":"108a41cf275e28f2ed42e5e2628645852ea1c3ed4ddade231b8794a88b3da5a1","functions":[{"id":"func/ControlStructureNormalization.old_to_new","name":"old_to_new","line":77,"end_line":79,"hash":"61a2022b46c119efe8fc394b0f6573fabe19f8f510ccfee8e246192831757756"},{"id":"func/_payload_dict","name":"_payload_dict","line":82,"end_line":93,"hash":"04d63614d7054ed03af076939fa95012c7a75fe2f7282ab6202e300d3c0edcba"},{"id":"func/_empty_namespace_entries","name":"_empty_namespace_entries","line":96,"end_line":98,"hash":"f000cbe63cad1c3296a80aa7eb6a9e8c265d66db08af8f73f3e48498619af8f3"},{"id":"func/_collect_child_source_ids","name":"_collect_child_source_ids","line":101,"end_line":121,"hash":"c98829f502fd3120cc0fc57987ecfd5a41f311a1b36e67e586863e8871d19904"},{"id":"func/_child_source_id_entry","name":"_child_source_id_entry","line":124,"end_line":137,"hash":"11abcaafe3f1fb742f3b0b1a291b86b888dcc080556d2205a32875e4ffdfe7f5"},{"id":"func/_collect_responsibility_source_ids","name":"_collect_responsibility_source_ids","line":140,"end_line":159,"hash":"c9288eb08c16461f0a45a58be2e081ce4be3a32063d94d318f1a0d7b0c78e772"},{"id":"func/_collect_controlled_process_source_ids","name":"_collect_controlled_process_source_ids","line":162,"end_line":175,"hash":"5cf7a5ef7c6aa48a6fe0c9d2e08af4ac510ec84803b02b0f80c3a18d816e8824"},{"id":"func/_collect_coordination_source_ids","name":"_collect_coordination_source_ids","line":178,"end_line":187,"hash":"d38fb4a6dd81fcc21934632aa931c22239e2c997a138f31192f681f7032c0aac"},{"id":"func/_string_id","name":"_string_id","line":190,"end_line":194,"hash":"2be0e1c959077e17f1d53d73abcbdf552cc20e2dfeeb5051de2d2f694809691c"},{"id":"func/_collect_coordination_link_source_ids","name":"_collect_coordination_link_source_ids","line":197,"end_line":213,"hash":"e4d7708ec632bfdc0399d7d5d4a813e9850a4f28c9148d2927cad699892b8dc0"},{"id":"func/_source_id_entries","name":"_source_id_entries","line":216,"end_line":236,"hash":"4ab1d149107cf0b0f7d3860d409c426c22224c775ec7bbd7f1b00e8f299081db"},{"id":"func/_unique_source_map","name":"_unique_source_map","line":239,"end_line":248,"hash":"94602069054cb0124dbf827ca2dbdae29c41b8f0f74de3caa380d96349460051"},{"id":"func/_flat_unique_source_map","name":"_flat_unique_source_map","line":251,"end_line":263,"hash":"6b577e308afd3246ade4447c7916d0065e6f74acceac5b22a0797c542ae57e6d"},{"id":"func/_set_responsibility_canonical_ids","name":"_set_responsibility_canonical_ids","line":266,"end_line":274,"hash":"6d47de99c25914b784899a1fb6acce500aaf4ee0614ea91b02d878195aba1997"},{"id":"func/_set_responsibility_child_canonical_ids","name":"_set_responsibility_child_canonical_ids","line":277,"end_line":290,"hash":"c06e17e316dfa27c65bc4eb56eee941f77723ba3cd11c5720d818d5c40c8ad5c"},{"id":"func/_set_controlled_process_canonical_ids","name":"_set_controlled_process_canonical_ids","line":293,"end_line":297,"hash":"fb6b97a53c899831a27a688075df83156ee01fda0e4c5cbb4419db6af523b9cc"},{"id":"func/_set_coordination_canonical_ids","name":"_set_coordination_canonical_ids","line":300,"end_line":308,"hash":"04c933c644aba41c05398d493959f80cbb1e28ab0132a96c7ecb69e57048e105"},{"id":"func/_set_canonical_ids","name":"_set_canonical_ids","line":311,"end_line":323,"hash":"a13e31fa5b37e084a0df0df32b9eb23e3c913039e8cc299cce9bd4259d25c718"},{"id":"func/_reference_type_value","name":"_reference_type_value","line":326,"end_line":332,"hash":"1ce8b2d123998eb9c921a8749227150832ecbd8777be5be29a8dd68550f9aabb"},{"id":"func/_ref_items","name":"_ref_items","line":335,"end_line":348,"hash":"9430a6f3bed4bedb85560faf6433f9111c8ce3966a91535db50f5950b8c320b3"},{"id":"func/_fix_type","name":"_fix_type","line":351,"end_line":362,"hash":"a349e6e21f7774866752f4abf45e3ac4fa6d83c563883cfeba437f76088ab3dc"},{"id":"func/_repair_element_ref_types","name":"_repair_element_ref_types","line":365,"end_line":374,"hash":"82422bd40d6d0aa3199211c25b9f9d516ef625775a0572be16b3e3654c807c1f"},{"id":"func/_rewrite_typed_reference","name":"_rewrite_typed_reference","line":377,"end_line":391,"hash":"3598ef10b0b7eb2cd4d7ee854b5af4b23bb36036fd0ac370a1aabf8684b4c8e0"},{"id":"func/_rewrite_local_pm_reference","name":"_rewrite_local_pm_reference","line":394,"end_line":401,"hash":"93514dc77186bde827b3bffccc0a180b72c04206426883e9c80f404c9776ece6"},{"id":"func/_rewrite_responsibility_references","name":"_rewrite_responsibility_references","line":404,"end_line":411,"hash":"1e471851a8bf0d199fed3f2c742dd7c3b6e389640379975b1ff3ef753911b55e"},{"id":"func/_rewrite_typed_responsibility_references","name":"_rewrite_typed_responsibility_references","line":414,"end_line":420,"hash":"77e51082d7f6368f729d4aea39a71dd4d67de2c8e420790af17d592ec9e02d7c"},{"id":"func/_rewrite_feedback_channel_references","name":"_rewrite_feedback_channel_references","line":423,"end_line":433,"hash":"8d68098c4e797f420780765ad6643024df1d797cb1d79a1ecedce8f5590f77d0"},{"id":"func/_rewrite_coordination_references","name":"_rewrite_coordination_references","line":436,"end_line":454,"hash":"d3f62927dc29636c68cc76b577e59fd3836a0a8cb918a8c806e3641664a7a8be"},{"id":"func/_build_source_id_maps","name":"_build_source_id_maps","line":457,"end_line":466,"hash":"9634647cba55668ca0d6b59073a50818c79beae0ca12bfccff92f1dc7d663552"},{"id":"func/_build_local_pm_maps","name":"_build_local_pm_maps","line":469,"end_line":487,"hash":"79b39cf43385652eaca51a7742c95e713e4126d6330d9b644e12a26ef02450aa"},{"id":"func/normalize_control_structure_payload","name":"normalize_control_structure_payload","line":490,"end_line":526,"hash":"d9cbf646bd1eb70d0152621ee0724af4cd7bcf033ed594fb31ffda6925625e7d"},{"id":"func/_rewrite_references_before_id_replacement","name":"_rewrite_references_before_id_replacement","line":529,"end_line":542,"hash":"a3a42b9afff04f7e92f8a389961d1d849fbd78c755f5dc97c9456ed81b05a36c"},{"id":"func/_rewrite_responsibility_references_in_payload","name":"_rewrite_responsibility_references_in_payload","line":545,"end_line":565,"hash":"d72e124372ef1857f517e2453099cfed4a7569c69a4c8f2d884691ecc021ad8b"},{"id":"func/_set_empty_description","name":"_set_empty_description","line":582,"end_line":590,"hash":"df67f9471a5f9a81bb366bf6672434cee47961ca0948ef57749b04436df34805"},{"id":"func/_fb_text","name":"_fb_text","line":593,"end_line":608,"hash":"0af9c3eb2171c35eeb30d893d6bd02082be0a83e869e861b43d070c757a7bfb9"},{"id":"func/_set_feedback_description","name":"_set_feedback_description","line":611,"end_line":618,"hash":"e99c2b5586c6e3e4d17fc4d47c5f410b4ea12828e17d7525fcac1e2eaebe9861"},{"id":"func/_fix_children","name":"_fix_children","line":621,"end_line":629,"hash":"c5cdfb6507216e864fbcc263e10494e824578077f9f3c58dba87494ee959e878"},{"id":"func/_fix_resps","name":"_fix_resps","line":632,"end_line":643,"hash":"4a7cbddb66083744fd9a1c7c41c568a12fb1b559a53900f6521c314e73a73aac"},{"id":"func/_fix_list","name":"_fix_list","line":646,"end_line":651,"hash":"92f96d67c2291f3a280a19bd0442815f2a7d0553e60154d773b88d3e1435bcc7"},{"id":"func/_fix_links","name":"_fix_links","line":654,"end_line":664,"hash":"b2a619f2edf1f59498ca0ca5e1d46dc1490282b8f2987a6c8d13781ff9b43220"},{"id":"func/_repair_empty_descriptions","name":"_repair_empty_descriptions","line":667,"end_line":671,"hash":"2516bf9eeaa9eba67242f7e376555081603f4737e68f5248107fc44ad9f06e1c"},{"id":"func/validate_normalized_control_structure","name":"validate_normalized_control_structure","line":674,"end_line":679,"hash":"50b99861dc189a1f4ab2410683c9c45ecd4350b9bca9db9cfcd8c976aa1c21d6"}]}
# mutate4py-manifest-end
