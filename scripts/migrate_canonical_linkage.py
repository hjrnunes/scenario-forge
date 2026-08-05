#!/usr/bin/env python3
"""Migrate all 49 canonical patterns to add explicit resource_links and
observable_outcome_links, then recompute chain semantic digests.

Semantic migration: each link assignment is determined by analyzing the
pattern's declared resources, causal inputs/effects, boundary position,
and observable postconditions.  No mechanical cardinality mapping.

Activation classification
-------------------------
A pattern activates through exactly one branch-free mechanism:

* **direct ingress** — the attacker directly controls the canonical ingress
  entry point.  The first non-outside step is an attacker step that crosses
  into the system; it receives an ``ingress`` resource link.
* **source influence** — the attacker plants content in an upstream source
  outside the trust boundary and the *system* fetches/ingests it across a
  trust boundary into the canonical ingress.  The first non-outside step is
  a system step; it receives a ``source_influence`` resource link whose
  ``target_ingress_slot_id`` is the canonical ingress entry point.

The two mechanisms are mutually exclusive (one per chain).

This script is text-preserving: it inserts only the new linkage keys and
updates ``semantic_digest`` values, leaving all other authoring formatting
(comments, line wrapping, null representation) byte-for-byte intact.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from scenario_forge.models.attack_pattern import compute_chain_semantic_digest

# Tool-fixture step assignments: for each pattern with tool slots, which
# step uses which tool slot.  Each entry is the step that invokes the tool
# (executor acts through the tool slot to produce the step's effect).
TOOL_FIXTURE_STEPS: dict[str, dict[str, str]] = {
    "AP-T9-01": {"execute_delegated_actions": "delegated_capability"},
    "AP-T16-02": {"execute_unintended_operations": "receiving_agent"},
    "AP-T16-03": {"invoke_tool_under_false_scope": "consuming_agent"},
    "AP-T3-06": {"privileged_tool_invocation": "agent_tools"},
    "AP-T6-06": {"script_execution": "execution_tool"},
    "AP-T11-05": {"gui_action_injection": "computer_use_agent"},
    "AP-T17-03": {"tool_invocation": "adopter_agent"},
    "AP-T17-04": {"tool_invocation": "adopter_agent"},
    "AP-T6-02": {"execute_code_via_interpreter": "tool_chain"},
    "AP-T11-01": {"invoke_tools_with_attacker_args": "code_generator"},
    "AP-T11-02": {"generate_backdoored_workflow": "workflow_agent"},
    "AP-T13-04": {"replicate_in_agent_outputs": "initial_agent"},
    "AP-T2-01": {"invoke_tool": "target_tool"},
    "AP-T2-02": {"discover_data": "retrieval_tool", "collect_data": "delivery_tool"},
    "AP-T2-03": {"amplification": "amplification_tool"},
    "AP-T2-04": {"invoke_tool_from_memory": "target_tool"},
    "AP-T2-05": {"trigger_tool_invocation": "target_tool"},
    "AP-T2-06": {"invoke_tool": "execution_tool"},
    "AP-T3-03": {"operate_shadow_agent": "shadow_agent"},
    "AP-T4-03": {"amplify_api_calls": "agent_tools"},
}

_PATTERN_LINE = re.compile(r"^  ([A-Za-z0-9_.-]+):\s*$")
_STEP_LINE = re.compile(r'^(\s*)- step_id: "?([A-Za-z0-9_.-]+)"?\s*$')
_ORDER_LINE = re.compile(r"^(\s*)order: \d+\s*$")
_CHAIN_DIGEST_LINE = re.compile(r'^(\s*)semantic_digest: ("?)([0-9a-f]{64})("?)\s*$')
_RESOURCE_LINKS_LINE = re.compile(r"^(\s*)resource_links:(\s*\[\])?\s*$")
_OUTCOME_LINKS_LINE = re.compile(r"^(\s*)observable_outcome_links:(\s*\[\])?\s*$")


def _get_patterns_key(data: dict) -> str:
    for k in data:
        if k != "source":
            return k
    raise KeyError("no patterns key found")


def _first_non_outside_step(chain: dict) -> dict:
    for step in chain["steps"]:
        if step["boundary_position"] != "outside":
            return step
    raise ValueError("chain has no non-outside step")


def _slots_of_kind(chain: dict, kind: str) -> list[dict]:
    return [s for s in chain["resource_slots"] if s["kind"] == kind]


def _source_integration_slot(chain: dict) -> str:
    intermediate = [
        s
        for s in _slots_of_kind(chain, "integration")
        if s["purpose"] == "intermediate"
    ]
    if not intermediate:
        raise ValueError("source-influence chain has no intermediate integration slot")
    return intermediate[0]["slot_id"]


def _trust_boundary_slot(chain: dict) -> str:
    supporting = [
        s
        for s in _slots_of_kind(chain, "trust_boundary")
        if s["purpose"] == "supporting"
    ]
    if supporting:
        return supporting[0]["slot_id"]
    tbs = _slots_of_kind(chain, "trust_boundary")
    if not tbs:
        raise ValueError("source-influence chain has no trust boundary slot")
    return tbs[0]["slot_id"]


def _target_integration_slot(chain: dict) -> str | None:
    integrations = _slots_of_kind(chain, "integration")
    for slot in integrations:
        if slot["purpose"] == "target":
            return slot["slot_id"]
    if integrations:
        return integrations[0]["slot_id"]
    return None


def _is_source_influence(chain: dict) -> bool:
    return _first_non_outside_step(chain)["executor_role"] == "system"


def _compute_resource_links(chain: dict, pattern_id: str) -> dict[str, list[dict]]:
    """Return step_id -> resource_links list."""
    ingress_slot = chain["initial_ingress_slot_id"]
    first = _first_non_outside_step(chain)
    tool_steps = TOOL_FIXTURE_STEPS.get(pattern_id, {})
    mechanism = "source_influence" if _is_source_influence(chain) else "ingress"
    links_by_step: dict[str, list[dict]] = {}
    for step in chain["steps"]:
        links: list[dict] = []
        if mechanism == "source_influence" and step["step_id"] == first["step_id"]:
            links.append(
                {
                    "slot_id": _source_integration_slot(chain),
                    "role": "source_influence",
                    "trust_boundary_slot_id": _trust_boundary_slot(chain),
                    "target_ingress_slot_id": ingress_slot,
                }
            )
        elif mechanism == "ingress" and step["step_id"] == first["step_id"]:
            links.append(
                {
                    "slot_id": ingress_slot,
                    "role": "ingress",
                    "trust_boundary_slot_id": None,
                    "target_ingress_slot_id": None,
                }
            )
        if step["step_id"] in tool_steps:
            links.append(
                {
                    "slot_id": tool_steps[step["step_id"]],
                    "role": "tool_fixture",
                    "trust_boundary_slot_id": None,
                    "target_ingress_slot_id": None,
                }
            )
        links_by_step[step["step_id"]] = links
    return links_by_step


def _observation_for_step(
    step: dict, chain: dict, pattern_id: str, first_step_id: str
) -> tuple[str, str] | None:
    tool_steps = TOOL_FIXTURE_STEPS.get(pattern_id, {})
    ingress_slot = chain["initial_ingress_slot_id"]
    target_integration = _target_integration_slot(chain)
    if step["step_id"] in tool_steps:
        return ("tool_invocation", tool_steps[step["step_id"]])
    if step["step_id"] == first_step_id:
        return ("model_context", ingress_slot)
    if step["boundary_position"] == "inside" and target_integration:
        return ("persistent_state", target_integration)
    return ("model_context", ingress_slot)


def _compute_outcome_links(chain: dict, pattern_id: str) -> dict[str, list[dict]]:
    first_step_id = _first_non_outside_step(chain)["step_id"]
    links_by_step: dict[str, list[dict]] = {}
    for step in chain["steps"]:
        obs = _observation_for_step(step, chain, pattern_id, first_step_id)
        outcome_links: list[dict] = []
        if obs is not None:
            observation, binding = obs
            for pc in step["observable_postconditions"]:
                outcome_links.append(
                    {
                        "postcondition_id": pc["postcondition_id"],
                        "observation": observation,
                        "binding_slot_id": binding,
                    }
                )
        links_by_step[step["step_id"]] = outcome_links
    return links_by_step


def _link_block_lines(links: list[dict], key: str, indent: str) -> list[str]:
    if not links:
        return [f"{indent}{key}: []"]
    lines = [f"{indent}{key}:"]
    for link in links:
        lines.append(f"{indent}- slot_id: {link['slot_id']}")
        lines.append(f"{indent}  role: {link['role']}")
        tb = link["trust_boundary_slot_id"]
        lines.append(
            f"{indent}  trust_boundary_slot_id: {'null' if tb is None else tb}"
        )
        tg = link["target_ingress_slot_id"]
        lines.append(
            f"{indent}  target_ingress_slot_id: {'null' if tg is None else tg}"
        )
    return lines


def _outcome_block_lines(links: list[dict], key: str, indent: str) -> list[str]:
    if not links:
        return [f"{indent}{key}: []"]
    lines = [f"{indent}{key}:"]
    for link in links:
        lines.append(f"{indent}- postcondition_id: {link['postcondition_id']}")
        lines.append(f"{indent}  observation: {link['observation']}")
        lines.append(f"{indent}  binding_slot_id: {link['binding_slot_id']}")
    return lines


def migrate_file(filepath: Path) -> tuple[int, list[str]]:
    with open(filepath) as f:
        data = yaml.safe_load(f)
    patterns = data[_get_patterns_key(data)]

    # Precompute per-pattern links and digests.
    resource_by_step: dict[str, dict[str, list[dict]]] = {}
    outcome_by_step: dict[str, dict[str, list[dict]]] = {}
    new_digest: dict[str, str] = {}
    pattern_order: list[str] = []
    for pid, pattern in patterns.items():
        chain = pattern["canonical_chain"]
        resource_by_step[pid] = _compute_resource_links(chain, pid)
        outcome_by_step[pid] = _compute_outcome_links(chain, pid)
        # Build a mutated chain copy for the digest.
        chain_copy = {**chain, "steps": []}
        for step in chain["steps"]:
            s = {**step}
            s["resource_links"] = resource_by_step[pid][step["step_id"]]
            s["observable_outcome_links"] = outcome_by_step[pid][step["step_id"]]
            chain_copy["steps"].append(s)
        new_digest[pid] = compute_chain_semantic_digest(chain_copy)
        pattern_order.append(pid)

    # Text-preserving rewrite.
    text = filepath.read_text()
    lines = text.splitlines(keepends=False)
    out: list[str] = []
    current_pattern: str | None = None
    current_step: str | None = None
    step_has_resource_links = False
    step_has_outcome_links = False
    in_patterns = False
    count = 0

    for line in lines:
        if line.strip() == "patterns:":
            in_patterns = True
        m_pat = _PATTERN_LINE.match(line)
        if in_patterns and m_pat and m_pat.group(1) in patterns:
            current_pattern = m_pat.group(1)
            current_step = None
        m_step = _STEP_LINE.match(line)
        if m_step and current_pattern is not None:
            current_step = m_step.group(2)
            step_has_resource_links = False
            step_has_outcome_links = False
        # Track whether this step already carries linkage keys so the
        # script is idempotent: never insert a second block.
        if current_step is not None:
            if _RESOURCE_LINKS_LINE.match(line):
                step_has_resource_links = True
            if _OUTCOME_LINKS_LINE.match(line):
                step_has_outcome_links = True

        # Replace the chain semantic_digest value (quote-preserving).
        m_digest = _CHAIN_DIGEST_LINE.match(line)
        if m_digest and current_pattern is not None:
            indent, open_q, _digest_value = (
                m_digest.group(1),
                m_digest.group(2),
                m_digest.group(3),
            )
            quote = '"' if open_q else ""
            out.append(
                f"{indent}semantic_digest: {quote}{new_digest[current_pattern]}{quote}"
            )
            continue

        # Insert linkage keys before the step's `order:` line, using the
        # step field indent captured from the order line.  Skip insertion
        # when the step already has the key (idempotency).
        m_order = _ORDER_LINE.match(line)
        if m_order and current_pattern is not None and current_step is not None:
            field_indent = m_order.group(1)
            if not step_has_resource_links:
                rlinks = resource_by_step[current_pattern][current_step]
                out.extend(_link_block_lines(rlinks, "resource_links", field_indent))
            if not step_has_outcome_links:
                olinks = outcome_by_step[current_pattern][current_step]
                out.extend(
                    _outcome_block_lines(
                        olinks, "observable_outcome_links", field_indent
                    )
                )

        out.append(line)

    for pid in pattern_order:
        count += 1
    filepath.write_text("\n".join(out) + "\n")
    return count, pattern_order


def audit() -> None:
    """Print a per-pattern audit table of activation mechanism and links."""
    base = Path("data/taxonomies/attack-patterns")
    files = [
        f
        for f in sorted(base.glob("attack-patterns-*.yaml"))
        if "catalog-lineage" not in f.name
    ]
    print(
        f"{'pattern':12s} {'mechanism':16s} {'activation step':28s} "
        f"{'source/tb/ingress':40s} tool_steps"
    )
    total = 0
    for filepath in files:
        with open(filepath) as f:
            data = yaml.safe_load(f)
        patterns = data[_get_patterns_key(data)]
        for pid in patterns:
            chain = patterns[pid]["canonical_chain"]
            first = _first_non_outside_step(chain)
            mechanism = "source_influence" if _is_source_influence(chain) else "ingress"
            src = ""
            if mechanism == "source_influence":
                src = (
                    f"{_source_integration_slot(chain)}/{_trust_boundary_slot(chain)}"
                    f"/{chain['initial_ingress_slot_id']}"
                )
            tools = TOOL_FIXTURE_STEPS.get(pid, {})
            tool_desc = ",".join(f"{s}:{t}" for s, t in tools.items()) or "-"
            print(
                f"{pid:12s} {mechanism:16s} {first['step_id']:28s} {src:40s} {tool_desc}"
            )
            total += 1
    print(f"TOTAL: {total}")


def main() -> None:
    base = Path("data/taxonomies/attack-patterns")
    files = [
        f
        for f in sorted(base.glob("attack-patterns-*.yaml"))
        if "catalog-lineage" not in f.name
    ]
    total = 0
    for filepath in files:
        count, _ids = migrate_file(filepath)
        print(f"{filepath.name}: {count} patterns migrated")
        total += count
    print(f"\nTotal: {total} patterns migrated")
    print("\n--- Audit table ---")
    audit()


if __name__ == "__main__":
    main()
