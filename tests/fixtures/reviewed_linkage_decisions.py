"""Reviewed semantic decision table for non-obvious canonical linkage.

Each entry records the reviewed observation kind, binding slot, and
concise independent rationale for a linkage decision that is not
self-evident from the postcondition description alone.  Tests validate
that the canonical YAML matches these decisions.

Decisions are grouped by rationale category:
- INGRESS_DELIVERY: request/prompt delivered to agent → model_context/ingress
- TOOL_OUTCOME: tool performs or exposes the outcome → tool_invocation/tool
- STATE_PERSIST: actual persisted state in an integration → persistent_state/integration

Rationale cites the postcondition description, produced reference,
and causal mechanism — not action kind/name, slot cardinality, or
taxonomy mapping.
"""

# Category constants for the decision table.
INGRESS_DELIVERY = "ingress_delivery"
TOOL_OUTCOME = "tool_outcome"
STATE_PERSIST = "state_persist"

# Each entry: (pattern_id, step_id, postcondition_id, observation, binding_slot_id, category, rationale)
REVIEWED_DECISIONS: list[dict] = [
    # --- Corrected linkages (second Mayor review) ---
    {
        "pattern_id": "AP-T3-02",
        "step_id": "deliver_request",
        "postcondition_id": "post.deliver.request",
        "observation": "model_context",
        "binding_slot_id": "ingress",
        "category": INGRESS_DELIVERY,
        "rationale": (
            "Postcondition: 'Obfuscated cross-boundary request delivered to "
            "the agent as a direct prompt.' The request enters the agent's "
            "context through the ingress entry point — this is context "
            "admission, not persistent state in the connected_service "
            "integration."
        ),
    },
    {
        "pattern_id": "AP-T4-03",
        "step_id": "deliver_request",
        "postcondition_id": "post.deliver.request",
        "observation": "model_context",
        "binding_slot_id": "ingress",
        "category": INGRESS_DELIVERY,
        "rationale": (
            "Postcondition: 'The crafted request submitted to the agent.' "
            "The step carries the ingress activation link; the request "
            "enters the agent's context through the entry point — this is "
            "context admission, not persistent state in the external_api "
            "integration."
        ),
    },
    {
        "pattern_id": "AP-T2-02",
        "step_id": "exfiltrate_data",
        "postcondition_id": "post.exfiltrate.data",
        "observation": "tool_invocation",
        "binding_slot_id": "delivery_tool",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'The transmission tool sends the collected data "
            "to the attacker-chosen destination.' The delivery_tool performs "
            "the outbound transmission — the outcome is exposed through the "
            "tool, not through the ingress entry point."
        ),
    },
    {
        "pattern_id": "AP-T17-03",
        "step_id": "exfiltration",
        "postcondition_id": "post.exfiltration.transmitted",
        "observation": "tool_invocation",
        "binding_slot_id": "adopter_agent",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'Each invocation silently transmits the "
            "operation's data to the attacker through the covert "
            "side-channel.' The adopter_agent tool performs the "
            "transmission — the outcome is exposed through the tool."
        ),
    },
    {
        "pattern_id": "AP-T17-03",
        "step_id": "impact",
        "postcondition_id": "post.impact.continuous_leak",
        "observation": "tool_invocation",
        "binding_slot_id": "adopter_agent",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'An adopter's invocation of the namesquatted "
            "tool exfiltrates data through the covert side-channel.' The "
            "adopter_agent tool performs the exfiltration — the outcome "
            "is exposed through the tool."
        ),
    },
    {
        "pattern_id": "AP-T17-04",
        "step_id": "exfiltration",
        "postcondition_id": "post.exfiltration.transmitted",
        "observation": "tool_invocation",
        "binding_slot_id": "adopter_agent",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'Each invocation of the poisoned version "
            "silently transmits the operation's data to the attacker.' "
            "The adopter_agent tool performs the transmission — the "
            "outcome is exposed through the tool."
        ),
    },
    {
        "pattern_id": "AP-T17-04",
        "step_id": "impact",
        "postcondition_id": "post.impact.rug_pull_complete",
        "observation": "tool_invocation",
        "binding_slot_id": "adopter_agent",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'An adopter's routine upgrade has pulled the "
            "malicious version and its invocation exfiltrates data on "
            "every use.' The adopter_agent tool performs the exfiltration "
            "— the outcome is exposed through the tool."
        ),
    },
    {
        "pattern_id": "AP-T4-01",
        "step_id": "submit_expensive_input",
        "postcondition_id": "post.submit.expensive.input",
        "observation": "model_context",
        "binding_slot_id": "ingress",
        "category": INGRESS_DELIVERY,
        "rationale": (
            "Postcondition: 'The crafted input submitted to the agent.' "
            "The step carries the ingress activation link; the input "
            "enters the agent's context through the entry point — this "
            "is context admission, not persistent state in the "
            "compute_surface integration."
        ),
    },
    {
        "pattern_id": "AP-T2-01",
        "step_id": "impact",
        "postcondition_id": "post.impact",
        "observation": "tool_invocation",
        "binding_slot_id": "target_tool",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'The tool executes with the polluted parameters "
            "and produces the out-of-bounds outcome.' The target_tool "
            "performs the outcome — the result is exposed through the tool, "
            "not through the ingress entry point."
        ),
    },
    {
        "pattern_id": "AP-T9-01",
        "step_id": "attribution_recorded_for_user",
        "postcondition_id": "post.attribution_recorded_for_user",
        "observation": "tool_invocation",
        "binding_slot_id": "delegated_capability",
        "category": TOOL_OUTCOME,
        "rationale": (
            "Postcondition: 'The agent's action is recorded as originating "
            "from the legitimate user.' The action was performed through "
            "the delegated_capability tool; the forged attribution is a "
            "consequence of the tool's execution — the outcome is exposed "
            "through the tool."
        ),
    },
    # --- Intentionally typed infeasible ---
    {
        "pattern_id": "AP-T6-07",
        "step_id": "_chain",
        "postcondition_id": "_chain",
        "observation": "_infeasible",
        "binding_slot_id": "_infeasible",
        "category": "infeasible",
        "rationale": (
            "AP-T6-07 has no activation link (no ingress or source_influence "
            "resource link). The pattern requires pre-existing attacker "
            "execution to modify the agent's configuration; this is "
            "prerequisite-based activation, which the canonical model cannot "
            "represent. Typed infeasible for candidate-v2."
        ),
    },
    # --- Borderline cases reviewed and kept as-is ---
    {
        "pattern_id": "AP-T1-06",
        "step_id": "rendered_output_exfiltration",
        "postcondition_id": "post.rendered_output_exfiltration.encoded",
        "observation": "model_context",
        "binding_slot_id": "ingress",
        "category": INGRESS_DELIVERY,
        "rationale": (
            "Postcondition: 'The sensitive data is encoded in a rendered "
            "output element the client will automatically fetch from the "
            "attacker endpoint.' The agent's rendered output is part of "
            "its model context, observable through the entry point. No "
            "tool or integration slot represents the agent's output "
            "surface; model_context/ingress is the closest truthful "
            "binding."
        ),
    },
    {
        "pattern_id": "AP-T1-06",
        "step_id": "impact",
        "postcondition_id": "post.impact.exfiltration_complete",
        "observation": "persistent_state",
        "binding_slot_id": "exfil_endpoint",
        "category": STATE_PERSIST,
        "rationale": (
            "Postcondition: 'The client's automatic fetch delivers the "
            "encoded sensitive data to the attacker-controlled endpoint.' "
            "The data arrives at the exfil_endpoint integration — this is "
            "actual persisted state at the destination."
        ),
    },
]
