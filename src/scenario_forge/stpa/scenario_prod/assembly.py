"""Assemble ScenarioEnvelope from components.

Combines the ScenarioSpec, narrative, attack tree, and Gherkin spec
into a ScenarioEnvelope with faceting metadata.
"""

from __future__ import annotations

from scenario_forge.stpa.models.scenario_envelope import GherkinSpec, ScenarioEnvelope
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

__all__ = ["assemble_envelope"]


def assemble_envelope(
    scenario_id: str,
    scenario_spec: ScenarioSpec,
    narrative: str,
    attack_tree: dict,
    gherkin_spec: GherkinSpec,
    gherkin_raw: str = "",
) -> ScenarioEnvelope:
    """Assemble a ScenarioEnvelope from its components.

    Args:
        scenario_id: The scenario ID (must match scenario_spec.scenario_id).
        scenario_spec: The scenario specification from Stage 5.
        narrative: The attack narrative text from Stage 6 Call A.
        attack_tree: The attack tree dict from Stage 6 Call B.
        gherkin_spec: The structured Gherkin spec from Stage 6 Call C.
        gherkin_raw: The raw Gherkin text from Stage 6 Call C.

    Returns:
        A :class:`ScenarioEnvelope`.
    """
    return ScenarioEnvelope(
        scenario_id=scenario_id,
        scenario_spec=scenario_spec,
        narrative=narrative,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_spec,
        gherkin_raw=gherkin_raw,
        target_responsibility=scenario_spec.target_controller,
        ica_type=scenario_spec.ica_type,
        catalog_mappings=scenario_spec.catalog_context,
        provenance=scenario_spec.threat_source.provenance,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T14:20:09Z","module_hash":"d8e76de06d1345632e26d6399fc19b7dbf275d3591022628a9699f73a1083f17","functions":[{"id":"func/assemble_envelope","name":"assemble_envelope","line":15,"end_line":47,"hash":"1fde56b2fa7bb139523b67322735564bac123fbaa7cb2892bb855017194e2faf"}]}
# mutate4py-manifest-end
