"""ScenarioEnvelope boundary schema (Section 4.6 of the STPA-Sec foundation spec).

SP3 final output. Wraps Stage 6 artifacts (narrative, attack tree, Gherkin)
plus the ScenarioSpec and faceting metadata.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from scenario_forge.stpa.models.enriched_threat_set import CatalogMapping
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec


class ScenarioEnvelope(BaseModel):
    """Scenario envelope wrapping Stage 6 artifacts and faceting metadata."""

    scenario_id: str
    scenario_spec: ScenarioSpec
    narrative: str  # Stage 6 Call A output
    attack_tree: dict  # Stage 6 Call B output (YAML-serializable tree)
    gherkin_spec: str  # Stage 6 Call C output
    # Faceting metadata for querying/filtering
    target_responsibility: str
    ica_type: UCAType
    catalog_mappings: list[CatalogMapping] = Field(default_factory=list)
    provenance: str  # "structural" or "catalog_only"

    @model_validator(mode="after")
    def validate_scenario_id_match(self) -> ScenarioEnvelope:
        if self.scenario_id != self.scenario_spec.scenario_id:
            raise ValueError(
                f"ScenarioEnvelope scenario_id '{self.scenario_id}' does not "
                f"match scenario_spec scenario_id "
                f"'{self.scenario_spec.scenario_id}'."
            )
        return self


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T11:52:38Z","module_hash":"d30f3163f40dc2eac5871555332b356ce184be5d9d0cdf729ce5621e1dbb1144","functions":[{"id":"func/ScenarioEnvelope.validate_scenario_id_match","name":"validate_scenario_id_match","line":31,"end_line":38,"hash":"ae66e01ea20d4bafb634c17253dfa96bea6a31c8e839f07ca0ec5a5c316bdbf4"}]}
# mutate4py-manifest-end
