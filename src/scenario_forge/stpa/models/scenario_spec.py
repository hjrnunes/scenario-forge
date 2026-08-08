"""ScenarioSpec boundary schema (Section 4.5 of the STPA-Sec foundation spec).

SP3 internal, produced by Stage 5.

Cross-artifact validation against ControlStructure requires the
referencing model to have access to the referenced model. This is
handled by the ``validate_against`` method.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from scenario_forge.stpa.models.enriched_threat_set import CatalogMapping
from scenario_forge.stpa.models.ica_enumeration import UCAType

if TYPE_CHECKING:
    from scenario_forge.stpa.models.control_structure import ControlStructure


class DefenderBelief(BaseModel):
    """A defender belief referencing a process model part."""

    pm_id: str  # references ControlStructure PM
    content: str
    vulnerability: str  # LLM-added annotation


class DefenderDesire(BaseModel):
    """A defender desire referencing a responsibility."""

    resp_id: str  # references ControlStructure RESP
    content: str


class DefenderIntention(BaseModel):
    """A defender intention referencing a control action."""

    ca_id: str  # references ControlStructure CA
    content: str


class DefenderBDI(BaseModel):
    """Defender Belief-Desire-Intention model."""

    beliefs: list[DefenderBelief]
    desires: list[DefenderDesire]
    intentions: list[DefenderIntention]


class AttackerBDI(BaseModel):
    """Attacker Belief-Desire-Intention model (free-form strings)."""

    beliefs: list[str]
    desires: list[str]
    intentions: list[str]


class ThreatSource(BaseModel):
    """The source threat for a scenario."""

    ica_slot_id: str  # RESP-X:CA-Y:TYPE-Z or CL-X:CM-Y:TYPE-Z
    provenance: Literal["structural", "catalog_only"]
    ica_id: str | None = None


class ScenarioSpec(BaseModel):
    """A scenario specification produced by Stage 5."""

    scenario_id: str  # SCN-001, ...
    threat_source: ThreatSource
    target_controller: str  # resp_id
    target_control_action: str  # ca_id
    ica_type: UCAType
    defender_bdi: DefenderBDI
    attacker_bdi: AttackerBDI
    catalog_context: list[CatalogMapping] = Field(default_factory=list)
    loss_scenario: str  # carried from Stage 3

    def validate_against(self, control_structure: ControlStructure) -> None:
        """Validate scenario spec references against a ControlStructure.

        Checks:
        - Every DefenderBelief.pm_id references a valid PM.
        - Every DefenderDesire.resp_id references a valid RESP.
        - Every DefenderIntention.ca_id references a valid CA.
        - target_controller references a valid RESP.
        - target_control_action references a valid CA belonging to
          target_controller.

        Args:
            control_structure: The control structure to validate against.

        Raises:
            ValueError: If any reference is invalid.
        """
        # Build lookup maps
        resp_ids: set[str] = set()
        all_pm_ids: set[str] = set()
        all_ca_ids: set[str] = set()
        ca_to_resp: dict[str, str] = {}

        for resp in control_structure.responsibilities:
            resp_ids.add(resp.resp_id)
            for pm in resp.process_model_parts:
                all_pm_ids.add(pm.pm_id)
            for ca in resp.control_actions:
                all_ca_ids.add(ca.ca_id)
                ca_to_resp[ca.ca_id] = resp.resp_id

        # Validate target_controller
        if self.target_controller not in resp_ids:
            raise ValueError(
                f"target_controller '{self.target_controller}' is not a valid "
                f"responsibility ID."
            )

        # Validate target_control_action exists and belongs to target_controller
        if self.target_control_action not in all_ca_ids:
            raise ValueError(
                f"target_control_action '{self.target_control_action}' is not a "
                f"valid control action ID."
            )
        if ca_to_resp.get(self.target_control_action) != self.target_controller:
            raise ValueError(
                f"target_control_action '{self.target_control_action}' does not "
                f"belong to target_controller '{self.target_controller}'."
            )

        # Validate defender beliefs
        for belief in self.defender_bdi.beliefs:
            if belief.pm_id not in all_pm_ids:
                raise ValueError(
                    f"DefenderBelief references non-existent pm_id "
                    f"'{belief.pm_id}'."
                )

        # Validate defender desires
        for desire in self.defender_bdi.desires:
            if desire.resp_id not in resp_ids:
                raise ValueError(
                    f"DefenderDesire references non-existent resp_id "
                    f"'{desire.resp_id}'."
                )

        # Validate defender intentions
        for intention in self.defender_bdi.intentions:
            if intention.ca_id not in all_ca_ids:
                raise ValueError(
                    f"DefenderIntention references non-existent ca_id "
                    f"'{intention.ca_id}'."
                )
