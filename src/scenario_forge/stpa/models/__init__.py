"""STPA boundary schemas — Pydantic models for inter-SP data contracts.

Public API: import boundary schema classes from here rather than from
individual sub-modules.  Internal helpers (``_validation``) are not
re-exported.
"""

from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    HeuristicResult,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    check_structural_heuristics,
)
from scenario_forge.stpa.models.enriched_threat_set import (
    CatalogMapping,
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from scenario_forge.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from scenario_forge.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from scenario_forge.stpa.models.scenario_envelope import (
    ConsumerHints,
    GherkinSpec,
    ScenarioEnvelope,
    SystemContext,
)
from scenario_forge.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)

__all__ = [
    # loss_analysis
    "Hazard",
    "Loss",
    "LossAnalysis",
    "LossProvenance",
    "SecurityConstraint",
    # control_structure
    "ControlAction",
    "ControlStructure",
    "ControlledProcess",
    "CoordinationLink",
    "CoordinationMechanism",
    "ElementRef",
    "FeedbackChannel",
    "HeuristicResult",
    "ProcessModelPart",
    "ReferenceType",
    "Responsibility",
    "ResponsibilityConstraint",
    "check_structural_heuristics",
    # ica_enumeration
    "ICA",
    "ICAEnumeration",
    "ICASlot",
    "UCAType",
    # enriched_threat_set
    "CatalogMapping",
    "CoverageAnalysis",
    "EnrichedThreatSet",
    "StructuralThreat",
    # scenario_spec
    "AttackerBDI",
    "DefenderBDI",
    "DefenderBelief",
    "DefenderDesire",
    "DefenderIntention",
    "ScenarioSpec",
    "ThreatSource",
    # scenario_envelope
    "ConsumerHints",
    "GherkinSpec",
    "ScenarioEnvelope",
    "SystemContext",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"5dcba9e829a9cd8df0f5cc563c3206dfd5e1b613ca540fe8e378d0ecbcdec2ae","functions":[]}
# mutate4py-manifest-end
