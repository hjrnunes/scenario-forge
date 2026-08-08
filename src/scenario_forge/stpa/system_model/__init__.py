"""SP1 — System Model (Stages 1a, 1b, 2).

Derives the control structure that is the pipeline's primary representation.
"""

from scenario_forge.stpa.system_model.control_structure import (
    Requirement,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    run_completeness_critic,
    run_revision,
)
from scenario_forge.stpa.system_model.heuristics import (
    check_solution_neutrality,
    run_heuristics,
)
from scenario_forge.stpa.system_model.loss_analysis import derive_loss_analysis
from scenario_forge.stpa.system_model.profile import derive_capability_profile
from scenario_forge.stpa.system_model.run import run_sp1

__all__ = [
    # internal models
    "Requirement",
    "RequirementSet",
    "ResponsibilitySet",
    "CriticFindings",
    "CriticGap",
    # stage functions
    "derive_loss_analysis",
    "derive_capability_profile",
    "derive_control_structure",
    "run_completeness_critic",
    "run_revision",
    "run_heuristics",
    "check_solution_neutrality",
    "run_sp1",
]
