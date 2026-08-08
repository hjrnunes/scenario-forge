"""SP1 — System Model (Stages 1a, 1b, 2).

Derives the control structure that is the pipeline's primary representation.
"""

from pathlib import Path

# Single source of truth for the prompts directory.
# Defined before sub-module imports so they can import it without
# triggering a circular import.
PROMPTS_DIR = Path(__file__).parent / "prompts"

from scenario_forge.stpa.system_model.control_structure import (  # noqa: E402
    Requirement,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from scenario_forge.stpa.system_model.critic import (  # noqa: E402
    CriticFindings,
    CriticGap,
    run_completeness_critic,
    run_revision,
)
from scenario_forge.stpa.system_model.heuristics import (  # noqa: E402
    check_solution_neutrality,
    run_heuristics,
)
from scenario_forge.stpa.system_model.loss_analysis import derive_loss_analysis  # noqa: E402
from scenario_forge.stpa.system_model.profile import derive_capability_profile  # noqa: E402
from scenario_forge.stpa.system_model.run import run_sp1  # noqa: E402

__all__ = [
    # constants
    "PROMPTS_DIR",
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
