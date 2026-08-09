"""SP1 — System Model (Stages 1a, 1b, 2).

Derives the control structure that is the pipeline's primary representation.
"""

from scenario_forge.stpa.infra.llm_helpers import StageError  # noqa: E402
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
from scenario_forge.stpa.system_model.control_structure import (  # noqa: E402
    ConnectionAssignment,
    ConnectionSet,
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
from scenario_forge.stpa.system_model.run import SP1RunResult, run_sp1  # noqa: E402

__all__ = [
    # constants
    "PROMPTS_DIR",
    # error types
    "StageError",
    # internal models
    "Requirement",
    "RequirementSet",
    "ResponsibilitySet",
    "ConnectionAssignment",
    "ConnectionSet",
    "CriticFindings",
    "CriticGap",
    # run result
    "SP1RunResult",
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"9ca157f8102b7761c861dc5eed11dbcc289d4f12a0c2546cef453deb7c5cfd68","functions":[]}
# mutate4py-manifest-end
