"""Structural heuristics and solution-neutrality post-checks.

Wraps the foundation's ``check_structural_heuristics`` and adds the
solution-neutrality keyword scan. These are deterministic post-checks
run after Stage 2 Call 3 assembles the ControlStructure.
"""

from __future__ import annotations

from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    HeuristicResult,
    check_structural_heuristics,
)
from scenario_forge.stpa.models.loss_analysis import LossAnalysis

# Component names that violate solution-neutrality (case-insensitive).
_SOLUTION_NEUTRALITY_KEYWORDS: tuple[str, ...] = (
    "LLM",
    "proxy",
    "orchestrator",
    "guardrail",
    "prompt",
    "API",
)


def run_heuristics(
    cs: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
) -> HeuristicResult:
    """Run structural heuristics on a control structure.

    Wraps the foundation's ``check_structural_heuristics``. When
    ``loss_analysis`` is provided, the hazard tracing check is included.

    Args:
        cs: The control structure to check.
        loss_analysis: Optional loss analysis for hazard tracing.

    Returns:
        A HeuristicResult with errors and warnings.
    """
    return check_structural_heuristics(cs, loss_analysis)


def check_solution_neutrality(cs: ControlStructure) -> list[str]:
    """Check control structure descriptions for solution-neutrality violations.

    Scans responsibility, process model part, control action, and feedback
    channel descriptions for implementation-specific component names
    (LLM, proxy, orchestrator, guardrail, prompt, API). Case-insensitive.

    Args:
        cs: The control structure to check.

    Returns:
        A list of warning messages for each violation found.
    """
    warnings: list[str] = []
    for resp in cs.responsibilities:
        _scan_description(resp.description, "responsibility", resp.resp_id, warnings)
        for pm in resp.process_model_parts:
            _scan_description(pm.description, "PM", pm.pm_id, warnings)
        for ca in resp.control_actions:
            _scan_description(ca.description, "CA", ca.ca_id, warnings)
        for fb in resp.feedback_channels:
            _scan_description(fb.description, "FB", fb.fb_id, warnings)
    return warnings


def _scan_description(
    description: str,
    element_type: str,
    element_id: str,
    warnings: list[str],
) -> None:
    """Scan a description for solution-neutrality violations and append warnings."""
    desc_lower = description.lower()
    for keyword in _SOLUTION_NEUTRALITY_KEYWORDS:
        if keyword.lower() in desc_lower:
            warnings.append(
                f"{element_type} {element_id} description contains "
                f"solution-specific term '{keyword}'."
            )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:38:54Z","module_hash":"8c73f77dde47329a50a83cd1a665b6683b367ffe380b97e4f6b2184a17d5f3ad","functions":[{"id":"func/run_heuristics","name":"run_heuristics","line":28,"end_line":44,"hash":"9d71848d1a520d80a6c5080fd4b27f215737b4c8f4894b6564357c75e59392da"},{"id":"func/check_solution_neutrality","name":"check_solution_neutrality","line":47,"end_line":69,"hash":"443de08cadb6ff8f25d0612ecb9efd0bf86e99529bc1879be35881a255a88ffc"},{"id":"func/_scan_description","name":"_scan_description","line":72,"end_line":85,"hash":"9d4fd2a8a1b69b8b3c00957bc8c0ceb945c3538b9d5aeb400381a0bdfef8e019"}]}
# mutate4py-manifest-end
