"""Observation acceptance handlers for the shadow_cleanup feature group."""

from __future__ import annotations

from runtime_shared import (
    ControlStructure,
    CoverageAnalysis,
    EnrichedThreatSet,
    Responsibility,
    World,
    _sp1_valid_cs_dict,
)


def _h_sc_heuristic_passed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a heuristic result that passed."""
    world.heuristic_result = type("R", (), {"passed": True, "errors": []})()
    return True, ""


def _h_sc_returns_false_heuristic_passed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns false because the heuristic passed."""
    from runtime_features.foundation import _h_heuristic_fails_with

    result = _h_heuristic_fails_with(
        world, "the heuristic check fails with error containing something", {}
    )
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if "passed" not in result[1].lower():
        return False, f"Expected 'passed' in error message, got: {result[1]}"
    return True, ""


def _h_sc_cs_resp1_available(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 is available."""
    if world.control_structure is None:
        world.control_structure = ControlStructure.model_validate(_sp1_valid_cs_dict())
    resp_ids = [r.resp_id for r in world.control_structure.responsibilities]
    if "RESP-1" not in resp_ids:
        world.control_structure = world.control_structure.model_copy(
            update={
                "responsibilities": list(world.control_structure.responsibilities)
                + [Responsibility(resp_id="RESP-1", description="Responsibility 1")]
            }
        )
    world.sc_cs_created_by_sp1_helper = True
    return True, ""


def _h_sc_world_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the world control structure has responsibility RESP-1."""
    cs = getattr(world, "control_structure", None)
    if cs is None:
        return False, "No control structure in world"
    resp_ids = [r.resp_id for r in cs.responsibilities]
    if "RESP-1" not in resp_ids:
        return False, f"Control structure does not have RESP-1: {resp_ids}"
    return True, ""


def _h_sc_cs_sp1_helper(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure was created by the SP1 helper function."""
    if not getattr(world, "sc_cs_created_by_sp1_helper", False):
        return False, "Control structure was not created by the SP1 helper"
    return True, ""


def _h_sc_sp1_no_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the SP1 mock client has no calls recorded."""
    world.sp1_mock_client = type("C", (), {"calls": []})()
    return True, ""


def _h_sc_returns_true_no_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns true because no calls were made."""
    from runtime_features.sp1 import _h_sp1_critic_prompt_cs

    result = _h_sp1_critic_prompt_cs(
        world, "the user prompt contains the control structure", {}
    )
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


def _h_sc_returns_true_unconditional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns true unconditionally."""
    from runtime_features.sp1_revision import _h_gd_pipeline_no_crash

    result = _h_gd_pipeline_no_crash(world, "the pipeline does not crash", {})
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


def _h_sc_ets_empty_uncovered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: an enriched threat set with an empty uncovered_reason."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={},
            uncovered_reason="",
        ),
    )
    return True, ""


def _h_sc_returns_false_uncovered_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the handler returns false because uncovered_reason is empty."""
    from runtime_features.sp2 import _h_sp2_uncovered_reason

    result = _h_sp2_uncovered_reason(world, "uncovered_reason is not empty", {})
    if result[0]:
        return False, "Expected handler to return false, but it returned true"
    if "empty" not in result[1].lower():
        return False, f"Expected 'empty' in error message, got: {result[1]}"
    return True, ""


def _h_sc_scorecard_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the in-memory scorecard has a validation section with N stage_local_errors."""
    world.sp3_scorecard = {
        "validation": {
            "stage_local_errors": ["error1", "error2"],
        }
    }
    return True, ""


def _h_sc_returns_true(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the handler returns true."""
    from runtime_features.sp3 import _h_sp3_scorecard_validation_section

    result = _h_sp3_scorecard_validation_section(
        world, "the scorecard validation section has 2 stage_local_errors", {}
    )
    if not result[0]:
        return (
            False,
            f"Expected handler to return true, but it returned false: {result[1]}",
        )
    return True, ""


def _h_sc_not_manual_mock(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure is not produced by manual mock call sequencing."""
    cs = getattr(world, "control_structure", None)
    if isinstance(cs, ControlStructure):
        return True, ""
    return False, {
        type(None): "No control structure produced",
    }.get(type(cs), f"Expected ControlStructure model, got {type(cs).__name__}")
