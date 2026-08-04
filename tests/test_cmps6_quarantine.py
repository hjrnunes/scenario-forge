"""Validation lifecycle coverage for invalid cmps.6 access provenance."""

from __future__ import annotations

from scenario_forge.pipeline.validation import validate_scenario_semantics
from tests.test_actor_entry_point_validation import _make_envelope, _make_profile


def test_invalid_access_provenance_is_excluded_from_admitted_inventory() -> None:
    profile = _make_profile()
    # An initial_ingress action without the required actor access record is a
    # persistent semantic failure and therefore cannot be admitted downstream.
    scenario = _make_envelope(
        actor_type="cybercriminal",
        narrative_entry_point=profile.entry_points[0].name,
        entry_point_id=profile.entry_points[0].entry_point_id,
        access=None,
    )

    validate_scenario_semantics([scenario], profile)

    assert scenario.validation_passed is False
    assert scenario.validation is not None
    assert scenario.validation.semantic is not None
    assert scenario.validation.semantic.valid is False
    access_violations = [
        violation
        for violation in scenario.validation.semantic.violations
        if violation.rule == "missing_access_provenance"
    ]
    assert access_violations

    # The runner quarantines failed validation before eval/report inventory is
    # built; model that admission gate explicitly without requiring an LLM run.
    generated_inventory = [scenario]
    admitted_inventory = [
        candidate
        for candidate in generated_inventory
        if candidate.validation_passed is True
    ]
    assert scenario not in admitted_inventory
    assert admitted_inventory == []
