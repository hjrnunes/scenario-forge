"""Stage 7 — Validators (stage-local + end-to-end traceability).

Stage-local validators check BDI grounding, vulnerability completeness,
tree branch coverage, and Gherkin structure. End-to-end traceability
validation checks the full provenance chain:
provenance root → loss → hazard → constraint → responsibility → CA → ICA → scenario.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

__all__ = [
    "ValidationResult",
    "TraceabilityError",
    "validate_bdi_grounding",
    "validate_vulnerability_completeness",
    "validate_tree_branch_coverage",
    "validate_gherkin_structure",
    "validate_tree_id_references",
    "validate_traceability",
    "detect_orphan_elements",
    "detect_orphan_icas",
    "BRANCH_CATEGORIES",
]

BRANCH_CATEGORIES = ["controller_side", "path_side", "coordination_gap"]

LEGAL_PROVENANCE_ROOTS = {"risk_card", "use_case", "critic_derived"}


@dataclass
class ValidationResult:
    """Result of a validation check."""

    passed: bool
    errors: list[str] = field(default_factory=list)

    @classmethod
    def success(cls) -> ValidationResult:
        return cls(passed=True, errors=[])

    @classmethod
    def failure(cls, errors: list[str]) -> ValidationResult:
        return cls(passed=False, errors=errors)


@dataclass
class TraceabilityError:
    """A traceability validation error for a single scenario."""

    scenario_id: str
    broken_link: str
    expected: str
    actual: str


def validate_bdi_grounding(
    scenario_spec: ScenarioSpec,
    control_structure: ControlStructure,
) -> ValidationResult:
    """Validate that defender BDI references valid control structure IDs.

    Checks:
    - Every DefenderBelief.pm_id references a valid PM.
    - Every DefenderDesire.resp_id references a valid RESP.
    - Every DefenderIntention.ca_id references a valid CA.
    - target_controller references a valid RESP.
    - target_control_action references a valid CA belonging to target_controller.

    Args:
        scenario_spec: The scenario spec to validate.
        control_structure: The control structure to validate against.

    Returns:
        A :class:`ValidationResult`.
    """
    errors: list[str] = []
    try:
        scenario_spec.validate_against(control_structure)
    except ValueError as e:
        errors.append(str(e))
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def validate_vulnerability_completeness(
    scenario_spec: ScenarioSpec,
) -> ValidationResult:
    """Validate that every defender belief has a non-empty vulnerability.

    Args:
        scenario_spec: The scenario spec to validate.

    Returns:
        A :class:`ValidationResult`.
    """
    errors: list[str] = []
    for belief in scenario_spec.defender_bdi.beliefs:
        if not belief.vulnerability or not belief.vulnerability.strip():
            errors.append(
                f"DefenderBelief {belief.pm_id} has an empty vulnerability "
                f"annotation."
            )
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _count_branch_categories(attack_tree: dict) -> int:
    """Count how many of the 3 branch categories are used in the tree."""
    branches = attack_tree.get("branches", [])
    categories = set()
    for branch in branches:
        cat = branch.get("category", "")
        if cat in BRANCH_CATEGORIES:
            categories.add(cat)
    return len(categories)


def _get_branch_categories(attack_tree: dict) -> set[str]:
    """Get the set of branch categories used in the tree."""
    branches = attack_tree.get("branches", [])
    categories = set()
    for branch in branches:
        cat = branch.get("category", "")
        if cat in BRANCH_CATEGORIES:
            categories.add(cat)
    return categories


def validate_tree_branch_coverage(attack_tree: dict) -> ValidationResult:
    """Validate that the attack tree uses at least 2 of 3 branch categories.

    Args:
        attack_tree: The attack tree dict (YAML-serializable).

    Returns:
        A :class:`ValidationResult`.
    """
    count = _count_branch_categories(attack_tree)
    if count < 2:
        return ValidationResult.failure([
            f"Attack tree uses only {count} branch categor"
            f"{'y' if count == 1 else 'ies'}, need at least 2."
        ])
    return ValidationResult.success()


def validate_gherkin_structure(gherkin_text: str) -> ValidationResult:
    """Validate that Gherkin text has should/but structure and PM references.

    Checks:
    - Contains a `Then ... should ...` line.
    - Contains a `But` line.
    - Given steps reference process model states (PM-* IDs or descriptions).

    Args:
        gherkin_text: The Gherkin text to validate.

    Returns:
        A :class:`ValidationResult`.
    """
    errors: list[str] = []
    text_lower = gherkin_text.lower()

    has_then_should = bool(re.search(r"then.*should", text_lower))
    if not has_then_should:
        errors.append("Gherkin missing a 'Then ... should ...' line.")

    has_but = bool(re.search(r"^\s*but\s", gherkin_text, re.IGNORECASE | re.MULTILINE))
    if not has_but:
        errors.append("Gherkin missing a 'But' line.")

    has_pm_ref = bool(re.search(r"PM-\d+-\d+", gherkin_text))
    if not has_pm_ref:
        errors.append(
            "Gherkin Given steps do not reference a process model state (PM-*)."
        )

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def validate_tree_id_references(
    attack_tree: dict,
    control_structure: ControlStructure,
) -> ValidationResult:
    """Validate that attack tree branch references to IDs are valid.

    Checks that any PM-*, FB-*, CA-*, RESP-* IDs mentioned in the tree
    exist in the control structure.

    Args:
        attack_tree: The attack tree dict.
        control_structure: The control structure.

    Returns:
        A :class:`ValidationResult`.
    """
    valid_pm = {pm.pm_id for r in control_structure.responsibilities for pm in r.process_model_parts}
    valid_fb = {fb.fb_id for r in control_structure.responsibilities for fb in r.feedback_channels}
    valid_ca = {ca.ca_id for r in control_structure.responsibilities for ca in r.control_actions}
    valid_resp = {r.resp_id for r in control_structure.responsibilities}

    tree_text = _flatten_tree_to_text(attack_tree)
    errors: list[str] = []

    for pm_match in re.finditer(r"PM-\d+-\d+", tree_text):
        pm_id = pm_match.group()
        if pm_id not in valid_pm:
            errors.append(f"Attack tree references non-existent PM '{pm_id}'.")

    for fb_match in re.finditer(r"FB-\d+-\d+", tree_text):
        fb_id = fb_match.group()
        if fb_id not in valid_fb:
            errors.append(f"Attack tree references non-existent FB '{fb_id}'.")

    for ca_match in re.finditer(r"CA-\d+-\d+", tree_text):
        ca_id = ca_match.group()
        if ca_id not in valid_ca:
            errors.append(f"Attack tree references non-existent CA '{ca_id}'.")

    for resp_match in re.finditer(r"RESP-\d+", tree_text):
        resp_id = resp_match.group()
        if resp_id not in valid_resp:
            errors.append(f"Attack tree references non-existent RESP '{resp_id}'.")

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _flatten_tree_to_text(attack_tree: dict) -> str:
    """Flatten an attack tree dict to a single text string for ID scanning."""
    import json
    return json.dumps(attack_tree, default=str)


def validate_traceability(
    scenarios: list[ScenarioEnvelope],
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> list[TraceabilityError]:
    """Validate end-to-end provenance chains for all scenarios.

    For each scenario, traces the chain:
    provenance root → loss → hazard → constraint → responsibility → CA → ICA → scenario

    Args:
        scenarios: List of scenario envelopes.
        enriched_threat_set: The enriched threat set.
        control_structure: The control structure.
        loss_analysis: The loss analysis.

    Returns:
        A list of :class:`TraceabilityError` for broken links.
    """
    errors: list[TraceabilityError] = []

    # Build lookup maps
    hazard_ids = {h.hazard_id for h in loss_analysis.hazards}
    constraint_ids = {sc.constraint_id for sc in loss_analysis.security_constraints}
    resp_ids = {r.resp_id for r in control_structure.responsibilities}
    all_ca_ids = {ca.ca_id for r in control_structure.responsibilities for ca in r.control_actions}
    threat_by_ica_id = {t.ica_id: t for t in enriched_threat_set.structural_threats if t.ica_id}

    for scenario in scenarios:
        spec = scenario.scenario_spec
        sid = scenario.scenario_id

        # Check provenance root
        provenance = spec.threat_source.provenance
        if provenance not in LEGAL_PROVENANCE_ROOTS and provenance != "structural":
            errors.append(TraceabilityError(
                scenario_id=sid,
                broken_link="provenance_root",
                expected=str(LEGAL_PROVENANCE_ROOTS | {"structural"}),
                actual=provenance,
            ))

        # Check responsibility link
        if spec.target_controller not in resp_ids:
            errors.append(TraceabilityError(
                scenario_id=sid,
                broken_link="responsibility",
                expected=f"valid RESP ID from {sorted(resp_ids)}",
                actual=spec.target_controller,
            ))

        # Check CA link
        if spec.target_control_action not in all_ca_ids:
            errors.append(TraceabilityError(
                scenario_id=sid,
                broken_link="control_action",
                expected=f"valid CA ID from {sorted(all_ca_ids)}",
                actual=spec.target_control_action,
            ))

        # Check ICA link — find the threat for this scenario
        threat = threat_by_ica_id.get(spec.threat_source.ica_id)
        if threat is None:
            errors.append(TraceabilityError(
                scenario_id=sid,
                broken_link="ica",
                expected=f"valid ica_id from {sorted(threat_by_ica_id.keys())}",
                actual=spec.threat_source.ica_id or "None",
            ))
            continue

        # Check hazard links
        for hz_id in threat.related_hazards:
            if hz_id not in hazard_ids:
                errors.append(TraceabilityError(
                    scenario_id=sid,
                    broken_link="hazard",
                    expected=f"valid hazard ID from {sorted(hazard_ids)}",
                    actual=hz_id,
                ))

        # Check constraint links
        for cs_id in threat.related_constraints:
            if cs_id not in constraint_ids and not cs_id.startswith("RC-"):
                errors.append(TraceabilityError(
                    scenario_id=sid,
                    broken_link="constraint",
                    expected=f"valid constraint ID from {sorted(constraint_ids)}",
                    actual=cs_id,
                ))

    return errors


def detect_orphan_elements(
    control_structure: ControlStructure,
    enriched_threat_set: EnrichedThreatSet,
) -> list[str]:
    """Detect control structure elements not referenced by any ICA.

    An element is orphaned if no structural threat references it.

    Args:
        control_structure: The control structure.
        enriched_threat_set: The enriched threat set.

    Returns:
        A list of orphan element IDs.
    """
    referenced_pms: set[str] = set()
    referenced_cas: set[str] = set()
    referenced_resps: set[str] = set()

    for threat in enriched_threat_set.structural_threats:
        slot_parts = threat.ica_slot_id.split(":")
        if len(slot_parts) >= 2:
            referenced_resps.add(slot_parts[0])
            referenced_cas.add(slot_parts[1])

        # Scan ICA text for PM references
        for pm_match in re.finditer(r"PM-\d+-\d+", threat.ica_text + " " + threat.hazardous_context):
            referenced_pms.add(pm_match.group())

    orphans: list[str] = []
    for resp in control_structure.responsibilities:
        if resp.resp_id not in referenced_resps:
            orphans.append(resp.resp_id)
        for pm in resp.process_model_parts:
            if pm.pm_id not in referenced_pms:
                orphans.append(pm.pm_id)
        for ca in resp.control_actions:
            if ca.ca_id not in referenced_cas:
                orphans.append(ca.ca_id)

    return orphans


def detect_orphan_icas(
    enriched_threat_set: EnrichedThreatSet,
    scenarios: list[ScenarioEnvelope],
) -> list[str]:
    """Detect ICAs not concretized into scenarios.

    Args:
        enriched_threat_set: The enriched threat set.
        scenarios: The produced scenario envelopes.

    Returns:
        A list of orphan ICA IDs.
    """
    scenario_ica_ids = {
        s.scenario_spec.threat_source.ica_id
        for s in scenarios
        if s.scenario_spec.threat_source.ica_id
    }
    orphans: list[str] = []
    for threat in enriched_threat_set.structural_threats:
        if threat.ica_id and threat.ica_id not in scenario_ica_ids:
            orphans.append(threat.ica_id)
    return orphans
