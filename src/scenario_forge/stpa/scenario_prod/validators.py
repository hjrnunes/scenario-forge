"""Stage 7 — Validators (stage-local + end-to-end traceability).

Stage-local validators check BDI grounding, vulnerability completeness,
tree branch coverage, and Gherkin structure. End-to-end traceability
validation checks the full provenance chain:
provenance root → loss → hazard → constraint → responsibility → CA → ICA → scenario.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from scenario_forge.stpa.models.control_structure import ControlStructure, Responsibility
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet, StructuralThreat
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
    "collect_valid_tree_ids",
    "count_branch_categories",
    "get_branch_categories",
    "BRANCH_CATEGORIES",
]

BRANCH_CATEGORIES = ["controller_side", "path_side", "coordination_gap"]

LEGAL_PROVENANCE_ROOTS = {"risk_card", "use_case", "critic_derived"}

# (regex pattern, label) for tree ID validation
_TREE_ID_SPECS: list[tuple[str, str]] = [
    (r"PM-\d+-\d+", "PM"),
    (r"FB-\d+-\d+", "FB"),
    (r"CA-\d+-\d+", "CA"),
    (r"RESP-\d+", "RESP"),
]


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


def count_branch_categories(attack_tree: dict) -> int:
    """Count how many of the 3 branch categories are used in the tree."""
    return len(get_branch_categories(attack_tree))


def get_branch_categories(attack_tree: dict) -> set[str]:
    """Get the set of branch categories used in the tree."""
    branches = attack_tree.get("branches", [])
    categories: set[str] = set()
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
    count = count_branch_categories(attack_tree)
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
    valid_ids = collect_valid_tree_ids(control_structure)
    tree_text = _flatten_tree_to_text(attack_tree)

    errors: list[str] = []
    for pattern, label in _TREE_ID_SPECS:
        errors.extend(_find_invalid_ids(tree_text, pattern, valid_ids[label], label))

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def collect_valid_tree_ids(cs: ControlStructure) -> dict[str, set[str]]:
    """Collect all valid PM, FB, CA, and RESP IDs from the control structure."""
    return {
        "PM": _flatten_nested_ids(cs.responsibilities, "process_model_parts", "pm_id"),
        "FB": _flatten_nested_ids(cs.responsibilities, "feedback_channels", "fb_id"),
        "CA": _flatten_nested_ids(cs.responsibilities, "control_actions", "ca_id"),
        "RESP": {r.resp_id for r in cs.responsibilities},
    }


def _flatten_nested_ids(
    responsibilities: list[Responsibility],
    attr: str,
    id_attr: str,
) -> set[str]:
    """Flatten a nested collection of IDs from responsibilities.

    Each responsibility has a list attribute (e.g. ``process_model_parts``);
    this collects ``id_attr`` from every item across all responsibilities.
    """
    return {
        getattr(item, id_attr)
        for r in responsibilities
        for item in getattr(r, attr)
    }


def _find_invalid_ids(
    tree_text: str,
    pattern: str,
    valid_ids: set[str],
    label: str,
) -> list[str]:
    """Find IDs matching *pattern* in *tree_text* that are not in *valid_ids*."""
    errors: list[str] = []
    for match in re.finditer(pattern, tree_text):
        id_val = match.group()
        if id_val not in valid_ids:
            errors.append(f"Attack tree references non-existent {label} '{id_val}'.")
    return errors


def _flatten_tree_to_text(attack_tree: dict) -> str:
    """Flatten an attack tree dict to a single text string for ID scanning."""
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
    lookups = _build_traceability_lookups(
        enriched_threat_set, control_structure, loss_analysis
    )

    errors: list[TraceabilityError] = []
    for scenario in scenarios:
        errors.extend(
            _validate_single_scenario_traceability(
                scenario, lookups
            )
        )
    return errors


@dataclass
class _TraceabilityLookups:
    """Pre-computed lookup sets for traceability validation."""

    hazard_ids: set[str]
    constraint_ids: set[str]
    resp_ids: set[str]
    all_ca_ids: set[str]
    threat_by_ica_id: dict[str, StructuralThreat]


def _build_traceability_lookups(
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> _TraceabilityLookups:
    """Build lookup maps for traceability validation."""
    cs_ids = collect_valid_tree_ids(control_structure)
    return _TraceabilityLookups(
        hazard_ids={h.hazard_id for h in loss_analysis.hazards},
        constraint_ids={sc.constraint_id for sc in loss_analysis.security_constraints},
        resp_ids=cs_ids["RESP"],
        all_ca_ids=cs_ids["CA"],
        threat_by_ica_id={
            t.ica_id: t
            for t in enriched_threat_set.structural_threats
            if t.ica_id
        },
    )


def _validate_single_scenario_traceability(
    scenario: ScenarioEnvelope,
    lookups: _TraceabilityLookups,
) -> list[TraceabilityError]:
    """Validate the provenance chain for a single scenario."""
    spec = scenario.scenario_spec
    sid = scenario.scenario_id
    errors: list[TraceabilityError] = []

    errors.extend(_check_scenario_links(sid, spec, lookups))

    threat = lookups.threat_by_ica_id.get(spec.threat_source.ica_id)
    if threat is None:
        errors.append(TraceabilityError(
            scenario_id=sid,
            broken_link="ica",
            expected=f"valid ica_id from {sorted(lookups.threat_by_ica_id.keys())}",
            actual=spec.threat_source.ica_id or "None",
        ))
        return errors

    errors.extend(_check_hazard_and_constraint_links(sid, threat, lookups))
    return errors


def _check_scenario_links(
    sid: str,
    spec: ScenarioSpec,
    lookups: _TraceabilityLookups,
) -> list[TraceabilityError]:
    """Check provenance root, responsibility, and CA links for a scenario."""
    errors: list[TraceabilityError] = []

    provenance = spec.threat_source.provenance
    if provenance not in LEGAL_PROVENANCE_ROOTS and provenance != "structural":
        errors.append(TraceabilityError(
            scenario_id=sid,
            broken_link="provenance_root",
            expected=str(LEGAL_PROVENANCE_ROOTS | {"structural"}),
            actual=provenance,
        ))

    if spec.target_controller not in lookups.resp_ids:
        errors.append(TraceabilityError(
            scenario_id=sid,
            broken_link="responsibility",
            expected=f"valid RESP ID from {sorted(lookups.resp_ids)}",
            actual=spec.target_controller,
        ))

    if spec.target_control_action not in lookups.all_ca_ids:
        errors.append(TraceabilityError(
            scenario_id=sid,
            broken_link="control_action",
            expected=f"valid CA ID from {sorted(lookups.all_ca_ids)}",
            actual=spec.target_control_action,
        ))

    return errors


def _check_hazard_and_constraint_links(
    sid: str,
    threat: StructuralThreat,
    lookups: _TraceabilityLookups,
) -> list[TraceabilityError]:
    """Check hazard and constraint links for a scenario's threat."""
    errors: list[TraceabilityError] = []

    for hz_id in threat.related_hazards:
        if hz_id not in lookups.hazard_ids:
            errors.append(TraceabilityError(
                scenario_id=sid,
                broken_link="hazard",
                expected=f"valid hazard ID from {sorted(lookups.hazard_ids)}",
                actual=hz_id,
            ))

    for cs_id in threat.related_constraints:
        if cs_id not in lookups.constraint_ids and not cs_id.startswith("RC-"):
            errors.append(TraceabilityError(
                scenario_id=sid,
                broken_link="constraint",
                expected=f"valid constraint ID from {sorted(lookups.constraint_ids)}",
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
    referenced = _collect_referenced_ids(enriched_threat_set.structural_threats)
    return _find_orphan_elements(control_structure, referenced)


def _collect_referenced_ids(
    threats: list[StructuralThreat],
) -> tuple[set[str], set[str], set[str]]:
    """Collect PM, CA, and RESP IDs referenced by any threat.

    Returns:
        A tuple of (referenced_pms, referenced_cas, referenced_resps).
    """
    referenced_pms: set[str] = set()
    referenced_cas: set[str] = set()
    referenced_resps: set[str] = set()

    for threat in threats:
        slot_parts = threat.ica_slot_id.split(":")
        if len(slot_parts) >= 2:
            referenced_resps.add(slot_parts[0])
            referenced_cas.add(slot_parts[1])

        for pm_match in re.finditer(
            r"PM-\d+-\d+", threat.ica_text + " " + threat.hazardous_context
        ):
            referenced_pms.add(pm_match.group())

    return referenced_pms, referenced_cas, referenced_resps


def _find_orphan_elements(
    control_structure: ControlStructure,
    referenced: tuple[set[str], set[str], set[str]],
) -> list[str]:
    """Find control structure elements not in the referenced set."""
    referenced_pms, referenced_cas, referenced_resps = referenced
    orphans: list[str] = []
    for resp in control_structure.responsibilities:
        orphans.extend(
            _find_orphans_in_resp(resp, referenced_pms, referenced_cas, referenced_resps)
        )
    return orphans


def _find_orphans_in_resp(
    resp: Responsibility,
    ref_pms: set[str],
    ref_cas: set[str],
    ref_resps: set[str],
) -> list[str]:
    """Find orphaned elements within a single responsibility."""
    orphans: list[str] = []
    if resp.resp_id not in ref_resps:
        orphans.append(resp.resp_id)
    orphans.extend(
        pm.pm_id for pm in resp.process_model_parts
        if pm.pm_id not in ref_pms
    )
    orphans.extend(
        ca.ca_id for ca in resp.control_actions
        if ca.ca_id not in ref_cas
    )
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T10:40:40Z","module_hash":"ab7bcbeecf2446e7429b12d50aa9ca87ec2398eb6f1f8dca4db7f256b6fcb260","functions":[{"id":"func/ValidationResult.success","name":"success","line":59,"end_line":60,"hash":"3a36210a7ab40b638ac1787bb2c2864d7845ea1067e8099a266579c7b582c851"},{"id":"func/ValidationResult.failure","name":"failure","line":63,"end_line":64,"hash":"60f505ac55cbbc1d676a483041caddcdf4a657855220434e64db790a50aed783"},{"id":"func/validate_bdi_grounding","name":"validate_bdi_grounding","line":77,"end_line":102,"hash":"19036765170d7a3d63df49fea53d24a5af5b02c7a7392f55e90c899b70acf6d7"},{"id":"func/validate_vulnerability_completeness","name":"validate_vulnerability_completeness","line":105,"end_line":123,"hash":"1007fba41561cfa487c5264983bfeaf9b92b834551517441610b5056f38c8dea"},{"id":"func/count_branch_categories","name":"count_branch_categories","line":126,"end_line":128,"hash":"ad647c02ff326df1e0c45a363a224a23262d5a27825f7a790d0df836c05ece5b"},{"id":"func/get_branch_categories","name":"get_branch_categories","line":131,"end_line":139,"hash":"5814967ed8907a71023845a8d1295e50e48a83ac679c95a7c831f7ca919cef6b"},{"id":"func/validate_tree_branch_coverage","name":"validate_tree_branch_coverage","line":142,"end_line":157,"hash":"4f98b4fa74974afa6d46ef999d2896bee00594490f40157deaf75b8ed126203c"},{"id":"func/validate_gherkin_structure","name":"validate_gherkin_structure","line":160,"end_line":191,"hash":"5dc5b70394b825ce16c81b63b2f4d8a8a3cbe8db9e0262ffe048b705c09f9cf5"},{"id":"func/validate_tree_id_references","name":"validate_tree_id_references","line":194,"end_line":217,"hash":"ebcd44a47e295f9a9a91102fbc47d9826b33ab553aa85fcbd4a56460e72f464c"},{"id":"func/collect_valid_tree_ids","name":"collect_valid_tree_ids","line":220,"end_line":227,"hash":"c47456ace92e1e6dccb0446300c705ae1a4534b28c0f96070070c2d404bcfd6a"},{"id":"func/_flatten_nested_ids","name":"_flatten_nested_ids","line":230,"end_line":244,"hash":"0db7827f3a6ff4a5d806cda897b17b57ee42b65724b33ba2d6cd85a6f4a16a6c"},{"id":"func/_find_invalid_ids","name":"_find_invalid_ids","line":247,"end_line":259,"hash":"bfe8f2662e0382d2f34e1443be856e7bf8ece1b50ef0db0ad94c6d9bb2ac03ca"},{"id":"func/_flatten_tree_to_text","name":"_flatten_tree_to_text","line":262,"end_line":264,"hash":"1dad91db161fa6d2d88c90494e16b924113f9da3518088e3fd0e7abe6cba828f"},{"id":"func/validate_traceability","name":"validate_traceability","line":267,"end_line":298,"hash":"76c05ee9095e81cf02b066a9d46eb9284e5e14ed2f06d072f1fa1a4a3667331a"},{"id":"func/_build_traceability_lookups","name":"_build_traceability_lookups","line":312,"end_line":329,"hash":"22eb64e4511295ef533581b0497057b488f770cf2e1c933fca03e57124dcc57a"},{"id":"func/_validate_single_scenario_traceability","name":"_validate_single_scenario_traceability","line":332,"end_line":354,"hash":"bfe6845fba17982e8134eb3754b464320a30972cacf2b0605ce75f828edb8b25"},{"id":"func/_check_scenario_links","name":"_check_scenario_links","line":357,"end_line":390,"hash":"2ec1f695c39932d4b1786511eb1365a9831e6e79134e89b47e27bb46e01b9cd1"},{"id":"func/_check_hazard_and_constraint_links","name":"_check_hazard_and_constraint_links","line":393,"end_line":419,"hash":"79671e032e7cb2a178a7527424d3b04d54085cca49d4881b9e89bea7c5b5bfd7"},{"id":"func/detect_orphan_elements","name":"detect_orphan_elements","line":422,"end_line":438,"hash":"dfa990f8c9ce8ab74e9a0eed95702454409aef6b1a672053b4393cd179a0a920"},{"id":"func/_collect_referenced_ids","name":"_collect_referenced_ids","line":441,"end_line":464,"hash":"01b368e8e43e1007d906556a26b01deb6b35938b2757ac92f376b8e0040641b8"},{"id":"func/_find_orphan_elements","name":"_find_orphan_elements","line":467,"end_line":478,"hash":"f0559e49a7893e2c5c86f03b9ad32223d59143a33580ed883993c8a842aa872a"},{"id":"func/_find_orphans_in_resp","name":"_find_orphans_in_resp","line":481,"end_line":499,"hash":"8fe01464546569fb46383d39a7315314090c8dee4a48f7e3352f32b61f4c13bd"},{"id":"func/detect_orphan_icas","name":"detect_orphan_icas","line":502,"end_line":524,"hash":"bd47a7852159d5e33d72771d4c134aba2618878ddaa9f387d092aba575946245"}]}
# mutate4py-manifest-end
