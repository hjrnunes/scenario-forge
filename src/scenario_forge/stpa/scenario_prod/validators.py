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

from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
)
from scenario_forge.stpa.models.enriched_threat_set import (
    EnrichedThreatSet,
    StructuralThreat,
)
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec, ScenarioEnvelope
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

__all__ = [
    "ValidationResult",
    "TraceabilityError",
    "validate_bdi_grounding",
    "validate_vulnerability_completeness",
    "validate_tree_branch_coverage",
    "validate_gherkin_structure",
    "validate_loss_hazard_id_references",
    "validate_attack_tree_root_label",
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
                f"DefenderBelief {belief.pm_id} has an empty vulnerability annotation."
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
        return ValidationResult.failure(
            [
                f"Attack tree uses only {count} branch categor"
                f"{'y' if count == 1 else 'ies'}, need at least 2."
            ]
        )
    return ValidationResult.success()


def validate_gherkin_structure(gherkin: GherkinSpec | str) -> ValidationResult:
    """Validate that Gherkin has should/but structure and PM references.

    Accepts either a structured :class:`GherkinSpec` or a raw Gherkin
    string (for backward compatibility).

    When given a :class:`GherkinSpec`, validates the structured fields:
    - ``given`` is non-empty and references process model states (PM-*).
    - ``then_expected`` is non-empty and contains a "should" step.
    - ``then_actual`` is non-empty and contains a "but" step.

    When given a ``str``, validates the text for:
    - Contains a `Then ... should ...` line.
    - Contains a `But` line.
    - Given steps reference process model states (PM-* IDs or descriptions).

    Args:
        gherkin: The Gherkin spec (structured or raw text) to validate.

    Returns:
        A :class:`ValidationResult`.
    """
    if isinstance(gherkin, GherkinSpec):
        return _validate_gherkin_spec(gherkin)
    return _validate_gherkin_text(gherkin)


_PM_ID_RE = re.compile(r"PM-\d+-\d+")


def _validate_gherkin_spec(spec: GherkinSpec) -> ValidationResult:
    """Validate a structured :class:`GherkinSpec`."""
    errors: list[str] = []
    errors.extend(_check_then_expected(spec.then_expected))
    errors.extend(_check_then_actual(spec.then_actual))
    errors.extend(_check_given_pm_refs(spec.given))
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _check_then_expected(steps: list[str]) -> list[str]:
    """Validate that then_expected has a 'should' clause."""
    if not steps:
        return [
            "Gherkin missing a 'Then ... should ...' step (then_expected is empty)."
        ]
    if not any("should" in step.lower() for step in steps):
        return ["Gherkin then_expected missing a 'should' clause."]
    return []


def _check_then_actual(steps: list[str]) -> list[str]:
    """Validate that then_actual has a 'But' clause."""
    if not steps:
        return ["Gherkin missing a 'But' step (then_actual is empty)."]
    if not any(step.lower().startswith("but") for step in steps):
        return ["Gherkin then_actual missing a 'But' clause."]
    return []


def _check_given_pm_refs(steps: list[str]) -> list[str]:
    """Validate that given steps reference process model states (PM-*)."""
    if not steps or not any(_PM_ID_RE.search(step) for step in steps):
        return ["Gherkin Given steps do not reference a process model state (PM-*)."]
    return []


def _validate_gherkin_text(gherkin_text: str) -> ValidationResult:
    """Validate raw Gherkin text for should/but structure and PM references."""
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


# Regex patterns for Loss and Hazard ID extraction
_LOSS_ID_RE = re.compile(r"L-\d+")
_HAZARD_ID_RE = re.compile(r"H-\d+")


def validate_loss_hazard_id_references(
    gherkin: GherkinSpec | str,
    loss_analysis: LossAnalysis,
) -> ValidationResult:
    """Check that all L-* and H-* references in Gherkin are valid.

    Extracts all L-\\* and H-\\* patterns from the Gherkin text (using
    ``gherkin_raw`` for :class:`GherkinSpec` input, or the text directly
    for ``str`` input) and checks each against the valid IDs from the
    loss analysis.

    Args:
        gherkin: The Gherkin spec (structured or raw text) to check.
        loss_analysis: The loss analysis with valid Loss and Hazard IDs.

    Returns:
        A :class:`ValidationResult` with errors for hallucinated IDs.
    """
    if isinstance(gherkin, GherkinSpec):
        text = gherkin.to_feature_text()
    else:
        text = gherkin

    valid_loss_ids = {
        loss.loss_id
        for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    }
    valid_hazard_ids = {hazard.hazard_id for hazard in loss_analysis.hazards}

    errors: list[str] = []
    errors.extend(_find_hallucinated_ids(text, _LOSS_ID_RE, valid_loss_ids, "Loss"))
    errors.extend(
        _find_hallucinated_ids(text, _HAZARD_ID_RE, valid_hazard_ids, "Hazard")
    )

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _find_hallucinated_ids(
    text: str,
    id_regex: re.Pattern,
    valid_ids: set[str],
    label: str,
) -> list[str]:
    """Find IDs in *text* matching *id_regex* that are not in *valid_ids*."""
    errors: list[str] = []
    for match in id_regex.finditer(text):
        id_val = match.group()
        if id_val not in valid_ids:
            errors.append(f"Gherkin references hallucinated {label} ID '{id_val}'.")
    return errors


def validate_attack_tree_root_label(
    attack_tree: dict,
    ica_type: str,
    ca_id: str,
) -> ValidationResult:
    """Check that attack tree root matches the expected format.

    Expected root label: ``f"Induce ICA {ica_type} on {ca_id}"``.

    The check is case-insensitive on "Induce ICA" but exact on the
    ICA type enum value and the CA ID.

    Args:
        attack_tree: The attack tree dict with a ``root`` key.
        ica_type: The expected UCAType value (e.g. ``NOT_PROVIDED``).
        ca_id: The expected control action ID (e.g. ``CA-1-1``).

    Returns:
        A :class:`ValidationResult`.
    """
    root = _extract_root(attack_tree)
    expected = f"Induce ICA {ica_type} on {ca_id}"

    if not root or not root.strip():
        return ValidationResult.failure(
            [f"Attack tree root is empty; expected '{expected}'."]
        )

    # Case-insensitive on "Induce ICA", exact on type and CA
    root_lower = root.lower().strip()
    prefix = "induce ica "
    if not root_lower.startswith(prefix):
        return ValidationResult.failure(
            [
                f"Attack tree root '{root}' does not start with 'Induce ICA'; "
                f"expected '{expected}'."
            ]
        )

    remainder = root.strip()[len("Induce ICA ") :]
    expected_suffix = f"{ica_type} on {ca_id}"
    if remainder != expected_suffix:
        return ValidationResult.failure(
            [
                f"Attack tree root '{root}' does not match expected '{expected}' "
                f"(ICA type or CA ID mismatch)."
            ]
        )

    return ValidationResult.success()


def _extract_root(attack_tree: dict | object) -> str:
    """Safely extract the root label from *attack_tree*."""
    if isinstance(attack_tree, dict):
        return attack_tree.get("root", "")
    return ""


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
        getattr(item, id_attr) for r in responsibilities for item in getattr(r, attr)
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
        errors.extend(_validate_single_scenario_traceability(scenario, lookups))
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
            t.ica_id: t for t in enriched_threat_set.structural_threats if t.ica_id
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
        errors.append(
            TraceabilityError(
                scenario_id=sid,
                broken_link="ica",
                expected=f"valid ica_id from {sorted(lookups.threat_by_ica_id.keys())}",
                actual=spec.threat_source.ica_id or "None",
            )
        )
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
        errors.append(
            TraceabilityError(
                scenario_id=sid,
                broken_link="provenance_root",
                expected=str(LEGAL_PROVENANCE_ROOTS | {"structural"}),
                actual=provenance,
            )
        )

    if spec.target_controller not in lookups.resp_ids:
        errors.append(
            TraceabilityError(
                scenario_id=sid,
                broken_link="responsibility",
                expected=f"valid RESP ID from {sorted(lookups.resp_ids)}",
                actual=spec.target_controller,
            )
        )

    if spec.target_control_action not in lookups.all_ca_ids:
        errors.append(
            TraceabilityError(
                scenario_id=sid,
                broken_link="control_action",
                expected=f"valid CA ID from {sorted(lookups.all_ca_ids)}",
                actual=spec.target_control_action,
            )
        )

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
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="hazard",
                    expected=f"valid hazard ID from {sorted(lookups.hazard_ids)}",
                    actual=hz_id,
                )
            )

    for cs_id in threat.related_constraints:
        if cs_id not in lookups.constraint_ids and not cs_id.startswith("RC-"):
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="constraint",
                    expected=f"valid constraint ID from {sorted(lookups.constraint_ids)}",
                    actual=cs_id,
                )
            )

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
            _find_orphans_in_resp(
                resp, referenced_pms, referenced_cas, referenced_resps
            )
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
        pm.pm_id for pm in resp.process_model_parts if pm.pm_id not in ref_pms
    )
    orphans.extend(ca.ca_id for ca in resp.control_actions if ca.ca_id not in ref_cas)
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
# {"version":1,"tested_at":"2026-08-10T14:21:32Z","module_hash":"1459b14730648e4ebd546d26c3ac30889802875c1a9fbf94b4a3747a4b8f8077","functions":[{"id":"func/ValidationResult.success","name":"success","line":61,"end_line":62,"hash":"3a36210a7ab40b638ac1787bb2c2864d7845ea1067e8099a266579c7b582c851"},{"id":"func/ValidationResult.failure","name":"failure","line":65,"end_line":66,"hash":"60f505ac55cbbc1d676a483041caddcdf4a657855220434e64db790a50aed783"},{"id":"func/validate_bdi_grounding","name":"validate_bdi_grounding","line":79,"end_line":104,"hash":"19036765170d7a3d63df49fea53d24a5af5b02c7a7392f55e90c899b70acf6d7"},{"id":"func/validate_vulnerability_completeness","name":"validate_vulnerability_completeness","line":107,"end_line":125,"hash":"1007fba41561cfa487c5264983bfeaf9b92b834551517441610b5056f38c8dea"},{"id":"func/count_branch_categories","name":"count_branch_categories","line":128,"end_line":130,"hash":"ad647c02ff326df1e0c45a363a224a23262d5a27825f7a790d0df836c05ece5b"},{"id":"func/get_branch_categories","name":"get_branch_categories","line":133,"end_line":141,"hash":"5814967ed8907a71023845a8d1295e50e48a83ac679c95a7c831f7ca919cef6b"},{"id":"func/validate_tree_branch_coverage","name":"validate_tree_branch_coverage","line":144,"end_line":159,"hash":"4f98b4fa74974afa6d46ef999d2896bee00594490f40157deaf75b8ed126203c"},{"id":"func/validate_gherkin_structure","name":"validate_gherkin_structure","line":162,"end_line":186,"hash":"f4a3d2f9893ce942f6e3dfbfc650763d43c26426cbd9c595c8c72a3f110153c2"},{"id":"func/_validate_gherkin_spec","name":"_validate_gherkin_spec","line":192,"end_line":198,"hash":"398e9168e9ad4349c1db27317f8d6b6e22347b949967d5aa558644313fe8f9bf"},{"id":"func/_check_then_expected","name":"_check_then_expected","line":201,"end_line":207,"hash":"d436c1f9f0fb2350bbf742aa91417c02cb015167826d21ca8f953126ad936a31"},{"id":"func/_check_then_actual","name":"_check_then_actual","line":210,"end_line":216,"hash":"436d764af35d227cade2b548bc3a13443366fec541cdcd549936edc85b855f47"},{"id":"func/_check_given_pm_refs","name":"_check_given_pm_refs","line":219,"end_line":225,"hash":"26758312520940d2b363211bacfe229a7ad04c2943b0b61f8d4461f24582b075"},{"id":"func/_validate_gherkin_text","name":"_validate_gherkin_text","line":228,"end_line":247,"hash":"4fbdebc838e8fdc42cb1c7147c8079b9b8fe6d836db375a4a8cb55b3e1fa8cab"},{"id":"func/validate_loss_hazard_id_references","name":"validate_loss_hazard_id_references","line":255,"end_line":288,"hash":"687ce2eada1c847fc972fb779adec639ca4ac22b85315841ddd0ab5c5438e85a"},{"id":"func/_find_hallucinated_ids","name":"_find_hallucinated_ids","line":291,"end_line":303,"hash":"bba7e26b375636aced77d3b7be96af00a8ab2fc81d7c4dd22bfd0e31e664c1db"},{"id":"func/validate_attack_tree_root_label","name":"validate_attack_tree_root_label","line":306,"end_line":351,"hash":"b6810cfbe66f0c61e7860cfae608bc7b7423d840171b085134aa0159c676088a"},{"id":"func/_extract_root","name":"_extract_root","line":354,"end_line":358,"hash":"7b09cbea173509a819b558e71dea5f6ce4de8f9a8a9def18bcf9da1b8cfb4b21"},{"id":"func/validate_tree_id_references","name":"validate_tree_id_references","line":360,"end_line":383,"hash":"ebcd44a47e295f9a9a91102fbc47d9826b33ab553aa85fcbd4a56460e72f464c"},{"id":"func/collect_valid_tree_ids","name":"collect_valid_tree_ids","line":386,"end_line":393,"hash":"c47456ace92e1e6dccb0446300c705ae1a4534b28c0f96070070c2d404bcfd6a"},{"id":"func/_flatten_nested_ids","name":"_flatten_nested_ids","line":396,"end_line":410,"hash":"0db7827f3a6ff4a5d806cda897b17b57ee42b65724b33ba2d6cd85a6f4a16a6c"},{"id":"func/_find_invalid_ids","name":"_find_invalid_ids","line":413,"end_line":425,"hash":"bfe8f2662e0382d2f34e1443be856e7bf8ece1b50ef0db0ad94c6d9bb2ac03ca"},{"id":"func/_flatten_tree_to_text","name":"_flatten_tree_to_text","line":428,"end_line":430,"hash":"1dad91db161fa6d2d88c90494e16b924113f9da3518088e3fd0e7abe6cba828f"},{"id":"func/validate_traceability","name":"validate_traceability","line":433,"end_line":464,"hash":"76c05ee9095e81cf02b066a9d46eb9284e5e14ed2f06d072f1fa1a4a3667331a"},{"id":"func/_build_traceability_lookups","name":"_build_traceability_lookups","line":478,"end_line":495,"hash":"22eb64e4511295ef533581b0497057b488f770cf2e1c933fca03e57124dcc57a"},{"id":"func/_validate_single_scenario_traceability","name":"_validate_single_scenario_traceability","line":498,"end_line":520,"hash":"bfe6845fba17982e8134eb3754b464320a30972cacf2b0605ce75f828edb8b25"},{"id":"func/_check_scenario_links","name":"_check_scenario_links","line":523,"end_line":556,"hash":"2ec1f695c39932d4b1786511eb1365a9831e6e79134e89b47e27bb46e01b9cd1"},{"id":"func/_check_hazard_and_constraint_links","name":"_check_hazard_and_constraint_links","line":559,"end_line":585,"hash":"79671e032e7cb2a178a7527424d3b04d54085cca49d4881b9e89bea7c5b5bfd7"},{"id":"func/detect_orphan_elements","name":"detect_orphan_elements","line":588,"end_line":604,"hash":"dfa990f8c9ce8ab74e9a0eed95702454409aef6b1a672053b4393cd179a0a920"},{"id":"func/_collect_referenced_ids","name":"_collect_referenced_ids","line":607,"end_line":630,"hash":"01b368e8e43e1007d906556a26b01deb6b35938b2757ac92f376b8e0040641b8"},{"id":"func/_find_orphan_elements","name":"_find_orphan_elements","line":633,"end_line":644,"hash":"f0559e49a7893e2c5c86f03b9ad32223d59143a33580ed883993c8a842aa872a"},{"id":"func/_find_orphans_in_resp","name":"_find_orphans_in_resp","line":647,"end_line":665,"hash":"8fe01464546569fb46383d39a7315314090c8dee4a48f7e3352f32b61f4c13bd"},{"id":"func/detect_orphan_icas","name":"detect_orphan_icas","line":668,"end_line":690,"hash":"bd47a7852159d5e33d72771d4c134aba2618878ddaa9f387d092aba575946245"}]}
# mutate4py-manifest-end
