"""Authoritative v3 evaluation over admitted, resolver-verified artifacts."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from pydantic import ValidationError

from scenario_forge.eval.scorecard import (
    MetricResult,
    MetricSection,
    MetricStatus,
    ScorecardV1,
    aggregate_qualification,
    ratio_metric,
    zero_gate,
)
from scenario_forge.manifest import ArtifactRole, ManifestInventoryResolver
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    InventoryCompleteness,
)
from scenario_forge.models.scenario import ScenarioEnvelope
from scenario_forge.pipeline.persistence import CoveragePlanV2, FinalizationInventoryV1

_TITLE_TOKEN_RE = re.compile(r"[a-z0-9]+")
_NEAR_TITLE_THRESHOLD = 0.6


def _ids(items: list[dict[str, Any]], key: str) -> set[str]:
    return {str(item[key]) for item in items if item.get(key)}


def _tree_leaves(node: dict[str, Any]) -> list[dict[str, Any]]:
    children = node.get("children") or []
    if not children:
        return [node]
    return [leaf for child in children for leaf in _tree_leaves(child)]


def _projected_ids(items: list[dict[str, Any]]) -> set[str]:
    return {
        str(step_id) for item in items for step_id in item.get("projected_step_ids", [])
    }


def _normal_title(value: str) -> str:
    return " ".join(_TITLE_TOKEN_RE.findall(value.casefold()))


def _title_tokens(value: str) -> set[str]:
    return set(_TITLE_TOKEN_RE.findall(value.casefold()))


def _components(nodes: list[str], edges: set[tuple[str, str]]) -> list[list[str]]:
    neighbors = {node: set() for node in nodes}
    for left, right in edges:
        neighbors[left].add(right)
        neighbors[right].add(left)
    result: list[list[str]] = []
    seen: set[str] = set()
    for node in sorted(nodes):
        if node in seen or not neighbors[node]:
            continue
        pending = [node]
        component: list[str] = []
        seen.add(node)
        while pending:
            current = pending.pop()
            component.append(current)
            for neighbor in sorted(neighbors[current], reverse=True):
                if neighbor not in seen:
                    seen.add(neighbor)
                    pending.append(neighbor)
        result.append(sorted(component))
    return sorted(result)


def title_duplicate_components(
    titles: dict[str, str],
) -> tuple[list[list[str]], list[list[str]]]:
    """Return exact-normalized groups and deterministic near-title components."""
    normalized_groups: dict[str, list[str]] = {}
    for scenario_id, title in titles.items():
        normalized_groups.setdefault(_normal_title(title), []).append(scenario_id)
    exact_groups = sorted(
        sorted(group)
        for title, group in normalized_groups.items()
        if title and len(group) > 1
    )
    title_edges: set[tuple[str, str]] = set()
    ids = sorted(titles)
    for index, left in enumerate(ids):
        for right in ids[index + 1 :]:
            left_tokens, right_tokens = (
                _title_tokens(titles[left]),
                _title_tokens(titles[right]),
            )
            union = left_tokens | right_tokens
            similarity = len(left_tokens & right_tokens) / len(union) if union else 0.0
            if similarity >= _NEAR_TITLE_THRESHOLD and _normal_title(
                titles[left]
            ) != _normal_title(titles[right]):
                title_edges.add((left, right))
    return exact_groups, _components(ids, title_edges)


def canonical_entry_point_sets(
    scenarios: list[dict[str, Any]], expected_ids: set[str]
) -> tuple[set[str], set[str]]:
    """Return covered and unknown IDs using only canonical envelope identity."""
    used_ids = {
        str(scenario["initial_entry_point_id"])
        for scenario in scenarios
        if scenario.get("initial_entry_point_id")
    }
    return used_ids & expected_ids, used_ids - expected_ids


def _count_metric(count: int, evidence: list[str], affected: list[str]) -> MetricResult:
    return MetricResult(
        status=MetricStatus.PASS,
        numerator=count,
        evidence=evidence,
        affected_ids=sorted(affected),
    )


def _resolver_orphan_fact(
    resolver: ManifestInventoryResolver, *, evidence: str
) -> MetricResult:
    if not getattr(resolver, "check_orphans", False):
        return MetricResult(
            status=MetricStatus.NOT_APPLICABLE,
            numerator=0,
            evidence=[
                evidence,
                "in-progress resolver does not own final orphan reconciliation",
            ],
            affected_ids=[],
        )
    return zero_gate(0, evidence=[evidence])


def _gate_for_codes(
    codes: set[str],
    failures: dict[str, set[str]],
    *,
    evidence: list[str],
    applicable: bool = True,
) -> MetricResult:
    affected = sorted(set().union(*(failures.get(code, set()) for code in codes)))
    if not applicable:
        return MetricResult(
            status=MetricStatus.NOT_APPLICABLE,
            numerator=len(affected),
            evidence=evidence,
            affected_ids=affected,
        )
    return zero_gate(len(affected), evidence=evidence, affected_ids=affected)


def evaluate_v3_scorecard(resolver: ManifestInventoryResolver) -> ScorecardV1:
    """Compute v1 metrics without discovery, repair, or artifact writes."""
    manifest = resolver.manifest
    if manifest.manifest_version != "3":
        raise ValueError("versioned evaluation requires authoritative manifest v3")

    plan_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
    final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
    profile_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    if plan_entry is None or final_entry is None or profile_entry is None:
        raise ValueError(
            "manifest v3 evaluation requires plan, finalization, and profile"
        )
    plan = CoveragePlanV2.model_validate_json(resolver.read_text(plan_entry))
    final = FinalizationInventoryV1.model_validate_json(resolver.read_text(final_entry))
    profile = CapabilityProfile.model_validate(resolver.read_yaml(profile_entry))

    scenario_items: list[tuple[str, dict[str, Any]]] = []
    schema_errors: list[str] = []
    for entry in resolver.scenario_yaml_entries():
        raw = resolver.read_yaml(entry)
        if not isinstance(raw, dict):
            schema_errors.append(entry.scenario_id or entry.path)
            continue
        scenario_id = entry.scenario_id or entry.path
        scenario_items.append((scenario_id, raw))
        try:
            ScenarioEnvelope.model_validate(raw)
        except ValidationError:
            schema_errors.append(scenario_id)

    feature_entries = resolver.scenario_feature_entries()
    scenario_ids = [scenario_id for scenario_id, _ in scenario_items]
    feature_ids = [entry.scenario_id or entry.path for entry in feature_entries]
    plan_targets = {target.entry_point_id for target in plan.targets}
    covered_targets, unknown_targets = canonical_entry_point_sets(
        [raw for _, raw in scenario_items], plan_targets
    )
    admitted_receipts = [
        receipt
        for receipt in final.admitted_inventory
        if receipt.scenario_id is not None
    ]
    receipt_scenarios = {receipt.scenario_id for receipt in admitted_receipts}
    receipt_pairs = Counter(receipt.scenario_id for receipt in admitted_receipts)
    bad_pairs = sorted(sid for sid, count in receipt_pairs.items() if count != 2)
    evaluated_ids = set(scenario_ids) & set(feature_ids)
    count_mismatch_ids = sorted(
        (set(scenario_ids) ^ set(feature_ids)) | (evaluated_ids ^ receipt_scenarios)
    )

    presence = {
        "manifest_evaluated_count_coherence": ratio_metric(
            len(evaluated_ids & receipt_scenarios),
            len(receipt_scenarios),
            evidence=[
                "manifest YAML/feature inventory",
                "finalization-inventory.json:admitted_inventory",
            ],
            affected_ids=count_mismatch_ids,
        ),
        "manifest_pair_coherence": ratio_metric(
            len(receipt_pairs) - len(bad_pairs),
            len(receipt_pairs),
            evidence=["finalization-inventory.json:admitted_inventory"],
            affected_ids=bad_pairs,
        ),
        "canonical_entry_point_coverage": ratio_metric(
            len(covered_targets),
            len(plan_targets),
            evidence=[
                "coverage-plan.json:targets",
                "admitted scenario initial_entry_point_id",
                f"completeness={plan.completeness}",
            ],
            affected_ids=sorted(plan_targets - covered_targets),
            applicable=plan.completeness == "confirmed_complete",
        ),
        "unknown_entry_point_count": zero_gate(
            len(unknown_targets),
            evidence=["coverage-plan.json:targets", "scenario.initial_entry_point_id"],
            affected_ids=sorted(unknown_targets),
        ),
        "stale_or_orphan_artifact_count": _resolver_orphan_fact(
            resolver, evidence="strict finalized resolver orphan check"
        ),
        "missing_pair_count": zero_gate(
            len(bad_pairs) + len(count_mismatch_ids),
            evidence=[
                "manifest YAML/feature pairing",
                "finalization admitted receipts",
            ],
            affected_ids=sorted(set(bad_pairs) | set(count_mismatch_ids)),
        ),
        "duplicate_or_overwritten_artifact_count": zero_gate(
            0,
            evidence=[
                "strict resolver canonical-path, inode, identity, and hash checks"
            ],
        ),
        "unmanifested_artifact_count": _resolver_orphan_fact(
            resolver, evidence="strict finalized resolver orphan check"
        ),
    }
    failures: dict[str, set[str]] = {}
    diagnostic_failures: dict[str, set[str]] = {}
    for decision in final.admission_decisions:
        destination = failures if decision.violations else diagnostic_failures
        for violation in decision.violations:
            destination.setdefault(violation.code, set()).add(decision.candidate_id)
        for gate in decision.gate_results:
            for violation in gate.violations:
                failures.setdefault(violation.code, set()).add(decision.candidate_id)
            for diagnostic in gate.diagnostics:
                diagnostic_failures.setdefault(diagnostic.code, set()).add(
                    decision.candidate_id
                )

    decision_count = len(final.admission_decisions)
    validity: dict[str, MetricResult] = {
        "scenario_schema_validity": ratio_metric(
            len(scenario_items) - len(schema_errors),
            len(scenario_items),
            evidence=["ScenarioEnvelope schema validation"],
            affected_ids=schema_errors,
        ),
    }
    for code in sorted(set(failures) | set(diagnostic_failures)):
        affected = sorted(
            failures.get(code, set()) | diagnostic_failures.get(code, set())
        )
        validity[f"admission_failure_rate:{code}"] = ratio_metric(
            len(affected),
            decision_count,
            threshold=0.0,
            evidence=[f"finalization-inventory.json:violation_code={code}"],
            affected_ids=affected,
            applicable=False,
        )
    quarantine_reasons: dict[str, set[str]] = {}
    for decision in final.admission_decisions:
        if decision.admitted:
            continue
        for violation in decision.violations:
            quarantine_reasons.setdefault(violation.code, set()).add(
                decision.candidate_id
            )
    for code, affected in sorted(quarantine_reasons.items()):
        validity[f"kill_chain_quarantine_reason:{code}"] = _count_metric(
            len(affected),
            [f"persisted quarantine violation category={code}"],
            sorted(affected),
        )

    admitted_by_candidate = {
        decision.candidate_id: decision
        for decision in final.admission_decisions
        if decision.admitted
    }
    choices = {
        choice.candidate_id: choice
        for target in plan.targets
        for choice in target.ordered_choices
    }
    pinned_total = 0
    pinned_found = 0
    projected_total = 0
    projected_all_found = 0
    tree_behavior_matches = 0
    vacuous_agreement_ids: list[str] = []
    projection_mappings = Counter()
    projection_problem_ids: list[str] = []
    tree_behavior_problem_ids: list[str] = []
    pinned_problem_ids: list[str] = []
    projected_problem_ids: list[str] = []
    titles: dict[str, str] = {}
    structures: dict[str, tuple[str, ...]] = {}

    for scenario_id, raw in scenario_items:
        candidate_id = str(raw.get("candidate_id", ""))
        choice = choices.get(candidate_id)
        tree_ids = _projected_ids(
            _tree_leaves(raw.get("attack_tree", {}).get("root", {}))
        )
        behavior_ids = _projected_ids(raw.get("behavior_spec", {}).get("actions", []))
        narrative_ids = _projected_ids(raw.get("narrative", {}).get("steps", []))
        projection = raw.get("projection", {}).get("projection", {})
        selected = {str(value) for value in projection.get("selected_step_ids", [])}
        projected_total += len(selected)
        common = selected & narrative_ids & tree_ids & behavior_ids
        projected_all_found += len(common)
        if common != selected:
            projected_problem_ids.append(scenario_id)
        if tree_ids == behavior_ids and tree_ids == selected:
            tree_behavior_matches += 1
        else:
            tree_behavior_problem_ids.append(scenario_id)
        pinned = set(choice.pinned_technique_ids) if choice is not None else set()
        tree_techniques = {
            str(leaf["technique_id"])
            for leaf in _tree_leaves(raw.get("attack_tree", {}).get("root", {}))
            if leaf.get("technique_id")
        }
        pinned_total += len(pinned)
        pinned_found += len(pinned & tree_techniques)
        if pinned - tree_techniques:
            pinned_problem_ids.append(scenario_id)
        if not pinned and not tree_techniques:
            vacuous_agreement_ids.append(scenario_id)
        for mapping in raw.get("projection", {}).get("projected_mappings", []):
            decision = mapping.get("mapping", {}).get("decision", "unknown")
            projection_mappings[str(decision)] += 1
        if candidate_id not in admitted_by_candidate:
            projection_problem_ids.append(scenario_id)
        title = str(raw.get("narrative", {}).get("title", ""))
        titles[scenario_id] = title
        structures[scenario_id] = tuple(sorted(selected))

    agreement = {
        "pinned_technique_recall": ratio_metric(
            pinned_found,
            pinned_total,
            evidence=[
                "coverage-plan pinned_technique_ids",
                "admitted attack-tree technique_id",
            ],
            affected_ids=pinned_problem_ids,
        ),
        "projected_step_recall": ratio_metric(
            projected_all_found,
            projected_total,
            evidence=[
                "persisted projection selected_step_ids",
                "artifact projected_step_ids",
            ],
            affected_ids=projected_problem_ids,
        ),
        "exact_tree_behavior_correspondence": ratio_metric(
            len(scenario_items) - len(tree_behavior_problem_ids),
            len(scenario_items),
            evidence=[
                "attack-tree leaves",
                "structured behavior actions",
                "projection",
            ],
            affected_ids=tree_behavior_problem_ids,
        ),
        "vacuous_agreement_count": _count_metric(
            len(vacuous_agreement_ids),
            ["empty pinned and attack-tree technique sets are not agreement"],
            vacuous_agreement_ids,
        ),
        "projection_conditional_decision_coverage": ratio_metric(
            projected_all_found,
            projected_total,
            evidence=[
                "selected canonical projected steps, including conditional steps"
            ],
            affected_ids=projected_problem_ids,
        ),
        "projection_mapping_coverage": ratio_metric(
            projection_mappings["exact"],
            sum(projection_mappings.values()),
            evidence=["projection.projected_mappings mapping decisions"],
            affected_ids=projection_problem_ids,
        ),
    }
    for decision, count in sorted(projection_mappings.items()):
        agreement[f"projection_mapping_status:{decision}"] = ratio_metric(
            count,
            sum(projection_mappings.values()),
            threshold=0.0,
            evidence=["projection.projected_mappings"],
            applicable=False,
        )

    exact_groups, title_components = title_duplicate_components(titles)
    exact_affected = sorted({sid for group in exact_groups for sid in group})
    structural_edges: set[tuple[str, str]] = set()
    ids = sorted(titles)
    for index, left in enumerate(ids):
        for right in ids[index + 1 :]:
            if structures[left] and structures[left] == structures[right]:
                structural_edges.add((left, right))
    structural_components = _components(ids, structural_edges)
    near_affected = sorted({sid for group in title_components for sid in group})
    structural_affected = sorted(
        {sid for group in structural_components for sid in group}
    )
    diagnostics = {
        "exact_normalized_title_duplicate_count": zero_gate(
            len(exact_groups),
            evidence=[f"normalized duplicate groups={exact_groups}"],
            affected_ids=exact_affected,
        ),
        "near_duplicate_title_component_count": _count_metric(
            len(title_components),
            [
                f"deterministic Jaccard threshold={_NEAR_TITLE_THRESHOLD}",
                f"components={title_components}",
            ],
            near_affected,
        ),
        "near_duplicate_title_affected_rate": ratio_metric(
            len(near_affected),
            len(ids),
            threshold=0.0,
            evidence=[f"components={title_components}"],
            affected_ids=near_affected,
            applicable=False,
        ),
        "structural_graph_component_count": _count_metric(
            len(structural_components),
            [
                f"exact selected-step structural signatures; components={structural_components}"
            ],
            structural_affected,
        ),
        "structural_graph_affected_rate": ratio_metric(
            len(structural_affected),
            len(ids),
            threshold=0.0,
            evidence=[f"components={structural_components}"],
            affected_ids=structural_affected,
            applicable=False,
        ),
    }

    confirmed_entry_points = (
        profile.entry_point_completeness
        is InventoryCompleteness.operator_confirmed_complete
    )
    confirmed_tools = (
        profile.tool_inventory_completeness
        is InventoryCompleteness.operator_confirmed_complete
    )
    quarantine_ids = sorted(
        receipt.candidate_id for receipt in final.quarantine_inventory
    )
    release = {
        "zero_quarantine": zero_gate(
            len(quarantine_ids),
            evidence=["finalization-inventory.json:quarantine_inventory"],
            affected_ids=quarantine_ids,
        ),
        "actor_attack_complexity": _gate_for_codes(
            {"actor_access", "capability_complexity"},
            failures,
            evidence=["persisted cmps.5 admission violations"],
        ),
        "capability_grounding": _gate_for_codes(
            {"phantom"},
            failures,
            evidence=[
                f"entry_point_completeness={profile.entry_point_completeness.value}"
            ],
            applicable=confirmed_entry_points,
        ),
        "tool_integration_grounding": _gate_for_codes(
            {"phantom"},
            failures,
            evidence=[
                f"tool_inventory_completeness={profile.tool_inventory_completeness.value}"
            ],
            applicable=confirmed_tools,
        ),
        "data_access_grounding": _gate_for_codes(
            {"actor_access", "narrative_access", "trusted_context"},
            failures,
            evidence=["persisted actor/access/trusted-context admission evidence"],
            applicable=confirmed_entry_points,
        ),
        "catalog_taxonomy_pin_validity": _gate_for_codes(
            {"trusted_context", "candidate_identity"},
            failures,
            evidence=[
                "persisted trusted-context and candidate-identity admission evidence"
            ],
        ),
        "resource_binding_validity": _gate_for_codes(
            {"traceability", "canonical_identity"},
            failures,
            evidence=["persisted projection traceability admission evidence"],
        ),
        "execution_requirement_drift": _gate_for_codes(
            {"traceability"},
            failures,
            evidence=["persisted projection traceability admission evidence"],
        ),
        "zero_schema_identifier_phantom_parsimony_failures": _gate_for_codes(
            {
                "structural",
                "semantic",
                "scenario_identity",
                "canonical_identity",
                "phantom",
                "parsimony",
            },
            failures,
            evidence=["persisted cmps.5 admission violations"],
        ),
        "kill_chain_quarantine_reasons": zero_gate(
            len(quarantine_ids),
            evidence=[
                "quarantine IDs; reason categories remain in persisted admission decisions/bundles"
            ],
            affected_ids=quarantine_ids,
        ),
    }
    qualification_gates = {
        "inventory_count_coherence": presence["manifest_evaluated_count_coherence"],
        "inventory_pair_coherence": presence["manifest_pair_coherence"],
        "scenario_schema_validity": validity["scenario_schema_validity"],
        "known_entry_point_identity": presence["unknown_entry_point_count"],
        "zero_stale_orphan": presence["stale_or_orphan_artifact_count"],
        "zero_missing_pairs": presence["missing_pair_count"],
        "zero_duplicate_overwritten": presence[
            "duplicate_or_overwritten_artifact_count"
        ],
        "zero_unmanifested": presence["unmanifested_artifact_count"],
        "projected_step_recall": agreement["projected_step_recall"],
        "pinned_technique_recall": agreement["pinned_technique_recall"],
        "tree_behavior_correspondence": agreement["exact_tree_behavior_correspondence"],
        "exact_title_duplicates": diagnostics["exact_normalized_title_duplicate_count"],
        **release,
    }
    return ScorecardV1(
        run_id=manifest.run_id,
        scenario_count=len(scenario_items),
        feature_file_count=len(feature_ids),
        presence_coverage=MetricSection(metrics=presence),
        validity_grounding=MetricSection(metrics=validity),
        cross_artifact_agreement=MetricSection(metrics=agreement),
        semantic_quality_diagnostics=MetricSection(metrics=diagnostics),
        release_qualification=MetricSection(metrics=release),
        qualification=aggregate_qualification(qualification_gates),
    )
