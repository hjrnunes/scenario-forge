"""Coverage analysis for Stage 4 (deterministic, no LLM calls).

Computes a three-way partition of ICA slots:
- **Structural coverage** — total / non-N/A / N/A / coverage rate
- **By ICA type** — count of non-N/A ICAs per UCA type
- **By controller** — count of non-N/A ICAs per responsibility / coordination link
- **Catalog correspondence** — mapped vs unmapped vs catalog-only

Also computes two slot-level eval metrics:
- **Structural consideration** — fraction of slots considered
- **N/A quality** — fraction of N/A justifications citing a structural property
"""

from __future__ import annotations

from scenario_forge.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    StructuralThreat,
)
from scenario_forge.stpa.models.ica_enumeration import ICASlot, UCAType

from .catalog_data import OWASP_AGENTIC_THREAT_IDS
from .na_quality import check_structural_keywords

__all__ = [
    "compute_coverage",
    "metric_structural_consideration",
    "metric_na_quality",
]


def compute_coverage(
    slots: list[ICASlot],
    structural_threats: list[StructuralThreat],
    na_reconciliation_flags: list[str] | None = None,
) -> CoverageAnalysis:
    """Compute coverage analysis from slots and enriched threats.

    Args:
        slots: All ICA slots (responsibility + coordination link).
        structural_threats: Enriched structural threats (non-N/A ICAs).
        na_reconciliation_flags: Flags from N/A reconciliation.

    Returns:
        A :class:`CoverageAnalysis` with all partitions and metrics.
    """
    total_slots = len(slots)
    na_count = sum(1 for s in slots if s.is_na)
    non_na_count = total_slots - na_count

    structural_coverage = {
        "total_slots": total_slots,
        "non_na": non_na_count,
        "na": na_count,
        "coverage_rate": non_na_count / total_slots if total_slots else 0.0,
    }

    by_ica_type = _partition_by_ica_type(slots)
    by_controller = _partition_by_controller(slots)

    catalog_correspondence = _compute_catalog_correspondence(structural_threats)

    uncovered_owasp_threats, uncovered_reason = _compute_uncovered_owasp(
        structural_threats
    )

    structural_consideration = metric_structural_consideration(slots)
    na_quality = metric_na_quality(slots)

    return CoverageAnalysis(
        structural_coverage=structural_coverage,
        by_ica_type=by_ica_type,
        by_controller=by_controller,
        catalog_correspondence=catalog_correspondence,
        na_reconciliation_flags=na_reconciliation_flags or [],
        uncovered_owasp_threats=uncovered_owasp_threats,
        uncovered_reason=uncovered_reason,
        structural_consideration=structural_consideration,
        na_quality=na_quality,
    )


def _partition_by_ica_type(slots: list[ICASlot]) -> dict[str, int]:
    """Count non-N/A ICAs per UCA type."""
    counts: dict[str, int] = {}
    for uca_type in UCAType:
        counts[uca_type.value] = 0
    for slot in slots:
        if slot.is_na:
            continue
        ica_count = len(slot.icas)
        counts[slot.uca_type.value] = counts.get(slot.uca_type.value, 0) + ica_count
    return counts


def _partition_by_controller(slots: list[ICASlot]) -> dict[str, int]:
    """Count non-N/A ICAs per controller (responsibility or coordination link)."""
    counts: dict[str, int] = {}
    for slot in slots:
        if slot.is_na:
            continue
        controller = slot.responsibility or slot.coordination_link or "UNKNOWN"
        ica_count = len(slot.icas)
        counts[controller] = counts.get(controller, 0) + ica_count
    return counts


def _compute_catalog_correspondence(
    structural_threats: list[StructuralThreat],
) -> dict[str, int]:
    """Compute catalog correspondence: mapped vs unmapped vs catalog-only."""
    with_match = sum(1 for t in structural_threats if t.catalog_mappings)
    unmapped = sum(1 for t in structural_threats if not t.catalog_mappings)
    return {
        "structural_with_match": with_match,
        "structural_unmapped": unmapped,
        "catalog_only_supplements": 0,
    }


def _compute_uncovered_owasp(
    structural_threats: list[StructuralThreat],
) -> tuple[list[str], str | None]:
    """Find OWASP Agentic threats with no structural or catalog correspondent."""
    covered_ids = _collect_covered_owasp_ids(structural_threats)
    uncovered = [tid for tid in OWASP_AGENTIC_THREAT_IDS if tid not in covered_ids]

    if not uncovered:
        return [], None
    return uncovered, "No structural slot matched these OWASP agentic threats"


def _collect_covered_owasp_ids(
    structural_threats: list[StructuralThreat],
) -> set[str]:
    """Collect all OWASP Agentic threat IDs covered by structural threats."""
    covered_ids: set[str] = set()
    for threat in structural_threats:
        for mapping in threat.catalog_mappings:
            if mapping.catalog == "OWASP_AGENTIC":
                covered_ids.add(mapping.id)
    return covered_ids


def _is_slot_considered(slot: ICASlot) -> bool:
    """Return True if a slot has ICAs or a justified N/A."""
    return bool(slot.icas) or (
        slot.is_na and check_structural_keywords(slot.na_justification)
    )


def metric_structural_consideration(slots: list[ICASlot]) -> dict:
    """Compute what fraction of slots were considered.

    A slot is "considered" if it has either ICAs or a justified N/A.

    Args:
        slots: All ICA slots.

    Returns:
        A dict with ``total_slots``, ``considered``, ``rate``,
        ``by_ica_type``, and ``by_responsibility``.
    """
    total = len(slots)
    considered = sum(1 for s in slots if _is_slot_considered(s))
    return {
        "total_slots": total,
        "considered": considered,
        "rate": considered / total if total else 0.0,
        "by_ica_type": _breakdown_by_type(slots, _is_slot_considered),
        "by_responsibility": _breakdown_by_resp(slots, _is_slot_considered),
    }


def metric_na_quality(slots: list[ICASlot]) -> dict:
    """Compute fraction of N/A justifications citing a structural property.

    Args:
        slots: All ICA slots.

    Returns:
        A dict with ``na_count``, ``quality_count``, and ``quality_rate``.
        If there are no N/A slots, ``quality_rate`` is ``None``.
    """
    na_slots = [s for s in slots if s.is_na]
    if not na_slots:
        return {"na_count": 0, "quality_rate": None}
    quality_count = sum(
        1 for s in na_slots if check_structural_keywords(s.na_justification)
    )
    return {
        "na_count": len(na_slots),
        "quality_count": quality_count,
        "quality_rate": quality_count / len(na_slots),
    }


def _breakdown_by_type(
    slots: list[ICASlot], predicate,
) -> dict[str, int]:
    """Break down considered slots by ICA type."""
    counts: dict[str, int] = {}
    for uca_type in UCAType:
        counts[uca_type.value] = 0
    for slot in slots:
        if predicate(slot):
            counts[slot.uca_type.value] = counts.get(slot.uca_type.value, 0) + 1
    return counts


def _breakdown_by_resp(
    slots: list[ICASlot], predicate,
) -> dict[str, int]:
    """Break down considered slots by responsibility."""
    counts: dict[str, int] = {}
    for slot in slots:
        if not predicate(slot):
            continue
        controller = slot.responsibility or slot.coordination_link or "UNKNOWN"
        counts[controller] = counts.get(controller, 0) + 1
    return counts


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T00:32:43Z","module_hash":"0c6136095420220c7c3f51ed3a1b416608e2ff26cd67c1a8aee266cc14edcf3f","functions":[{"id":"func/compute_coverage","name":"compute_coverage","line":32,"end_line":80,"hash":"d42cc3ac007cc5e4a2d8cbd8cc9d32f5cb5092f882bad6b18688ca33f4e03895"},{"id":"func/_partition_by_ica_type","name":"_partition_by_ica_type","line":83,"end_line":93,"hash":"e7918b4c87e876a4bcd592ce2e9425714072c9e220f4d8ad51e4642d664ce2e9"},{"id":"func/_partition_by_controller","name":"_partition_by_controller","line":96,"end_line":105,"hash":"8060ae97a9c8f928f0f4f86c8d5187a61e0157220131bd85317d4bbe5adb84c3"},{"id":"func/_compute_catalog_correspondence","name":"_compute_catalog_correspondence","line":108,"end_line":118,"hash":"af7c3cf1055eb93fd50d69d07adf5de86aa9b681e1c13b1fa7f47ee5353dff91"},{"id":"func/_compute_uncovered_owasp","name":"_compute_uncovered_owasp","line":121,"end_line":130,"hash":"5b6e00b55b87e0b7343ebdf63a03b14eb79866f3cd9bea9c123c9d15c29939ae"},{"id":"func/_collect_covered_owasp_ids","name":"_collect_covered_owasp_ids","line":133,"end_line":142,"hash":"76177dd6a4370ba8a1dc0f3c782b5befc93c84666a0b1f3c861cfc072d401c45"},{"id":"func/_is_slot_considered","name":"_is_slot_considered","line":145,"end_line":149,"hash":"05cc9d315bc3d8ea60ad8ccbb85fadab8a74d3a218d5393b51bb8d0fee4822c9"},{"id":"func/metric_structural_consideration","name":"metric_structural_consideration","line":152,"end_line":172,"hash":"80a6743e42bcd4b282a095bf7b88c24b3b629c54b2d0bb25cdf95ce5584ac2ef"},{"id":"func/metric_na_quality","name":"metric_na_quality","line":175,"end_line":195,"hash":"42eb0287c76fd6cbed26f0a034023353cc40323d5604ec1b69655ed1e532c76e"},{"id":"func/_breakdown_by_type","name":"_breakdown_by_type","line":198,"end_line":208,"hash":"7789b26e618de9d4355b46ea819d64e979294cfc4c8f8e70ba11d47e48b2841b"},{"id":"func/_breakdown_by_resp","name":"_breakdown_by_resp","line":211,"end_line":221,"hash":"b1b06c0ea13f16483290f2f90db25e052e566dcd66d0d2d5e32698a06ba59974"}]}
# mutate4py-manifest-end
