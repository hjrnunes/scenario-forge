"""Stage 7 — Coverage gap analysis.

Aggregates the three-way partition from SP2's Stage 4 with end-to-end
coverage: orphan detection, traceability errors, and N/A reconciliation
flags.
"""

from __future__ import annotations

import json
from pathlib import Path

from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope

from .validators import (
    TraceabilityError,
    detect_orphan_elements,
    detect_orphan_icas,
    validate_traceability,
)

__all__ = [
    "compute_coverage_gaps",
    "write_coverage_gaps",
]


def compute_coverage_gaps(
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    scenarios: list[ScenarioEnvelope],
    loss_analysis: LossAnalysis,
    *,
    precomputed_trace_errors: list[TraceabilityError] | None = None,
) -> dict:
    """Compute coverage gap analysis.

    Aggregates the three-way partition from SP2 with end-to-end coverage:
    orphan elements, orphan ICAs, traceability errors, and N/A reconciliation
    flags.

    Args:
        enriched_threat_set: The enriched threat set.
        control_structure: The control structure.
        scenarios: The produced scenario envelopes.
        loss_analysis: The loss analysis.
        precomputed_trace_errors: If provided, use these traceability
            errors instead of re-running :func:`validate_traceability`.

    Returns:
        A dict with ``structural_coverage``, ``by_ica_type``,
        ``by_controller``, ``catalog_correspondence``,
        ``uncovered_owasp_threats``, ``uncovered_reason``,
        ``orphan_elements``, ``orphan_icas``,
        ``na_reconciliation_flags``, and ``traceability_errors``.
    """
    ca = enriched_threat_set.coverage_analysis

    orphan_elements = detect_orphan_elements(control_structure, enriched_threat_set)
    orphan_icas = detect_orphan_icas(enriched_threat_set, scenarios)

    trace_errors = (
        precomputed_trace_errors
        if precomputed_trace_errors is not None
        else validate_traceability(
            scenarios, enriched_threat_set, control_structure, loss_analysis
        )
    )
    traceability_errors = [
        f"{e.scenario_id}: broken {e.broken_link} link (expected {e.expected}, "
        f"got {e.actual})"
        for e in trace_errors
    ]

    return {
        "structural_coverage": ca.structural_coverage,
        "by_ica_type": ca.by_ica_type,
        "by_controller": ca.by_controller,
        "catalog_correspondence": ca.catalog_correspondence,
        "uncovered_owasp_threats": ca.uncovered_owasp_threats,
        "uncovered_reason": ca.uncovered_reason,
        "orphan_elements": orphan_elements,
        "orphan_icas": orphan_icas,
        "na_reconciliation_flags": ca.na_reconciliation_flags,
        "traceability_errors": traceability_errors,
    }


def write_coverage_gaps(coverage_gaps: dict, run_dir: Path) -> Path:
    """Write coverage gaps to ``coverage-gaps.json``.

    Args:
        coverage_gaps: The coverage gaps dict.
        run_dir: Directory to write to.

    Returns:
        The path to the written file.
    """
    path = run_dir / "coverage-gaps.json"
    path.write_text(
        json.dumps(coverage_gaps, indent=2, default=str),
        encoding="utf-8",
    )
    return path


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T14:15:36Z","module_hash":"c76b7872676f2396943e52e98c317b55e908801c3cb866b9afeccfc6eb389375","functions":[{"id":"func/compute_coverage_gaps","name":"compute_coverage_gaps","line":31,"end_line":89,"hash":"a6444db31a68cead8c994eecbd641661384d88d157176faaf1da1fe5d7f0a314"},{"id":"func/write_coverage_gaps","name":"write_coverage_gaps","line":92,"end_line":107,"hash":"8ed670ecac10f9c93e7bb9a28365f55b1776f3f94dd22f6c1a8a79ff8aad925b"}]}
# mutate4py-manifest-end
