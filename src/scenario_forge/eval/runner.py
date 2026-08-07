"""Strict manifest-v3 evaluation entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scenario_forge.eval.versioned_metrics import evaluate_v3_scorecard
from scenario_forge.manifest import (
    MANIFEST_V3,
    ManifestInventoryResolver,
    find_run_dir,
    load_strict_resolver,
)


def run_evaluation(
    run_dir: Path | None = None,
    *,
    resolver: ManifestInventoryResolver | None = None,
    threats_path: Path | None = None,
    allow_non_authoritative: bool = False,
) -> dict[str, Any]:
    """Produce the strict, typed scorecard from admitted v3 inventory.

    Args:
        run_dir: Path to a run directory (or collection with one run).
            Used for **standalone** evaluation.  The manifest must be
            authoritative (``completed``) unless *allow_non_authoritative*
            is set.
        resolver: Pre-built in-memory resolver for **internal** pipeline
            use.  When provided, *run_dir* is ignored.
        threats_path: Retained CLI argument; v1 metrics use persisted admission
            evidence and do not reinterpret taxonomy authority.
        allow_non_authoritative: When True (standalone only), accept
            a finalized v3 manifest for explicit read-only forensics. It does
            not enable legacy manifests or automatic fallback.

    Returns:
        Structured scorecard dict ready for YAML/JSON serialization.
    """
    del threats_path
    if resolver is None:
        actual_run_dir = find_run_dir(run_dir)
        resolver = load_strict_resolver(
            actual_run_dir,
            require_final=True,
            require_authoritative=not allow_non_authoritative,
            manifest_version=MANIFEST_V3,
        )
    scorecard = evaluate_v3_scorecard(resolver)
    return scorecard.model_dump(mode="json")
