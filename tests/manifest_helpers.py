"""Shared helpers for building manifest-backed run directories in tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from scenario_forge.manifest import (
    ArtifactEntry,
    ArtifactRole,
    RunManifest,
    RunStatus,
    atomic_write_yaml,
    build_artifact_entry,
    MANIFEST_FILENAME,
)


def build_test_run_dir(
    run_dir: Path,
    *,
    profile_data: dict | None = None,
    threat_surface_data: dict | None = None,
    scenarios: list[dict[str, Any]] | None = None,
    feature_files: dict[str, str] | None = None,
    use_case: str | None = None,
    pipeline_calls: list[dict] | None = None,
    scenario_calls: list[dict] | None = None,
    coverage_data: dict | None = None,
    eval_scorecard: dict | None = None,
    status: RunStatus = RunStatus.COMPLETED,
) -> Path:
    """Build a run directory with artifacts and a finalized manifest.

    Writes the specified artifacts to *run_dir*, constructs a typed
    inventory with SHA-256 hashes, and writes a manifest with the given
    status.  Only artifacts that are provided (non-None) are written
    and inventoried.

    Returns the *run_dir* path.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    inventory: list[ArtifactEntry] = []

    def _write_and_inventory(
        role: ArtifactRole,
        rel_path: str,
        content: str,
        scenario_id: str | None = None,
        candidate_id: str | None = None,
    ) -> None:
        full = run_dir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        inventory.append(
            build_artifact_entry(
                role=role,
                run_dir=run_dir,
                rel_path=rel_path,
                scenario_id=scenario_id,
                candidate_id=candidate_id,
            )
        )

    if use_case is not None:
        _write_and_inventory(ArtifactRole.USE_CASE, "use-case.txt", use_case)

    if profile_data is not None:
        _write_and_inventory(
            ArtifactRole.CAPABILITY_PROFILE,
            "capability-profile.yaml",
            yaml.dump(profile_data, default_flow_style=False),
        )

    if threat_surface_data is not None:
        _write_and_inventory(
            ArtifactRole.THREAT_SURFACE,
            "threat-surface.yaml",
            yaml.dump(threat_surface_data, default_flow_style=False),
        )

    if scenarios:
        for i, sc in enumerate(scenarios):
            sid = sc.get("scenario_id", "scenario-unknown")
            cid = sc.get("candidate_id", f"cand:v1:{i + 1:032d}")
            # Ensure the serialized YAML includes candidate_id so it
            # matches the inventory entry (strict validation requires
            # serialized scenario_id AND candidate_id in every YAML).
            if "candidate_id" not in sc:
                sc = dict(sc)  # shallow copy to avoid mutating caller
                sc["candidate_id"] = cid
            _write_and_inventory(
                ArtifactRole.SCENARIO_YAML,
                f"scenarios/{sid}.yaml",
                yaml.dump(sc, default_flow_style=False),
                scenario_id=sid,
                candidate_id=cid,
            )
            # Strict manifest requires paired YAML/feature for every scenario.
            feature_content = (feature_files or {}).get(
                sid, f"Feature: {sid}\n  Scenario: {sid}\n"
            )
            _write_and_inventory(
                ArtifactRole.SCENARIO_FEATURE,
                f"scenarios/{sid}.feature",
                feature_content,
                scenario_id=sid,
                candidate_id=cid,
            )

    if pipeline_calls:
        lines = "\n".join(json_line(c) for c in pipeline_calls)
        _write_and_inventory(
            ArtifactRole.PIPELINE_CALL_LOG,
            "calls.jsonl",
            lines + "\n" if lines else "",
        )

    if scenario_calls:
        lines = "\n".join(json_line(c) for c in scenario_calls)
        _write_and_inventory(
            ArtifactRole.SCENARIO_CALL_LOG,
            "scenarios/calls.jsonl",
            lines + "\n" if lines else "",
        )

    if coverage_data is not None:
        import json

        _write_and_inventory(
            ArtifactRole.COVERAGE_REPORT,
            "coverage-gaps.json",
            json.dumps(coverage_data),
        )

    if eval_scorecard is not None:
        _write_and_inventory(
            ArtifactRole.EVAL_SCORECARD,
            "eval-scorecard.yaml",
            yaml.dump(eval_scorecard, default_flow_style=False),
        )

    # Write pipeline.log so orphan check passes
    log_path = run_dir / "pipeline.log"
    log_path.write_text("test log\n", encoding="utf-8")
    inventory.append(
        build_artifact_entry(
            role=ArtifactRole.PIPELINE_LOG,
            run_dir=run_dir,
            rel_path="pipeline.log",
        )
    )

    # Write report.html so orphan check passes
    report_path = run_dir / "report.html"
    report_path.write_text("<html>test</html>", encoding="utf-8")
    inventory.append(
        build_artifact_entry(
            role=ArtifactRole.REPORT,
            run_dir=run_dir,
            rel_path="report.html",
        )
    )

    # Build and write manifest (manifest container is NOT an artifact entry)
    manifest = RunManifest(
        status=status,
        run_id="20260101T000000_abcdef0123456789abcdef0123456789",
        timestamp_start="2026-01-01T00:00:00+00:00",
        timestamp_end="2026-01-01T00:01:00+00:00",
        inventory=inventory,
    )
    data = manifest.model_dump(mode="json", exclude_none=True)
    atomic_write_yaml(run_dir / MANIFEST_FILENAME, data)

    return run_dir


def json_line(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False)
