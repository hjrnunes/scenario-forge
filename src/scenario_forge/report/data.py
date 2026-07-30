"""ReportData — typed container for all report inputs, and a loader from disk.

In cmps.1, ``load_report_data`` consumes **strict manifest inventory** entries
rather than globbing the filesystem.  Paths, hashes, and roles are verified by
the shared :class:`ManifestInventoryResolver`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from scenario_forge.manifest import (
    ArtifactRole,
    find_run_dir,
    load_manifest,
    load_strict_resolver,
)

logger = logging.getLogger(__name__)


@dataclass
class ReportData:
    """All inputs needed by :func:`generate_report`.

    Each field corresponds to a pipeline artifact that was previously read
    inline inside the report generator.  By collecting them here the
    generator becomes a pure data-to-HTML function with no filesystem I/O.
    """

    profile_data: dict = field(default_factory=dict)
    threat_surface_data: dict = field(default_factory=dict)
    scenarios: list[dict] = field(default_factory=list)
    feature_files: dict[str, str] = field(default_factory=dict)
    call_logs: dict[str, list[dict]] = field(default_factory=dict)
    pipeline_call_logs: list[dict] = field(default_factory=list)
    coverage_data: dict = field(default_factory=dict)
    scorecard_data: dict = field(default_factory=dict)
    manifest_data: dict = field(default_factory=dict)
    use_case_text: str = ""
    raw_files: dict[str, str] = field(default_factory=dict)


def load_report_data(run_dir: Path, require_final: bool = True) -> ReportData:
    """Read all pipeline artifacts from *run_dir* into a :class:`ReportData`.

    In cmps.1, *run_dir* must be a run directory containing a manifest.
    If a collection directory is passed with exactly one run, that run
    is used; multiple runs raise (ambiguous).  All artifacts are loaded
    strictly from manifest inventory entries — stale sibling files
    cannot affect results.

    Args:
        run_dir: Path to a run directory (or collection with one run).
        require_final: If True (default, standalone), require a finalized
            manifest.  If False (in-pipeline), accept ``started`` manifests.

    Missing inventory entries are tolerated (with warnings); the returned
    object will have empty defaults for any artifact not in the manifest.
    """
    actual_run_dir = find_run_dir(run_dir)
    resolver = load_strict_resolver(actual_run_dir, require_final=require_final)

    profile_data: dict = {}
    threat_surface_data: dict = {}
    scenarios: list[dict] = []
    feature_files: dict[str, str] = {}
    raw_files: dict[str, str] = {}
    call_logs: dict[str, list[dict]] = {}
    pipeline_call_logs: list[dict] = []
    coverage_data: dict = {}
    scorecard_data: dict = {}
    manifest_data: dict = {}
    use_case_text: str = ""

    # --- Capability profile ---
    cap_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    if cap_entry is not None:
        text = resolver.read_text(cap_entry)
        profile_data = yaml.safe_load(text) or {}
        raw_files["capability-profile.yaml"] = text
        logger.info("Loaded capability profile from manifest inventory")
    else:
        logger.warning("capability-profile not in manifest inventory")

    # --- Threat surface ---
    ts_entry = resolver.entry_by_role(ArtifactRole.THREAT_SURFACE)
    if ts_entry is not None:
        text = resolver.read_text(ts_entry)
        threat_surface_data = yaml.safe_load(text) or {}
        raw_files["threat-surface.yaml"] = text
        logger.info("Loaded threat surface from manifest inventory")
    else:
        logger.warning("threat-surface not in manifest inventory")

    # --- Scenarios and feature files ---
    for entry in resolver.scenario_yaml_entries():
        text = resolver.read_text(entry)
        data = yaml.safe_load(text)
        if data and isinstance(data, dict):
            scenarios.append(data)
            raw_files[f"scenarios/{Path(entry.path).name}"] = text
            logger.info("Loaded scenario %s", Path(entry.path).name)

    for entry in resolver.scenario_feature_entries():
        content = resolver.read_text(entry)
        scenario_id = entry.scenario_id or Path(entry.path).stem
        feature_files[scenario_id] = content
        raw_files[f"scenarios/{Path(entry.path).name}"] = content

    logger.info(
        "Loaded %d scenarios, %d feature files",
        len(scenarios),
        len(feature_files),
    )

    # --- Scenario LLM call logs ---
    calls_entry = resolver.entry_by_role(ArtifactRole.SCENARIO_CALL_LOG)
    if calls_entry is not None:
        try:
            for line in resolver.read_text(calls_entry).strip().splitlines():
                entry_dict = json.loads(line)
                sid = entry_dict.get("scenario_id", "")
                call_logs.setdefault(sid, []).append(entry_dict)
            logger.info(
                "Loaded %d call log entries from manifest inventory",
                sum(len(v) for v in call_logs.values()),
            )
        except Exception as exc:
            logger.warning("Failed to load scenario call log: %s", exc)

    # --- Pipeline (non-scenario) LLM call logs ---
    pipeline_calls_entry = resolver.entry_by_role(ArtifactRole.PIPELINE_CALL_LOG)
    if pipeline_calls_entry is not None:
        try:
            for line in resolver.read_text(pipeline_calls_entry).strip().splitlines():
                pipeline_call_logs.append(json.loads(line))
            logger.info(
                "Loaded %d pipeline call log entries from manifest inventory",
                len(pipeline_call_logs),
            )
        except Exception as exc:
            logger.warning("Failed to load pipeline call log: %s", exc)

    # --- Coverage gaps ---
    coverage_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_REPORT)
    if coverage_entry is not None:
        try:
            text = resolver.read_text(coverage_entry)
            coverage_data = json.loads(text) or {}
            raw_files["coverage-gaps.json"] = text
            logger.info("Loaded coverage gaps from manifest inventory")
        except Exception as exc:
            logger.warning("Failed to load coverage report: %s", exc)

    # --- Eval scorecard ---
    scorecard_entry = resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD)
    if scorecard_entry is not None:
        try:
            text = resolver.read_text(scorecard_entry)
            scorecard_data = yaml.safe_load(text) or {}
            raw_files["eval-scorecard.yaml"] = text
            logger.info("Loaded eval scorecard from manifest inventory")
        except Exception as exc:
            logger.warning("Failed to load eval scorecard: %s", exc)

    # --- Run manifest ---
    manifest_data = load_manifest(actual_run_dir).model_dump(mode="json")
    logger.info("Loaded run manifest")

    # --- Use case description ---
    uc_entry = resolver.entry_by_role(ArtifactRole.USE_CASE)
    if uc_entry is not None:
        use_case_text = resolver.read_text(uc_entry)
        logger.info("Loaded use case description from manifest inventory")

    return ReportData(
        profile_data=profile_data,
        threat_surface_data=threat_surface_data,
        scenarios=scenarios,
        feature_files=feature_files,
        call_logs=call_logs,
        pipeline_call_logs=pipeline_call_logs,
        coverage_data=coverage_data,
        scorecard_data=scorecard_data,
        manifest_data=manifest_data,
        use_case_text=use_case_text,
        raw_files=raw_files,
    )
