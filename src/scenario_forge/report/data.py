"""ReportData — typed container for all report inputs, and a loader from disk."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

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


def load_report_data(output_dir: Path) -> ReportData:
    """Read all pipeline artifacts from *output_dir* into a :class:`ReportData`.

    Missing files are tolerated (with warnings); the returned object will
    have empty defaults for any artifact not found on disk.
    """
    output_dir = Path(output_dir)

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

    # --- Check eval scorecard staleness ---
    _scorecard_path = output_dir / "eval-scorecard.yaml"
    _scenarios_dir = output_dir / "scenarios"
    if not _scorecard_path.exists():
        logger.warning(
            "No eval scorecard found in %s. Run "
            "'scenario-forge eval --output-dir %s' before generating "
            "the report to embed quality metrics.",
            output_dir,
            output_dir,
        )
    elif _scenarios_dir.is_dir():
        scenario_yamls = list(_scenarios_dir.glob("*.yaml"))
        if scenario_yamls:
            newest_scenario = max(f.stat().st_mtime for f in scenario_yamls)
            if _scorecard_path.stat().st_mtime < newest_scenario:
                logger.warning(
                    "Eval scorecard is older than scenario files. Re-run "
                    "'scenario-forge eval --output-dir %s' to refresh.",
                    output_dir,
                )

    # --- Capability profile ---
    profile_path = output_dir / "capability-profile.yaml"
    if profile_path.exists():
        profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
        raw_files["capability-profile.yaml"] = profile_path.read_text(encoding="utf-8")
        logger.info("Loaded capability profile from %s", profile_path)
    else:
        logger.warning("capability-profile.yaml not found in %s", output_dir)

    # --- Threat surface ---
    ts_path = output_dir / "threat-surface.yaml"
    if ts_path.exists():
        threat_surface_data = yaml.safe_load(ts_path.read_text(encoding="utf-8")) or {}
        raw_files["threat-surface.yaml"] = ts_path.read_text(encoding="utf-8")
        logger.info("Loaded threat surface from %s", ts_path)
    else:
        logger.warning("threat-surface.yaml not found in %s", output_dir)

    # --- Scenarios and feature files ---
    scenarios_dir = output_dir / "scenarios"
    if scenarios_dir.is_dir():
        for yaml_file in sorted(scenarios_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if data and isinstance(data, dict):
                    scenarios.append(data)
                    raw_files[f"scenarios/{yaml_file.name}"] = yaml_file.read_text(
                        encoding="utf-8"
                    )
                    logger.info("Loaded scenario %s", yaml_file.name)
            except Exception as exc:
                logger.warning("Failed to load %s: %s", yaml_file, exc)

        for feature_file in sorted(scenarios_dir.glob("*.feature")):
            content = feature_file.read_text(encoding="utf-8")
            scenario_id = feature_file.stem
            feature_files[scenario_id] = content
            raw_files[f"scenarios/{feature_file.name}"] = content

        logger.info(
            "Loaded %d scenarios, %d feature files",
            len(scenarios),
            len(feature_files),
        )
    else:
        logger.warning("scenarios/ directory not found in %s", output_dir)

    # --- Scenario LLM call logs ---
    calls_path = output_dir / "scenarios" / "calls.jsonl"
    if calls_path.exists():
        try:
            for line in calls_path.read_text(encoding="utf-8").strip().splitlines():
                entry = json.loads(line)
                sid = entry.get("scenario_id", "")
                call_logs.setdefault(sid, []).append(entry)
            logger.info(
                "Loaded %d call log entries from %s",
                sum(len(v) for v in call_logs.values()),
                calls_path,
            )
        except Exception as exc:
            logger.warning("Failed to load %s: %s", calls_path, exc)
    else:
        logger.info(
            "calls.jsonl not found in %s (skipping call log section)",
            output_dir / "scenarios",
        )

    # --- Pipeline (non-scenario) LLM call logs ---
    pipeline_calls_path = output_dir / "calls.jsonl"
    if pipeline_calls_path.exists():
        try:
            for line in (
                pipeline_calls_path.read_text(encoding="utf-8").strip().splitlines()
            ):
                pipeline_call_logs.append(json.loads(line))
            logger.info(
                "Loaded %d pipeline call log entries from %s",
                len(pipeline_call_logs),
                pipeline_calls_path,
            )
        except Exception as exc:
            logger.warning("Failed to load %s: %s", pipeline_calls_path, exc)
    else:
        logger.info(
            "calls.jsonl not found in %s (skipping pipeline call log section)",
            output_dir,
        )

    # --- Coverage gaps ---
    coverage_path = output_dir / "coverage-gaps.json"
    if coverage_path.exists():
        try:
            coverage_data = json.loads(coverage_path.read_text(encoding="utf-8")) or {}
            raw_files["coverage-gaps.json"] = coverage_path.read_text(encoding="utf-8")
            logger.info("Loaded coverage gaps from %s", coverage_path)
        except Exception as exc:
            logger.warning("Failed to load %s: %s", coverage_path, exc)
    else:
        logger.info(
            "coverage-gaps.json not found in %s (skipping coverage section)", output_dir
        )

    # --- Eval scorecard ---
    scorecard_path = output_dir / "eval-scorecard.yaml"
    if scorecard_path.exists():
        try:
            scorecard_data = (
                yaml.safe_load(scorecard_path.read_text(encoding="utf-8")) or {}
            )
            raw_files["eval-scorecard.yaml"] = scorecard_path.read_text(
                encoding="utf-8"
            )
            logger.info("Loaded eval scorecard from %s", scorecard_path)
        except Exception as exc:
            logger.warning("Failed to load %s: %s", scorecard_path, exc)
    else:
        logger.info(
            "eval-scorecard.yaml not found in %s (skipping scorecard section)",
            output_dir,
        )

    # --- Run manifest ---
    manifest_path = output_dir / "run-manifest.yaml"
    if manifest_path.exists():
        try:
            manifest_data = (
                yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
            )
            logger.info("Loaded run manifest from %s", manifest_path)
        except Exception as exc:
            logger.warning("Failed to load %s: %s", manifest_path, exc)
    else:
        logger.info(
            "run-manifest.yaml not found in %s (skipping run summary section)",
            output_dir,
        )

    # --- Use case description ---
    use_case_path = output_dir / "use-case.txt"
    if use_case_path.exists():
        use_case_text = use_case_path.read_text(encoding="utf-8")
        logger.info("Loaded use case description from %s", use_case_path)
    else:
        logger.info(
            "use-case.txt not found in %s (skipping use case section)", output_dir
        )

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
