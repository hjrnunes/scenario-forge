"""Report generator — reads pipeline artifacts and produces a self-contained HTML report."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

from scenario_forge.report.template import (
    build_attacker_diversity_section,
    build_capability_profile_section,
    build_coverage_section,
    build_full_page,
    build_methodology_section,
    build_raw_data_section,
    build_run_summary_section,
    build_scenarios_section,
    build_scorecard_section,
    build_threat_surface_section,
    build_threat_technique_section,
    build_use_case_section,
)

logger = logging.getLogger(__name__)


def generate_report(output_dir: Path) -> Path:
    """Read all pipeline artifacts from *output_dir* and write ``report.html``.

    Expected directory layout::

        output_dir/
            capability-profile.yaml
            threat-surface.yaml
            scenarios/
                *.yaml
                *.feature

    Returns:
        Path to the generated ``report.html``.
    """
    output_dir = Path(output_dir)

    # --- Check eval scorecard status ---
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

    # --- Load capability profile ---
    profile_path = output_dir / "capability-profile.yaml"
    if profile_path.exists():
        profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
        logger.info("Loaded capability profile from %s", profile_path)
    else:
        logger.warning("capability-profile.yaml not found in %s", output_dir)
        profile_data = {}

    # --- Load threat surface ---
    ts_path = output_dir / "threat-surface.yaml"
    if ts_path.exists():
        ts_data = yaml.safe_load(ts_path.read_text(encoding="utf-8")) or {}
        logger.info("Loaded threat surface from %s", ts_path)
    else:
        logger.warning("threat-surface.yaml not found in %s", output_dir)
        ts_data = {}

    # --- Load scenarios and feature files ---
    scenarios_dir = output_dir / "scenarios"
    scenarios: list[dict] = []
    feature_files: dict[str, str] = {}
    raw_files: dict[str, str] = {}

    # Add top-level files to raw data
    if profile_path.exists():
        raw_files["capability-profile.yaml"] = profile_path.read_text(encoding="utf-8")
    if ts_path.exists():
        raw_files["threat-surface.yaml"] = ts_path.read_text(encoding="utf-8")

    if scenarios_dir.is_dir():
        # Load YAML scenario envelopes
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

        # Load feature files
        for feature_file in sorted(scenarios_dir.glob("*.feature")):
            content = feature_file.read_text(encoding="utf-8")
            # Extract scenario ID from filename (e.g., AP-T5-01-5f016c.feature -> AP-T5-01-5f016c)
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

    # --- Load LLM call logs ---
    calls_path = output_dir / "scenarios" / "calls.jsonl"
    call_logs: dict[str, list[dict]] = {}  # keyed by scenario_id
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

    # --- Load coverage gaps ---
    coverage_path = output_dir / "coverage-gaps.json"
    coverage_data: dict = {}
    if coverage_path.exists():
        try:
            coverage_data = json.loads(coverage_path.read_text(encoding="utf-8")) or {}
            logger.info("Loaded coverage gaps from %s", coverage_path)
            raw_files["coverage-gaps.json"] = coverage_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to load %s: %s", coverage_path, exc)
    else:
        logger.info(
            "coverage-gaps.json not found in %s (skipping coverage section)", output_dir
        )

    # --- Load eval scorecard ---
    scorecard_path = output_dir / "eval-scorecard.yaml"
    scorecard_data: dict = {}
    if scorecard_path.exists():
        try:
            scorecard_data = (
                yaml.safe_load(scorecard_path.read_text(encoding="utf-8")) or {}
            )
            logger.info("Loaded eval scorecard from %s", scorecard_path)
            raw_files["eval-scorecard.yaml"] = scorecard_path.read_text(
                encoding="utf-8"
            )
        except Exception as exc:
            logger.warning("Failed to load %s: %s", scorecard_path, exc)
    else:
        logger.info(
            "eval-scorecard.yaml not found in %s (skipping scorecard section)",
            output_dir,
        )

    # --- Load run manifest ---
    manifest_path = output_dir / "run-manifest.yaml"
    manifest_data: dict = {}
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

    # Sort scenarios by priority (descending)
    scenarios.sort(
        key=lambda s: s.get("priority", {}).get("composite", 0),
        reverse=True,
    )

    # --- Load use case description ---
    use_case_path = output_dir / "use-case.txt"
    use_case_text = ""
    if use_case_path.exists():
        use_case_text = use_case_path.read_text(encoding="utf-8")
        logger.info("Loaded use case description from %s", use_case_path)
    else:
        logger.info(
            "use-case.txt not found in %s (skipping use case section)", output_dir
        )

    # --- Compute priority breakdown for run summary ---
    high_count = 0
    medium_count = 0
    low_count = 0
    for s in scenarios:
        composite = s.get("priority", {}).get("composite", 0)
        if composite >= 0.7:
            high_count += 1
        elif composite >= 0.4:
            medium_count += 1
        else:
            low_count += 1

    # Coverage gaps count (from coverage-gaps.json if available)
    coverage_gaps_count: int | None = None
    if coverage_data:
        gaps = coverage_data.get("coverage_gaps", {})
        coverage_gaps_count = (
            len(gaps.get("uncovered_entry_points", []))
            + len(gaps.get("uncovered_zones", []))
            + len(gaps.get("uncovered_threats", []))
        )

    # --- Build HTML sections ---
    run_summary_html = (
        build_run_summary_section(
            manifest_data,
            len(scenarios),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            coverage_gaps=coverage_gaps_count,
        )
        if manifest_data
        else ""
    )
    methodology_html = build_methodology_section()
    use_case_html = build_use_case_section(use_case_text) if use_case_text else ""
    profile_html = build_capability_profile_section(profile_data)
    threats_html = build_threat_surface_section(ts_data, scenarios=scenarios)

    coverage_html = ""
    if coverage_data:
        coverage_html = build_coverage_section(coverage_data)

    diversity_html = build_attacker_diversity_section(scenarios)

    threat_technique_html = build_threat_technique_section(scenarios)

    scorecard_html = build_scorecard_section(scorecard_data) if scorecard_data else ""

    scenarios_html = build_scenarios_section(
        scenarios,
        feature_files,
        call_logs,
        threat_surface=ts_data,
        capability_profile=profile_data,
        scenarios_generated=manifest_data.get("scenarios_generated") if manifest_data else None,
        scorecard_data=scorecard_data,
    )
    raw_html = build_raw_data_section(raw_files)

    # --- Assemble full page ---
    page_html = build_full_page(
        profile_html=profile_html,
        threats_html=threats_html,
        scenarios_html=scenarios_html,
        raw_html=raw_html,
        coverage_html=coverage_html,
        diversity_html=diversity_html,
        use_case_html=use_case_html,
        scorecard_html=scorecard_html,
        threat_technique_html=threat_technique_html,
        run_summary_html=run_summary_html,
        methodology_html=methodology_html,
    )

    # --- Write output ---
    report_path = output_dir / "report.html"
    report_path.write_text(page_html, encoding="utf-8")
    logger.info("Report written to %s (%d bytes)", report_path, len(page_html))

    return report_path
