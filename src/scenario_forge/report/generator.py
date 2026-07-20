"""Report generator — builds a self-contained HTML report from ReportData."""

from __future__ import annotations

import logging
from pathlib import Path

from scenario_forge.report.data import ReportData, load_report_data
from scenario_forge.report.template import (
    build_attacker_diversity_section,
    build_capability_profile_section,
    build_coverage_section,
    build_full_page,
    build_methodology_section,
    build_pipeline_calls_section,
    build_raw_data_section,
    build_run_summary_section,
    build_scenarios_section,
    build_scorecard_section,
    build_threat_surface_section,
    build_threat_technique_section,
    build_use_case_section,
)

logger = logging.getLogger(__name__)


def generate_report(report_data: ReportData, output_dir: Path) -> Path:
    """Build the HTML report from *report_data* and write it to *output_dir*.

    This function performs no filesystem reads -- all data comes from the
    :class:`ReportData` object.  The only I/O is writing ``report.html``.

    Args:
        report_data: Pre-loaded report inputs (see :func:`load_report_data`).
        output_dir: Directory where ``report.html`` will be written.

    Returns:
        Path to the generated ``report.html``.
    """
    output_dir = Path(output_dir)

    # Unpack data for readability
    profile_data = report_data.profile_data
    ts_data = report_data.threat_surface_data
    scenarios = list(report_data.scenarios)  # copy so sort is non-destructive
    feature_files = report_data.feature_files
    call_logs = report_data.call_logs
    pipeline_call_logs = report_data.pipeline_call_logs
    coverage_data = report_data.coverage_data
    scorecard_data = report_data.scorecard_data
    manifest_data = report_data.manifest_data
    use_case_text = report_data.use_case_text
    raw_files = report_data.raw_files

    # Sort scenarios by priority (descending)
    scenarios.sort(
        key=lambda s: s.get("priority", {}).get("composite", 0),
        reverse=True,
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

    pipeline_calls_html = (
        build_pipeline_calls_section(pipeline_call_logs)
        if pipeline_call_logs
        else ""
    )

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
        pipeline_calls_html=pipeline_calls_html,
    )

    # --- Write output ---
    report_path = output_dir / "report.html"
    report_path.write_text(page_html, encoding="utf-8")
    logger.info("Report written to %s (%d bytes)", report_path, len(page_html))

    return report_path


def generate_report_from_dir(output_dir: Path) -> Path:
    """Convenience wrapper: load artifacts from *output_dir* and generate the report.

    Equivalent to::

        data = load_report_data(output_dir)
        return generate_report(data, output_dir)
    """
    data = load_report_data(output_dir)
    return generate_report(data, output_dir)
