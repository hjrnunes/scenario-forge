"""Acceptance step handlers for the report feature group."""

from __future__ import annotations

from runtime_shared import (
    Path,
    World,
    re,
    tempfile,
)

def _h_report_combined_dir_with_eval(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a combined output directory containing eval-scorecard.yaml with metrics: (data table)."""
    import tempfile
    world.report_tmpdir = Path(tempfile.mkdtemp(prefix="stpa_report_"))
    (world.report_tmpdir / "run-manifest.yaml").write_text("run_id: test-run\n")

    data_table = world.current_data_table
    if data_table:
        metrics_yaml = "metrics:\n"
        for row in data_table[1:]:  # skip header
            if len(row) >= 2:
                metrics_yaml += f"  {row[0].strip()}:\n    rate: {row[1].strip()}\n"
        (world.report_tmpdir / "eval-scorecard.yaml").write_text(metrics_yaml)
    return True, ""

def _h_report_eval_metric(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: eval-scorecard.yaml contains a metric "<metric>" with rate "<rate>"."""
    import tempfile
    metric = examples.get("metric", "")
    rate = examples.get("rate", "")
    world.report_tmpdir = Path(tempfile.mkdtemp(prefix="stpa_report_"))
    (world.report_tmpdir / "run-manifest.yaml").write_text("run_id: test-run\n")
    (world.report_tmpdir / "eval-scorecard.yaml").write_text(
        f"metrics:\n  {metric}:\n    rate: {rate}\n"
    )
    return True, ""

def _h_report_generate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: I generate the STPA report."""
    from scenario_forge.stpa.report import generate_report
    if not hasattr(world, "report_tmpdir") or world.report_tmpdir is None:
        import tempfile
        world.report_tmpdir = Path(tempfile.mkdtemp(prefix="stpa_report_"))
        (world.report_tmpdir / "run-manifest.yaml").write_text("run_id: test-run\n")
    world.report_html_path = generate_report(world.report_tmpdir)
    world.report_html_content = world.report_html_path.read_text(encoding="utf-8")
    return True, ""

def _h_report_gauge_colored(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the eval scorecard gauge for "<metric>" is colored "<color>"."""
    metric = examples.get("metric", "")
    color = examples.get("color", "")
    if not hasattr(world, "report_html_content") or world.report_html_content is None:
        return False, "No report HTML generated"
    html_content = world.report_html_content
    if metric not in html_content:
        return False, f"Metric '{metric}' not found in report HTML"
    if color not in html_content.lower():
        return False, f"Color '{color}' not found in report HTML"
    expected_class = f"eval-gauge-fill {color}"
    if expected_class not in html_content:
        return False, f"Expected gauge fill class '{expected_class}' not found"
    return True, ""

def _h_report_gauge_shown(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the eval scorecard shows a gauge for "...". """
    match = re.search(r'shows a gauge for "([^"]+)"', text)
    if not match:
        return False, f"Could not parse gauge step: {text}"
    metric = match.group(1)
    if not hasattr(world, "report_html_content") or world.report_html_content is None:
        return False, "No report HTML generated"
    if metric not in world.report_html_content:
        return False, f"Metric '{metric}' not found in report HTML"
    return True, ""

FEATURE_ID = 'report'

def register(api: object) -> None:
    """Register this feature group through the supplied facade API."""
    api.set_feature(None)
    api.set_feature('stpa_report')
    api.register_first('a combined output directory containing eval-scorecard\\.yaml with metrics:', _h_report_combined_dir_with_eval, source_order=20291)
    api.register_first('eval-scorecard\\.yaml contains a metric .* with rate .*', _h_report_eval_metric, source_order=20292)
    api.register_first('I generate the STPA report', _h_report_generate, source_order=20293)
    api.register_first('the eval scorecard gauge for .* is colored .*', _h_report_gauge_colored, source_order=20294)
    api.register_first('the eval scorecard shows a gauge for .*', _h_report_gauge_shown, source_order=20295)
    api.set_feature(None)

__all__ = ["FEATURE_ID", "register"]
