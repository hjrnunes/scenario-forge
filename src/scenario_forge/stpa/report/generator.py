"""STPA report generator — loads artifacts and assembles the HTML report.

Reads SP1, SP2, SP3, and infrastructure artifacts from a single combined
output directory and delegates to :mod:`scenario_forge.stpa.report.template`
for HTML assembly.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope
from scenario_forge.stpa.report.template import (
    build_html,
    build_llm_call_inspector,
    build_run_manifest,
    build_sp1_card,
    build_sp2_card,
    build_sp3_card,
    extract_metric_rate,
)

logger = logging.getLogger(__name__)


def _read_yaml_raw(path: Path) -> str:
    """Read a YAML file as raw text."""
    return path.read_text(encoding="utf-8")


def _read_dict_file(path: Path, parser: Any, label: str) -> dict | None:
    """Read a file and parse as dict, returning None on failure.

    Args:
        path: File path to read.
        parser: Callable that parses text into a Python object
            (e.g. ``yaml.safe_load`` or ``json.loads``).
        label: Human-readable format name for log messages.
    """
    if not path.exists():
        return None
    try:
        data = parser(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse %s: %s", path, exc)
        return None


def _read_yaml_dict(path: Path) -> dict | None:
    """Read a YAML file and parse as dict, returning None on failure."""
    return _read_dict_file(path, yaml.safe_load, "YAML")


def _read_json_dict(path: Path) -> dict | None:
    """Read a JSON file and parse as dict, returning None on failure."""
    return _read_dict_file(path, json.loads, "JSON")


def _read_calls_jsonl(path: Path) -> list[dict]:
    """Read a JSONL calls file and return a list of entry dicts."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed JSONL line: %s", exc)
    return entries


def _load_scenarios(scenarios_dir: Path) -> list[tuple[str, Any, str | None]]:
    """Load all scenario envelopes and feature files from a scenarios directory.

    Each scenario YAML is parsed into a :class:`ScenarioEnvelope` model so
    that template builders can use attribute access.  If parsing fails the
    envelope is ``None`` (the Gherkin feature file is still loaded).

    Returns a list of (scenario_id, envelope, feature_text) tuples
    sorted by scenario_id.
    """
    if not scenarios_dir.exists():
        return []

    yaml_files = sorted(scenarios_dir.glob("*.yaml"))
    result: list[tuple[str, Any, str | None]] = []

    for yaml_path in yaml_files:
        scenario_id = yaml_path.stem
        envelope = _load_model_artifact(
            yaml_path, {}, ScenarioEnvelope, yaml_path.name,
        )
        feature_path = scenarios_dir / f"{scenario_id}.feature"
        feature_text = None
        if feature_path.exists():
            feature_text = feature_path.read_text(encoding="utf-8")
        result.append((scenario_id, envelope, feature_text))

    return result


def _load_model_artifact(
    path: Path,
    raw_dict: dict[str, str],
    model_cls: type,
    filename: str,
) -> Any | None:
    """Load a Pydantic model artifact, storing raw text in *raw_dict*.

    Returns the parsed model instance, or ``None`` if the file is missing
    or fails to parse.
    """
    if not path.exists():
        return None
    raw_dict[filename] = _read_yaml_raw(path)
    try:
        return model_cls.model_validate(
            yaml.safe_load(path.read_text(encoding="utf-8"))
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse %s: %s", filename, exc)
        return None


def _load_raw_yaml(path: Path, raw_dict: dict[str, str], filename: str) -> None:
    """Load raw YAML text into *raw_dict* if *path* exists."""
    if path.exists():
        raw_dict[filename] = _read_yaml_raw(path)


def _load_sp1_artifacts(
    output_dir: Path,
) -> tuple[Any | None, Any | None, Any | None, dict[str, str]]:
    """Load SP1 artifacts: loss analysis, capability profile, control structure."""
    sp1_raw: dict[str, str] = {}
    loss_analysis = _load_model_artifact(
        output_dir / "loss-analysis.yaml", sp1_raw, LossAnalysis, "loss-analysis.yaml",
    )
    capability_profile = _load_model_artifact(
        output_dir / "capability-profile.yaml", sp1_raw,
        CapabilityProfile, "capability-profile.yaml",
    )
    control_structure = _load_model_artifact(
        output_dir / "control-structure.yaml", sp1_raw,
        ControlStructure, "control-structure.yaml",
    )
    return loss_analysis, capability_profile, control_structure, sp1_raw


def _load_sp2_artifacts(
    output_dir: Path,
) -> tuple[Any | None, Any | None, dict[str, str]]:
    """Load SP2 artifacts: ICA enumeration, enriched threats."""
    sp2_raw: dict[str, str] = {}
    ica_enumeration = _load_model_artifact(
        output_dir / "ica-enumeration.yaml", sp2_raw,
        ICAEnumeration, "ica-enumeration.yaml",
    )
    enriched_threats = _load_model_artifact(
        output_dir / "enriched-threats.yaml", sp2_raw,
        EnrichedThreatSet, "enriched-threats.yaml",
    )
    return ica_enumeration, enriched_threats, sp2_raw


def _extract_eval_metrics(eval_data: dict | None) -> dict[str, float] | None:
    """Extract key eval metrics for the hero summary.

    Returns a dict of metric_name -> rate, or None if no eval data.
    """
    if not eval_data:
        return None
    metrics = eval_data.get("metrics", eval_data)
    if not isinstance(metrics, dict):
        return None
    result: dict[str, float] = {}
    for name, data in metrics.items():
        rate = extract_metric_rate(data)
        if rate is not None:
            result[name] = rate
    return result if result else None


def _extract_hero_data(
    manifest_data: dict | None,
    scenarios: list[tuple[str, Any, str | None]],
    eval_data: dict | None,
) -> tuple[str | None, str | None, int | None, dict[str, float] | None]:
    """Extract hero summary fields from manifest, scenarios, and eval data."""
    run_id = manifest_data.get("run_id") if manifest_data else None
    created_at = manifest_data.get("created_at") if manifest_data else None
    scenario_count = manifest_data.get("scenario_count") if manifest_data else None
    if scenario_count is None and scenarios:
        scenario_count = len(scenarios)
    eval_metrics = _extract_eval_metrics(eval_data)
    return run_id, created_at, scenario_count, eval_metrics


def _resolve_output_path(output_dir: Path, output_path: Path | None) -> Path:
    """Resolve the output path, defaulting to output_dir/stpa-report.html."""
    if output_path is None:
        return output_dir / "stpa-report.html"
    return Path(output_path)


def _build_sp3_html(
    scenarios: list[tuple[str, Any, str | None]],
    eval_data: dict | None,
    sp3_raw: dict[str, str],
) -> str:
    """Build SP3 section HTML, or empty string if no SP3 data."""
    if not scenarios and not eval_data:
        return ""
    return build_sp3_card(scenarios, eval_data, sp3_raw)


def _compute_has_sp2(
    sp2_html: str,
    ica_enumeration: Any | None,
    enriched_threats: Any | None,
) -> bool:
    """Determine whether the SP2 section should be shown."""
    return bool(
        sp2_html and (ica_enumeration is not None or enriched_threats is not None)
    )


def generate_report(output_dir: Path, output_path: Path | None = None) -> Path:
    """Generate a self-contained HTML report from a combined STPA output directory.

    Args:
        output_dir: Directory containing SP1/SP2/SP3 artifacts.
        output_path: Destination HTML file path. If None, defaults to
            ``output_dir / "stpa-report.html"``.

    Returns:
        The path to the written HTML file.

    Raises:
        FileNotFoundError: If *output_dir* does not exist.
    """
    output_dir = Path(output_dir)
    if not output_dir.exists():
        raise FileNotFoundError(f"directory not found: {output_dir}")

    output_path = _resolve_output_path(output_dir, output_path)

    # --- Load artifacts ---
    loss_analysis, capability_profile, control_structure, sp1_raw = (
        _load_sp1_artifacts(output_dir)
    )
    ica_enumeration, enriched_threats, sp2_raw = _load_sp2_artifacts(output_dir)

    scenarios_dir = output_dir / "scenarios"
    scenarios = _load_scenarios(scenarios_dir)

    eval_path = output_dir / "eval-scorecard.yaml"
    eval_data = _read_yaml_dict(eval_path)

    _coverage_gaps = _read_json_dict(output_dir / "coverage-gaps.json")

    sp3_raw: dict[str, str] = {}
    _load_raw_yaml(eval_path, sp3_raw, "eval-scorecard.yaml")

    calls = _read_calls_jsonl(output_dir / "calls.jsonl")
    manifest_data = _read_yaml_dict(output_dir / "run-manifest.yaml")
    manifest_raw: dict[str, str] = {}
    _load_raw_yaml(
        output_dir / "run-manifest.yaml", manifest_raw, "run-manifest.yaml",
    )

    # --- Extract hero summary data ---
    run_id, created_at, scenario_count, eval_metrics = _extract_hero_data(
        manifest_data, scenarios, eval_data,
    )

    # --- Build section HTML ---
    sp1_html = build_sp1_card(
        loss_analysis, capability_profile, control_structure, sp1_raw,
    )
    sp2_html = build_sp2_card(ica_enumeration, enriched_threats, sp2_raw)
    sp3_html = _build_sp3_html(scenarios, eval_data, sp3_raw)
    calls_html = build_llm_call_inspector(calls) if calls else ""
    manifest_html = build_run_manifest(manifest_data, manifest_raw)

    has_sp2 = _compute_has_sp2(sp2_html, ica_enumeration, enriched_threats)
    has_sp3 = bool(sp3_html)

    # --- Assemble final HTML ---
    html_doc = build_html(
        run_id=run_id,
        created_at=created_at,
        scenario_count=scenario_count,
        eval_metrics=eval_metrics,
        sp1_html=sp1_html,
        sp2_html=sp2_html,
        sp3_html=sp3_html,
        calls_html=calls_html,
        manifest_html=manifest_html,
        has_sp2=has_sp2,
        has_sp3=has_sp3,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_doc, encoding="utf-8")
    logger.info("STPA report written to %s", output_path)
    return output_path
