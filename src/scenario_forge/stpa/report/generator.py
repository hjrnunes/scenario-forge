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

from scenario_forge.stpa.report.template import (
    _build_llm_call_inspector,
    _build_run_manifest,
    _build_sp1_card,
    _build_sp2_card,
    _build_sp3_card,
    build_html,
    _extract_metric_rate,
)

logger = logging.getLogger(__name__)


def _read_yaml_raw(path: Path) -> str:
    """Read a YAML file as raw text."""
    return path.read_text(encoding="utf-8")


def _read_yaml_dict(path: Path) -> dict | None:
    """Read a YAML file and parse as dict, returning None on failure."""
    if not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse %s: %s", path, exc)
        return None


def _read_json_dict(path: Path) -> dict | None:
    """Read a JSON file and parse as dict, returning None on failure."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse %s: %s", path, exc)
        return None


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

    Returns a list of (scenario_id, envelope_dict, feature_text) tuples
    sorted by scenario_id.
    """
    if not scenarios_dir.exists():
        return []

    yaml_files = sorted(scenarios_dir.glob("*.yaml"))
    result: list[tuple[str, Any, str | None]] = []

    for yaml_path in yaml_files:
        scenario_id = yaml_path.stem
        envelope_data = _read_yaml_dict(yaml_path)
        feature_path = scenarios_dir / f"{scenario_id}.feature"
        feature_text = None
        if feature_path.exists():
            feature_text = feature_path.read_text(encoding="utf-8")
        result.append((scenario_id, envelope_data, feature_text))

    return result


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
        rate = _extract_metric_rate(data)
        if rate is not None:
            result[name] = rate
    return result if result else None


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

    if output_path is None:
        output_path = output_dir / "stpa-report.html"
    else:
        output_path = Path(output_path)

    # --- Load SP1 artifacts ---
    loss_analysis = None
    capability_profile = None
    control_structure = None
    sp1_raw: dict[str, str] = {}

    la_path = output_dir / "loss-analysis.yaml"
    if la_path.exists():
        sp1_raw["loss-analysis.yaml"] = _read_yaml_raw(la_path)
        try:
            from scenario_forge.stpa.models.loss_analysis import LossAnalysis
            loss_analysis = LossAnalysis.model_validate(
                yaml.safe_load(la_path.read_text(encoding="utf-8"))
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse loss-analysis.yaml: %s", exc)

    cp_path = output_dir / "capability-profile.yaml"
    if cp_path.exists():
        sp1_raw["capability-profile.yaml"] = _read_yaml_raw(cp_path)
        try:
            from scenario_forge.models.capability_profile import CapabilityProfile
            capability_profile = CapabilityProfile.model_validate(
                yaml.safe_load(cp_path.read_text(encoding="utf-8"))
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse capability-profile.yaml: %s", exc)

    cs_path = output_dir / "control-structure.yaml"
    if cs_path.exists():
        sp1_raw["control-structure.yaml"] = _read_yaml_raw(cs_path)
        try:
            from scenario_forge.stpa.models.control_structure import ControlStructure
            control_structure = ControlStructure.model_validate(
                yaml.safe_load(cs_path.read_text(encoding="utf-8"))
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse control-structure.yaml: %s", exc)

    # --- Load SP2 artifacts ---
    ica_enumeration = None
    enriched_threats = None
    sp2_raw: dict[str, str] = {}

    ica_path = output_dir / "ica-enumeration.yaml"
    if ica_path.exists():
        sp2_raw["ica-enumeration.yaml"] = _read_yaml_raw(ica_path)
        try:
            from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
            ica_enumeration = ICAEnumeration.model_validate(
                yaml.safe_load(ica_path.read_text(encoding="utf-8"))
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse ica-enumeration.yaml: %s", exc)

    et_path = output_dir / "enriched-threats.yaml"
    if et_path.exists():
        sp2_raw["enriched-threats.yaml"] = _read_yaml_raw(et_path)
        try:
            from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
            enriched_threats = EnrichedThreatSet.model_validate(
                yaml.safe_load(et_path.read_text(encoding="utf-8"))
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse enriched-threats.yaml: %s", exc)

    # --- Load SP3 artifacts ---
    scenarios_dir = output_dir / "scenarios"
    scenarios = _load_scenarios(scenarios_dir)

    eval_path = output_dir / "eval-scorecard.yaml"
    eval_data = _read_yaml_dict(eval_path)

    # coverage-gaps.json (loaded but not directly displayed in a separate section)
    _coverage_gaps = _read_json_dict(output_dir / "coverage-gaps.json")

    sp3_raw: dict[str, str] = {}
    if eval_path.exists():
        sp3_raw["eval-scorecard.yaml"] = _read_yaml_raw(eval_path)

    # --- Load infrastructure ---
    calls = _read_calls_jsonl(output_dir / "calls.jsonl")
    manifest_data = _read_yaml_dict(output_dir / "run-manifest.yaml")
    manifest_raw: dict[str, str] = {}
    manifest_path = output_dir / "run-manifest.yaml"
    if manifest_path.exists():
        manifest_raw["run-manifest.yaml"] = _read_yaml_raw(manifest_path)

    # --- Extract hero summary data ---
    run_id = manifest_data.get("run_id") if manifest_data else None
    created_at = manifest_data.get("created_at") if manifest_data else None
    scenario_count = manifest_data.get("scenario_count") if manifest_data else None
    if scenario_count is None and scenarios:
        scenario_count = len(scenarios)
    eval_metrics = _extract_eval_metrics(eval_data)

    # --- Build section HTML ---
    sp1_html = _build_sp1_card(loss_analysis, capability_profile, control_structure, sp1_raw)
    sp2_html = _build_sp2_card(ica_enumeration, enriched_threats, sp2_raw)
    sp3_html = _build_sp3_card(scenarios, eval_data, sp3_raw) if scenarios or eval_data else ""
    calls_html = _build_llm_call_inspector(calls) if calls else ""
    manifest_html = _build_run_manifest(manifest_data, manifest_raw)

    has_sp2 = bool(sp2_html and (ica_enumeration is not None or enriched_threats is not None))
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
