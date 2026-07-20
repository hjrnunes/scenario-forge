"""Pipeline I/O boundary -- all filesystem writes for the pipeline runner.

This module centralises the file I/O that ``runner.run_pipeline`` performs so
that the pipeline orchestration logic can be tested without real filesystem
access.  Per-scenario incremental writes (``write_scenario_outputs``,
``write_call_log`` from ``generate.py``) remain in the generation loop for
crash-resilience but are re-exported here for a single import surface.
"""

from __future__ import annotations

import importlib.metadata
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.pipeline.threats import ThreatSurface

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Setup writes (top of pipeline)
# ---------------------------------------------------------------------------


def setup_pipeline_output(output_dir: Path, use_case: str) -> str:
    """Create output directory, persist the use-case, and write a manifest sentinel.

    Args:
        output_dir: Root output directory for this pipeline run.
        use_case: Free-text description of the AI system under assessment.

    Returns:
        ISO-format UTC timestamp recorded as the pipeline start time.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "use-case.txt").write_text(use_case)

    timestamp_start = datetime.now(timezone.utc).isoformat()
    manifest_path = output_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(
            {
                "status": "started",
                "timestamp_start": timestamp_start,
                "version": importlib.metadata.version("scenario-forge"),
            },
            default_flow_style=False,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return timestamp_start


# ---------------------------------------------------------------------------
# Per-stage writes
# ---------------------------------------------------------------------------


def write_capability_profile(profile: CapabilityProfile, output_dir: Path) -> Path:
    """Serialise and write the capability profile to ``capability-profile.yaml``.

    Returns:
        Path to the written file.
    """
    profile_output_path = output_dir / "capability-profile.yaml"
    profile_data = profile.model_dump(mode="json", exclude_none=True)
    profile_output_path.write_text(
        yaml.dump(
            profile_data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return profile_output_path


def write_threat_surface(threat_surface: ThreatSurface, output_dir: Path) -> Path:
    """Serialise and write the threat surface to ``threat-surface.yaml``.

    Returns:
        Path to the written file.
    """
    ts_path = output_dir / "threat-surface.yaml"
    ts_data = threat_surface.model_dump(mode="json", exclude_none=True)
    ts_path.write_text(
        yaml.dump(
            ts_data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return ts_path


def write_pipeline_call_log(entries: list[dict], output_dir: Path) -> None:
    """Append call-log entries to the top-level ``calls.jsonl`` in *output_dir*.

    This file records non-scenario LLM calls (capability-profile inference,
    candidate filtering) in the same JSON-per-line format used by
    ``scenarios/calls.jsonl``.
    """
    if not entries:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    calls_path = output_dir / "calls.jsonl"
    with calls_path.open("a", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def get_scenarios_dir(output_dir: Path) -> Path:
    """Return the path to the ``scenarios/`` subdirectory (does not create it).

    Creation is left to the incremental per-scenario writers in
    ``generate.write_scenario_outputs`` which call ``mkdir(parents=True)``.
    """
    return output_dir / "scenarios"


# ---------------------------------------------------------------------------
# Finalisation writes (post-loop)
# ---------------------------------------------------------------------------


def write_final_manifest(manifest: dict, output_dir: Path) -> Path:
    """Write the final run manifest, replacing the sentinel written at setup.

    Returns:
        Path to the written ``run-manifest.yaml``.
    """
    manifest_path = output_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(manifest, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return manifest_path


def write_eval_scorecard(scorecard: dict, output_dir: Path) -> Path:
    """Write the evaluation scorecard to ``eval-scorecard.yaml``.

    Returns:
        Path to the written file.
    """
    scorecard_path = output_dir / "eval-scorecard.yaml"
    scorecard_path.write_text(
        yaml.dump(
            scorecard,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return scorecard_path
