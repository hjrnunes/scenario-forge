"""Shared fixtures and state for acceptance framework contracts."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

_LAYOUT_ENVIRONMENT = (
    "SWARMFORGE_FEATURES_DIR",
    "SWARMFORGE_ACCEPTANCE_FEATURES_DIR",
    "SWARMFORGE_ACCEPTANCE_IR_DIR",
    "SWARMFORGE_ACCEPTANCE_DRY_DIR",
    "SWARMFORGE_ACCEPTANCE_GENERATED_DIR",
    "SWARMFORGE_ACCEPTANCE_MUTATION_DIR",
)

_AFR_BACKGROUND_STEP = "acceptance framework background observes its world"
_AFR_MUTATION_STEP = "acceptance framework first example changes its state"
_AFR_SCENARIO_STEP = "acceptance framework scenario observes its world"
_AFR_SUPPORTED_STEP = "acceptance framework supported passing step"
_AFR_ATOMIC_STAGED_PATTERN = "acceptance framework staged replacement witness"
_AFR_PRIORITY_PATTERN = "acceptance framework priority witness"
_AFR_ENVIRONMENT_VARIABLE = "ACCEPTANCE_FRAMEWORK_REFACTOR_TEST"

_ISOLATION_STATE_STACK: list[dict[str, Any]] = []


def _restore_environment(saved: dict[str, str | None]) -> None:
    """Restore only the layout variables changed by a framework fixture."""
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _without_layout_overrides() -> dict[str, str | None]:
    """Temporarily select the repository-relative default layout."""
    saved = {name: os.environ.get(name) for name in _LAYOUT_ENVIRONMENT}
    for name in _LAYOUT_ENVIRONMENT:
        os.environ.pop(name, None)
    return saved


def _fixture_state() -> dict[str, Any]:
    if not _ISOLATION_STATE_STACK:
        raise RuntimeError("acceptance framework isolation state is not active")
    return _ISOLATION_STATE_STACK[-1]


def _feature_ir(
    *,
    name: str,
    steps: list[str],
    examples: list[dict[str, str]] | None = None,
    background: list[str] | None = None,
) -> dict[str, Any]:
    """Build the small JSON IR shape consumed by ``execute_ir``."""
    return {
        "name": name,
        "background": [
            {"keyword": "Given", "text": text} for text in (background or [])
        ],
        "scenarios": [
            {
                "name": name,
                "steps": [{"keyword": "Then", "text": text} for text in steps],
                "examples": examples or [],
            }
        ],
    }


def _write_ir(payload: dict[str, Any], directory: Path | None = None) -> Path:
    root = directory or Path(tempfile.mkdtemp(prefix="acceptance-framework-ir-"))
    root.mkdir(parents=True, exist_ok=True)
    path = root / "fixture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
