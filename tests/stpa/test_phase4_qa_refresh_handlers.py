from __future__ import annotations

import os
import sys
from pathlib import Path


_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))

from registry import RegistrationAPI, RegistrationStage  # noqa: E402
from runtime_features import phase4_qa_refresh_migration  # noqa: E402
from runtime_features.phase4_qa_refresh_migration_support import (  # noqa: E402
    _ENDPOINT_VARIABLES,
    _finish_sentinel,
    _start_sentinel,
)


def test_phase4_handlers_register_each_feature_step_once():
    stage = RegistrationStage()
    phase4_qa_refresh_migration.register(RegistrationAPI(stage))

    patterns = [entry[3] for entry in stage.entries]

    assert phase4_qa_refresh_migration.FEATURE_ID == "phase4_qa_refresh_migration"
    assert len(patterns) == len(set(patterns))
    assert all(
        expected in patterns
        for expected in (
            r'the Phase 4 migration baseline is commit "([^"]+)"',
            "live endpoint opt-in is unset",
            "acceptance-refresh QA help is requested",
            r'help advertises option "([^"]+)"',
            "the migrated suite and generated Phase 4 acceptance test are run",
        )
    )
    assert stage.feature is None


def test_phase4_sentinel_restores_endpoint_environment(monkeypatch):
    original = {name: f"original-{name.lower()}" for name in _ENDPOINT_VARIABLES}
    missing = _ENDPOINT_VARIABLES[-1]
    for name, value in original.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)
    original[missing] = None

    world = type("World", (), {})()
    _start_sentinel(world)
    assert world.p4qrm_endpoint_environment == original

    _finish_sentinel(world)

    assert all(os.environ.get(name) == value for name, value in original.items())
    assert world.p4qrm_endpoint_environment is None
