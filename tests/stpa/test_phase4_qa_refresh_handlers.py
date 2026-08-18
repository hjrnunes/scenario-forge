from __future__ import annotations

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
