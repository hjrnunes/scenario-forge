from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)


def test_shadow_cleanup_cli_preserves_pipeline_skips_and_invalid_invocation() -> None:
    suite = _PROJECT_ROOT / "acceptance" / "qa" / "shadow-cleanup" / "qa_suite.py"
    environment = dict(os.environ)
    environment.pop("SCENARIO_FORGE_QA_PIPELINE", None)

    pipeline = subprocess.run(
        [sys.executable, str(suite), "--pipeline"],
        cwd=_PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert pipeline.returncode == 0
    assert pipeline.stdout.count("[SKIP] sc-pipeline-") == 2
    assert "QA suite: 0 passed, 0 failed" in pipeline.stdout

    invalid = subprocess.run(
        [sys.executable, str(suite), "--run-dir"],
        cwd=_PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert invalid.returncode == 2
    assert "argument --run-dir: expected one argument" in invalid.stderr
    assert "[PASS]" not in invalid.stdout
    assert "[FAIL]" not in invalid.stdout
    assert "[SKIP]" not in invalid.stdout


def test_shared_qa_runner_records_skips_without_counting_them_as_failures(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sys

    sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))
    from qa_harness import QARunner

    runner = QARunner()
    runner.skip("pipeline check", "not authorized")

    assert runner.summary() == 0
    result = runner.results[0]
    assert result.status == "SKIP"
    assert "[SKIP] pipeline check" in capsys.readouterr().out


def test_shadow_cleanup_suite_uses_shared_harness_for_child_execution() -> None:
    suite = _PROJECT_ROOT / "acceptance" / "qa" / "shadow-cleanup" / "qa_suite.py"
    tree = ast.parse(suite.read_text(encoding="utf-8"), filename=str(suite))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]

    assert "qa_harness" in imports
    assert not any(
        isinstance(node, ast.ClassDef) and node.name in {"CheckResult", "QARunner"}
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_command"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        for node in ast.walk(tree)
    )


def test_phase5_runtime_registration_is_one_scoped_feature_without_shadow_import() -> (
    None
):
    module_path = (
        _PROJECT_ROOT
        / "acceptance"
        / "runtime_features"
        / "phase5_qa_shadow_cleanup_migration.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.endswith("shadow_cleanup")
        for node in ast.walk(tree)
    )

    import sys

    sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))
    from runtime_features import phase5_qa_shadow_cleanup_migration as phase5

    class RecordingAPI:
        def __init__(self) -> None:
            self.feature: str | None = None
            self.entries: list[tuple[str, object, str | None]] = []

        def set_feature(self, feature: str | None) -> None:
            self.feature = feature

        def register(
            self, pattern: str, handler: object, *, source_order: int | None = None
        ) -> None:
            del source_order
            self.entries.append((pattern, handler, self.feature))

        def register_first(
            self, pattern: str, handler: object, *, source_order: int | None = None
        ) -> None:
            del source_order
            self.entries.append((pattern, handler, self.feature))

    api = RecordingAPI()
    phase5.register(api)

    assert phase5.FEATURE_ID == "phase5_qa_shadow_cleanup_migration"
    assert api.feature is None
    assert api.entries
    assert all(entry[2] == phase5.FEATURE_ID for entry in api.entries)
    assert len(api.entries) == len(
        {(pattern, handler) for pattern, handler, _feature in api.entries}
    )


def test_phase5_scope_allows_independent_phase4_characterization(monkeypatch) -> None:
    import sys
    from types import SimpleNamespace

    sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))
    from runtime_features import phase5_qa_shadow_cleanup_migration as phase5

    phase4_suite = "acceptance/qa/phase4-qa-refresh-migration/qa_suite.py"
    shadow_suite = "acceptance/qa/shadow-cleanup/qa_suite.py"
    other_suite = "acceptance/qa/acceptance-refresh/qa_suite.py"
    suites = [phase4_suite, shadow_suite, other_suite]
    baseline = {
        phase4_suite: b"phase4 completion\n",
        shadow_suite: b"shadow baseline\n",
        other_suite: b"other baseline\n",
    }
    current = {
        phase4_suite: b"phase4 forward-compatible characterization\n",
        shadow_suite: b"shadow baseline\n",
        other_suite: b"other baseline\n",
    }

    monkeypatch.setattr(
        phase5,
        "_git_tree_paths",
        lambda _ref, _root: suites,
    )
    monkeypatch.setattr(
        phase5,
        "_git_show",
        lambda ref, path: (baseline if ref == phase5._BASELINE else current).get(path),
    )

    passed, detail = phase5._h_other_suites(SimpleNamespace(), "", {})

    assert passed, detail
