"""Unit contracts for the decomplected acceptance framework seams."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))

from lifecycle import ScenarioContext, run_steps, scenario_context  # noqa: E402
from generate_entrypoints import _feature_path_for  # noqa: E402
from paths import project_root  # noqa: E402
from registry import (  # noqa: E402
    PatternRegistry,
    RegistrationAPI,
    RegistrationStage,
)
from runner_protocol import (  # noqa: E402
    infrastructure_response,
    responses,
    run_mutation_job,
    timeout_seconds,
)
import refresh_snapshot  # noqa: E402
from runtime_shared import World as SharedWorld  # noqa: E402
from runtime_world import World  # noqa: E402


def _handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


def _failing_handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return False, "failed"


def test_world_compatibility_import_uses_the_state_boundary() -> None:
    assert SharedWorld is World
    assert World().parallel_calls == []


def test_scenario_context_restores_environment_after_exception(monkeypatch) -> None:
    monkeypatch.setenv("ACCEPTANCE_FRAMEWORK_SEAM", "before")

    with pytest.raises(RuntimeError, match="fixture failure"):
        with scenario_context() as context:
            assert isinstance(context, ScenarioContext)
            context.world.seam_value = "example state"
            os.environ["ACCEPTANCE_FRAMEWORK_SEAM"] = "changed"
            raise RuntimeError("fixture failure")

    assert os.environ["ACCEPTANCE_FRAMEWORK_SEAM"] == "before"


def test_run_steps_stops_at_the_first_failure() -> None:
    seen: list[str] = []

    def execute(world, step, examples):
        seen.append(step["text"])
        return (step["text"] != "stop", "failed" if step["text"] == "stop" else "")

    result = run_steps(
        World(),
        [{"text": "stop"}, {"text": "after"}],
        {},
        execute,
        kind="scenario",
    )

    assert not result.passed
    assert result.failed_kind == "scenario"
    assert seen == ["stop"]


def test_registry_publishes_order_and_resolves_feature_scope() -> None:
    stage = RegistrationStage()
    api = RegistrationAPI(stage)
    api.register("witness", _handler, source_order=30)
    api.set_feature("first")
    api.register_first("witness", _failing_handler, source_order=10)
    api.set_feature("other")
    api.register_first("witness", _handler, source_order=20)

    registry = PatternRegistry()
    registry.publish(stage)

    assert registry.resolve("witness", "first") is _failing_handler
    assert registry.resolve("witness", "other") is _handler
    assert registry.resolve("witness", None) is _handler


def test_registry_rejects_duplicate_handler_registration() -> None:
    stage = RegistrationStage()
    api = RegistrationAPI(stage)
    api.register("duplicate", _handler)

    with pytest.raises(RuntimeError, match="Duplicate step pattern registration"):
        api.register("duplicate", _handler)


def test_runner_protocol_maps_return_codes_and_duration() -> None:
    ticks = iter((100, 145))

    def run(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="out", stderr="err")

    response = run_mutation_job(
        {"id": "job", "feature_json": "fixture.json", "timeout": "1s"},
        command_runner=run,
        root=_PROJECT_ROOT,
        clock=lambda: next(ticks),
    )

    assert response == {
        "id": "job",
        "outcome": "test_failure",
        "output": "out",
        "error": "err",
        "duration": 45,
    }


def test_runner_protocol_maps_timeout_and_keeps_malformed_lines_in_band() -> None:
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("runtime", 1)

    response = run_mutation_job(
        {"id": "job", "feature_json": "fixture.json", "timeout": "2s"},
        command_runner=timeout,
        root=_PROJECT_ROOT,
    )
    assert response["outcome"] == "infrastructure_error"
    assert response["id"] == "job"

    lines = list(
        responses(
            ["not-json\n", '{"id":"valid","feature_json":"fixture.json"}\n'],
            lambda job: {"id": job["id"], "outcome": "test_success"},
        )
    )
    assert lines == [
        infrastructure_response(
            "Invalid JSON: Expecting value: line 1 column 1 (char 0)"
        ),
        {"id": "valid", "outcome": "test_success"},
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("30s", 30), ("2m", 120), (4, 4)],
)
def test_timeout_parser_supports_worker_duration_values(value, expected) -> None:
    assert timeout_seconds(value) == expected


def test_project_root_is_shared_by_acceptance_tools(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'fixture'\n")
    nested = tmp_path / "build" / "acceptance"
    nested.mkdir(parents=True)

    assert project_root(nested) == tmp_path


def test_feature_path_mapping_preserves_nested_ir_paths(monkeypatch) -> None:
    for name in (
        "SWARMFORGE_FEATURES_DIR",
        "SWARMFORGE_ACCEPTANCE_FEATURES_DIR",
        "SWARMFORGE_ACCEPTANCE_IR_DIR",
    ):
        monkeypatch.delenv(name, raising=False)

    assert (
        _feature_path_for("build/acceptance/ir/group/example.json", None)
        == "features/group/example.feature"
    )
    assert (
        _feature_path_for("external/example.json", None) == "features/example.feature"
    )


def test_refresh_tool_runner_uses_fallback_and_reports_failure(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        refresh_snapshot,
        "_resolve_binary",
        lambda name: None if name == "bb" else f"/bin/{name}",
    )
    monkeypatch.setattr(
        refresh_snapshot.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv) or SimpleNamespace(returncode=0),
    )

    assert refresh_snapshot.run_tool(["gherkin-parser", "input", "output"]) == 0
    assert calls == [["/bin/gherkin-parser", "input", "output"]]

    monkeypatch.setattr(
        refresh_snapshot.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=17),
    )
    with pytest.raises(RuntimeError, match="command failed"):
        refresh_snapshot.run_tool(["gherkin-parser", "input", "output"])

    monkeypatch.setattr(refresh_snapshot, "_resolve_binary", lambda _name: None)
    with pytest.raises(FileNotFoundError, match="neither bb"):
        refresh_snapshot.run_tool(["gherkin-parser", "input", "output"])
