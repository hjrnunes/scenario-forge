"""Unit contracts for live-LLM acceptance opt-in and isolation."""

from __future__ import annotations

import json
import os
import re
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(ROOT / "acceptance"))

from acceptance_runtime import execute_ir  # noqa: E402


LIVE_MARKER = 'live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"'
PIPELINE_STEP = (
    "I run `scenario-forge stpa-run --use-case <use_case> "
    "--risk-extraction <risk_file> --output-dir <dir>`"
)


def _write_ir(tmp_path: Path, scenarios: list[dict]) -> Path:
    ir_path = tmp_path / "fixture.json"
    ir_path.write_text(
        json.dumps(
            {
                "name": "Live opt-in fixture",
                "background": [],
                "scenarios": scenarios,
            }
        ),
        encoding="utf-8",
    )
    return ir_path


def _scenario(name: str, *steps: str) -> dict:
    return {
        "name": name,
        "steps": [{"keyword": "Given", "text": step} for step in steps],
        "examples": [],
    }


def test_default_execution_skips_marked_scenario_even_with_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SCENARIO_FORGE_QA_PIPELINE", raising=False)
    monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "http://127.0.0.1:9/v1")

    passed, output = execute_ir(
        str(
            _write_ir(
                tmp_path,
                [
                    _scenario("deterministic"),
                    _scenario("live", LIVE_MARKER),
                ],
            )
        )
    )

    assert passed
    assert "PASS deterministic/example_1" in output
    assert (
        "SKIP live/example_1: live LLM acceptance requires "
        'SCENARIO_FORGE_QA_PIPELINE "1"'
    ) in output
    assert "FAIL live/example_1" not in output


@pytest.mark.parametrize("value", ["0", "true", "yes"])
def test_only_exact_one_authorizes_marked_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("SCENARIO_FORGE_QA_PIPELINE", value)

    passed, output = execute_ir(
        str(_write_ir(tmp_path, [_scenario("live", LIVE_MARKER)]))
    )

    assert passed
    assert "SKIP live/example_1" in output
    assert "PASS live/example_1" not in output


def test_opt_in_without_endpoint_attempts_and_fails_visibly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCENARIO_FORGE_QA_PIPELINE", "1")
    for name in (
        "SCENARIO_FORGE_MODEL_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "SCENARIO_FORGE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    passed, output = execute_ir(
        str(
            _write_ir(
                tmp_path,
                [_scenario("live", LIVE_MARKER, PIPELINE_STEP)],
            )
        )
    )

    assert not passed
    assert "SKIP live/example_1" not in output
    assert "FAIL live/example_1" in output
    assert "LLM endpoint not configured" in output


def test_scenario_environment_does_not_leak_fake_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCENARIO_FORGE_QA_PIPELINE", "1")
    for name in (
        "SCENARIO_FORGE_MODEL_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "SCENARIO_FORGE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    ir_path = _write_ir(
        tmp_path,
        [
            _scenario(
                "configures endpoint",
                "environment variable SCENARIO_FORGE_MODEL_BASE_URL "
                "is set to http://fake.example/v1",
            ),
            _scenario("live", LIVE_MARKER, PIPELINE_STEP),
        ],
    )

    passed, output = execute_ir(str(ir_path))

    assert not passed
    assert "PASS configures endpoint/example_1" in output
    assert "LLM endpoint not configured" in output
    assert "http://fake.example/v1" not in os.environ.values()


def test_pipeline_placeholders_are_fresh_files_per_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCENARIO_FORGE_QA_PIPELINE", "1")
    monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "http://fake.example/v1")
    commands: list[str] = []

    def fake_run(command: str, **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    live_scenarios = [
        _scenario(f"live-{index}", LIVE_MARKER, PIPELINE_STEP) for index in (1, 2)
    ]

    passed, output = execute_ir(str(_write_ir(tmp_path, live_scenarios)))

    assert passed
    assert output.count("PASS live-") == 2
    assert len(commands) == 2
    input_paths = [
        Path(match.group(1))
        for command in commands
        if (match := re.search(r"--use-case @([^ ]+)", command))
    ]
    risk_paths = [
        Path(match.group(1))
        for command in commands
        if (match := re.search(r"--risk-extraction ([^ ]+)", command))
    ]
    assert len(input_paths) == len(risk_paths) == 2
    assert all(path.is_file() for path in input_paths + risk_paths)
    assert len(set(input_paths + risk_paths)) == 4
    assert all(path != Path(".") for path in input_paths + risk_paths)
    assert all("fixture=" in line and "output=" in line for line in output.splitlines())
