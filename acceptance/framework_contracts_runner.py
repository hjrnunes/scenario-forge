"""Runner protocol contract handlers."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from runtime_bootstrap import PROJECT_ROOT
from runtime_world import World

from framework_contracts_common import (
    _feature_ir,
    _write_ir,
)


def _h_afr_runner_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(
        r' the mutation worker receives job "job-1" for an IR runtime that (.+)',
        text,
    )
    if match is None:
        match = re.fullmatch(
            r'the mutation worker receives job "job-1" for an IR runtime that (.+)',
            text,
        )
    if match is None:
        return False, f"Could not parse runner condition: {text}"
    world.afr_runner_condition = match.group(1)
    return True, ""


def _h_afr_runner_execute(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import runner_adapter

    condition = world.afr_runner_condition

    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        if condition == "exits with status 0":
            return SimpleNamespace(returncode=0, stdout="stdout", stderr="stderr")
        if condition == "exits with status 1":
            return SimpleNamespace(returncode=1, stdout="stdout", stderr="stderr")
        if condition == "exits with another status":
            return SimpleNamespace(returncode=2, stdout="stdout", stderr="stderr")
        if condition == "exceeds its requested timeout":
            raise subprocess.TimeoutExpired("runtime", 1)
        raise RuntimeError("injected worker execution exception")

    original_run = runner_adapter.subprocess.run
    runner_adapter.subprocess.run = fake_run
    try:
        world.afr_runner_response = runner_adapter.run_job(
            {
                "id": "job-1",
                "feature_json": "fixture.json",
                "timeout": "1s",
            }
        )
    finally:
        runner_adapter.subprocess.run = original_run
    return True, ""


def _h_afr_runner_id(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.afr_runner_response.get("id") == "job-1",
        f"unexpected runner id: {world.afr_runner_response}",
    )


def _h_afr_runner_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r'the response outcome is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse runner outcome: {text}"
    expected = match.group(1)
    actual = world.afr_runner_response.get("outcome")
    return actual == expected, f"unexpected outcome: {actual}"


def _h_afr_runner_duration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    duration = world.afr_runner_response.get("duration")
    return (
        type(duration) is int and duration >= 0,
        f"invalid duration: {duration!r}",
    )


def _h_afr_runner_streams(world: World, text: str, examples: dict) -> tuple[bool, str]:
    response = world.afr_runner_response
    return (
        isinstance(response.get("output"), str)
        and isinstance(response.get("error"), str)
        and response["output"] != response["error"],
        f"runner streams were conflated: {response}",
    )


def _h_afr_worker_ready(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.afr_worker_ready = True
    return True, ""


def _read_worker_ready(process: Any) -> tuple[str, str | None]:
    if process.stderr is None:
        return "", "runner stderr was unavailable"
    ready = process.stderr.readline()
    if ready.strip() != "runner_adapter: ready":
        return ready, f"runner did not announce readiness: {ready!r}"
    return ready, None


def _send_worker_request(process: Any, ir_path: Path) -> str | None:
    if process.stdin is None:
        return "runner stdin was unavailable"
    process.stdin.write(
        "not-json\n"
        + json.dumps(
            {
                "id": "job-valid",
                "feature_json": str(ir_path),
                "timeout": "30s",
            }
        )
        + "\n"
    )
    process.stdin.close()
    return None


def _collect_worker_output(process: Any) -> SimpleNamespace:
    stdout = process.stdout.read() if process.stdout else ""
    stderr = process.stderr.read() if process.stderr else ""
    return_code = process.wait(timeout=60)
    return SimpleNamespace(stdout=stdout, stderr=stderr, return_code=return_code)


def _stop_worker(process: Any) -> None:
    process.kill()
    process.wait()


def _run_worker(command: list[str], ir_path: Path) -> SimpleNamespace:
    process = subprocess.Popen(
        command,
        cwd=str(PROJECT_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, error = _read_worker_ready(process)
        if error:
            _stop_worker(process)
            return SimpleNamespace(error=error)
        error = _send_worker_request(process, ir_path)
        if error:
            _stop_worker(process)
            return SimpleNamespace(error=error)
        output = _collect_worker_output(process)
        return SimpleNamespace(error=None, ready=ready, output=output)
    except Exception as exc:
        _stop_worker(process)
        return SimpleNamespace(error=f"mutation worker protocol failed: {exc}")


def _h_afr_worker_protocol(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = Path(tempfile.mkdtemp(prefix="acceptance-framework-worker-"))
    ir_path = _write_ir(_feature_ir(name="worker-valid", steps=[]), root)
    command = [sys.executable, str(PROJECT_ROOT / "acceptance" / "runner_adapter.py")]
    result = _run_worker(command, ir_path)
    if result.error:
        return False, result.error
    output = result.output

    world.afr_worker_ready_line = result.ready.strip()
    world.afr_worker_stdout_lines = output.stdout.splitlines()
    world.afr_worker_stderr = result.ready + output.stderr
    world.afr_worker_return_code = output.return_code
    try:
        world.afr_worker_responses = [
            json.loads(line) for line in world.afr_worker_stdout_lines
        ]
    except json.JSONDecodeError as exc:
        world.afr_worker_responses = []
        return False, f"worker emitted non-JSON output: {exc}"
    return True, ""


def _h_afr_worker_malformed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    responses = world.afr_worker_responses
    matches = [
        response
        for response in responses
        if response.get("id") == "unknown"
        and response.get("outcome") == "infrastructure_error"
    ]
    return len(matches) == 1, f"malformed request response missing: {responses}"


def _h_afr_worker_continues(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    responses = world.afr_worker_responses
    valid = [response for response in responses if response.get("id") == "job-valid"]
    return len(responses) == 2 and len(valid) == 1, f"worker stopped early: {responses}"


def _h_afr_worker_json_lines(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        all(isinstance(response, dict) for response in world.afr_worker_responses)
        and world.afr_worker_return_code == 0,
        f"invalid worker protocol output: {world.afr_worker_responses}",
    )
