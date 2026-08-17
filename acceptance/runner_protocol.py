"""Mutation-worker protocol and subprocess outcome mapping."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import traceback
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from paths import project_root

CommandRunner = Callable[..., Any]
Clock = Callable[[], int]


def infrastructure_response(
    error: str,
    *,
    job_id: str = "unknown",
    output: str = "",
    duration: int = 0,
) -> dict[str, Any]:
    """Build a protocol response for work that could not be executed."""
    return {
        "id": job_id,
        "outcome": "infrastructure_error",
        "output": output,
        "error": error,
        "duration": duration,
    }


def timeout_seconds(value: Any) -> int:
    """Convert the mutator's ``30s``/``1m`` timeout notation to seconds."""
    if isinstance(value, bool):
        raise ValueError("timeout must be a duration string")
    if isinstance(value, (int, float)):
        return _numeric_timeout(value)
    if not isinstance(value, str):
        raise ValueError(f"unsupported timeout value: {value!r}")
    return _string_timeout(value)


def _numeric_timeout(value: int | float) -> int:
    if value < 0:
        raise ValueError("timeout must be non-negative")
    return int(value)


def _string_timeout(value: str) -> int:
    suffixes = {"s": 1, "m": 60}
    for suffix, multiplier in suffixes.items():
        if value.endswith(suffix):
            return int(value[: -len(suffix)]) * multiplier
    raise ValueError(f"unsupported timeout value: {value!r}")


def _test_response(
    job_id: Any,
    outcome: str,
    result: Any,
    duration: int,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "outcome": outcome,
        "output": result.stdout,
        "error": result.stderr,
        "duration": duration,
    }


def _process_response(job_id: Any, result: Any, duration: int) -> dict[str, Any]:
    if result.returncode == 0:
        return _test_response(job_id, "test_success", result, duration)
    if result.returncode == 1:
        return _test_response(job_id, "test_failure", result, duration)
    return infrastructure_response(
        result.stderr or f"Exit code {result.returncode}",
        job_id=job_id,
        output=result.stdout,
        duration=duration,
    )


def _timeout_response(
    job: dict[str, Any],
    start: int,
    clock: Clock,
) -> dict[str, Any]:
    try:
        limit = timeout_seconds(job.get("timeout", "30s"))
    except (TypeError, ValueError):
        limit = "requested"
    return infrastructure_response(
        f"Timeout after {limit}s",
        job_id=job.get("id", "unknown"),
        duration=clock() - start,
    )


def _execute_process(
    job: dict[str, Any],
    command_runner: CommandRunner | None,
    root: Path | None,
    runtime_script: Path | None,
) -> Any:
    limit = timeout_seconds(job.get("timeout", "30s"))
    project = root or project_root(Path(__file__))
    script = runtime_script or Path(__file__).resolve().parent / "acceptance_runtime.py"
    runner = command_runner or subprocess.run
    return runner(
        [sys.executable, str(script), job.get("feature_json", "")],
        capture_output=True,
        text=True,
        timeout=limit,
        cwd=str(project),
    )


def run_mutation_job(
    job: dict[str, Any],
    *,
    command_runner: CommandRunner | None = None,
    root: Path | None = None,
    runtime_script: Path | None = None,
    clock: Clock = time.perf_counter_ns,
) -> dict[str, Any]:
    """Run one acceptance runtime job and map its process outcome."""
    if not isinstance(job, dict):
        return infrastructure_response("Job must be a JSON object")

    job_id = job.get("id", "unknown")
    start = clock()
    try:
        result = _execute_process(
            job,
            command_runner,
            root,
            runtime_script,
        )
        return _process_response(job_id, result, clock() - start)
    except subprocess.TimeoutExpired:
        return _timeout_response(job, start, clock)
    except Exception as exc:
        duration = clock() - start
        return infrastructure_response(
            f"{exc}\n{traceback.format_exc()}",
            job_id=job_id,
            duration=duration,
        )


def decode_job(line: str) -> dict[str, Any]:
    """Decode one protocol line, keeping malformed input in-band."""
    try:
        job = json.loads(line)
    except json.JSONDecodeError as exc:
        return infrastructure_response(f"Invalid JSON: {exc}")
    if not isinstance(job, dict):
        return infrastructure_response("Job must be a JSON object")
    return job


def responses(
    lines: Iterable[str],
    run_job: Callable[[dict[str, Any]], dict[str, Any]] = run_mutation_job,
) -> Iterator[dict[str, Any]]:
    """Yield one response for every non-empty worker input line."""
    for raw_line in lines:
        line = raw_line.strip()
        if line:
            job = decode_job(line)
            if (
                job.get("outcome") == "infrastructure_error"
                and job.get("id") == "unknown"
            ):
                yield job
            else:
                yield run_job(job)


__all__ = [
    "decode_job",
    "infrastructure_response",
    "responses",
    "run_mutation_job",
    "timeout_seconds",
]
