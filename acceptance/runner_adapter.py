#!/usr/bin/env python3
"""Runner adapter for gherkin-mutator.

Persistent worker that reads mutation job requests from stdin (one JSON
object per line) and writes job responses to stdout (one JSON object per
line).

Job request:
    {"id": "m1", "feature_json": "path/to/feature.json", ...}

Job response:
    {"id": "m1", "outcome": "test_success|test_failure|infrastructure_error", ...}
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import traceback
from pathlib import Path


def _infrastructure_response(
    error: str, *, job_id: str = "unknown", output: str = ""
) -> dict:
    """Build a protocol response for work that could not be executed."""
    return {
        "id": job_id,
        "outcome": "infrastructure_error",
        "output": output,
        "error": error,
        "duration": 0,
    }


def run_job(job: dict) -> dict:
    """Execute a single mutation job."""
    if not isinstance(job, dict):
        return _infrastructure_response("Job must be a JSON object")

    job_id = job.get("id", "unknown")
    feature_json = job.get("feature_json", "")
    timeout_str = job.get("timeout", "30s")

    # Parse timeout
    timeout_seconds = 30
    if timeout_str.endswith("s"):
        timeout_seconds = int(timeout_str[:-1])
    elif timeout_str.endswith("m"):
        timeout_seconds = int(timeout_str[:-1]) * 60

    start = time.perf_counter_ns()

    try:
        # Run the acceptance runtime against the mutated IR
        project_root = next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        runtime_script = Path(__file__).resolve().parent / "acceptance_runtime.py"

        result = subprocess.run(
            [sys.executable, str(runtime_script), feature_json],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(project_root),
        )

        duration = time.perf_counter_ns() - start

        if result.returncode == 0:
            return {
                "id": job_id,
                "outcome": "test_success",
                "output": result.stdout,
                "error": result.stderr,
                "duration": duration,
            }
        elif result.returncode == 1:
            return {
                "id": job_id,
                "outcome": "test_failure",
                "output": result.stdout,
                "error": result.stderr,
                "duration": duration,
            }
        else:
            return _infrastructure_response(
                result.stderr or f"Exit code {result.returncode}",
                job_id=job_id,
                output=result.stdout,
            ) | {"duration": duration}
    except subprocess.TimeoutExpired:
        duration = time.perf_counter_ns() - start
        return _infrastructure_response(
            f"Timeout after {timeout_seconds}s", job_id=job_id
        ) | {"duration": duration}
    except Exception as e:
        duration = time.perf_counter_ns() - start
        return _infrastructure_response(
            f"{e}\n{traceback.format_exc()}", job_id=job_id
        ) | {"duration": duration}


def main() -> int:
    """Main loop: read jobs from stdin, write responses to stdout."""
    # Write startup message to stderr
    print("runner_adapter: ready", file=sys.stderr, flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            job = json.loads(line)
        except json.JSONDecodeError as e:
            response = _infrastructure_response(f"Invalid JSON: {e}")
            print(json.dumps(response), flush=True)
            continue

        response = run_job(job)
        print(json.dumps(response), flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
