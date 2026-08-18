"""Black-box characterization handlers for the Phase 4 QA migration."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from runtime_shared import PROJECT_ROOT, World

FEATURE_ID = "phase4_qa_refresh_migration"

_BASELINE = "9e112ea23a"
_QA_SUITE = PROJECT_ROOT / "acceptance" / "qa" / "acceptance-refresh" / "qa_suite.py"
_GENERATED_ROOT = PROJECT_ROOT / "build" / "acceptance" / "generated"
_IR_ROOT = PROJECT_ROOT / "build" / "acceptance" / "ir"
_DRY_ROOT = PROJECT_ROOT / "build" / "acceptance" / "dry"
_MUTATION_ROOT = PROJECT_ROOT / "build" / "acceptance-mutation"
_QA_TMP_ROOT = PROJECT_ROOT / "tmp" / "qa-phase4-qa-refresh-migration"
_OPT_IN = "SCENARIO_FORGE_QA_PIPELINE"
_ENDPOINT_VARIABLES = (
    "SCENARIO_FORGE_MODEL_BASE_URL",
    "OPENAI_BASE_URL",
    "SCENARIO_FORGE_API_KEY",
    "OPENAI_API_KEY",
)
_REFRESH_FEATURE_COUNTS = {
    "stage1b-entry-point-guidance": 8,
    "stage1b-grounding": 7,
    "stage2-coordination-analysis": 12,
    "stage2-assembly-fallback": 8,
}


def _without_live_opt_in() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop(_OPT_IN, None)
    return environment


def _run(
    argv: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
    timeout: int | float = 3600,
) -> subprocess.CompletedProcess[str]:
    environment = _without_live_opt_in()
    if env is not None:
        environment.update(env)
    return subprocess.run(
        argv,
        cwd=str(cwd),
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _run_qa_suite(
    arguments: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(
        [sys.executable, str(_QA_SUITE), *arguments],
        cwd=cwd,
        env=env,
    )


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}{result.stderr}"


def _check_lines(output: str) -> list[str]:
    return [
        line.strip()
        for line in output.splitlines()
        if re.match(r"^\s+\[(?:PASS|FAIL)\] ", line)
    ]


def _outcome_lines(output: str) -> list[str]:
    return [
        line
        for line in output.splitlines()
        if line.startswith(("PASS ", "FAIL ", "SKIP "))
    ]


def _new_temp_root(world: World) -> Path:
    previous = getattr(world, "p4qrm_tempdir", None)
    if previous is not None:
        previous.cleanup()
    _QA_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    tempdir = tempfile.TemporaryDirectory(
        prefix="run-",
        dir=str(_QA_TMP_ROOT),
    )
    world.p4qrm_tempdir = tempdir
    root = Path(tempdir.name)
    (root / "bin").mkdir()
    (root / "use-case.txt").write_text("phase4 acceptance fixture\n", encoding="utf-8")
    (root / "risks.json").write_text("[]\n", encoding="utf-8")
    (root / "profile.yaml").write_text("profile: phase4\n", encoding="utf-8")
    world.p4qrm_fixture_root = root
    world.p4qrm_invocation_log = root / "invocations.jsonl"
    return root


def _write_pipeline_standin(root: Path, mode: str) -> None:
    script = root / "bin" / "uv"
    script.write_text(
        """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["P4QRM_ROOT"])
argv = sys.argv[1:]
output_dir = None
if "--output-dir" in argv:
    output_dir = Path(argv[argv.index("--output-dir") + 1])
record = {
    "argv": argv,
    "cwd": str(Path.cwd()),
    "mode": os.environ.get("P4QRM_STANDIN_MODE", ""),
    "output_dir": str(output_dir) if output_dir is not None else None,
}
with (root / "invocations.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(record) + "\\n")

if record["mode"] == "failure":
    (root / "stdout.txt").write_text("phase4 stand-in stdout\\n", encoding="utf-8")
    (root / "stderr.txt").write_text("phase4 stand-in stderr\\n", encoding="utf-8")
    print("phase4 stand-in stdout")
    print("phase4 stand-in stderr", file=sys.stderr)
    raise SystemExit(7)

if output_dir is not None:
    output_dir.mkdir(parents=True, exist_ok=True)
    calls = [
        {"stage": "stage_1a", "step": "risk_derivation"},
        {"stage": "stage_1a", "step": "gap_analysis"},
        {"stage": "stage_1b", "step": "capability_profile"},
        {"stage": "stage_2", "step": "call_1_requirements"},
        {"stage": "stage_2", "step": "call_2a_responsibilities"},
        {"stage": "stage_2", "step": "call_2b_control_elements"},
        {"stage": "stage_2", "step": "call_3_coordination"},
    ]
    with (output_dir / "calls.jsonl").open("w", encoding="utf-8") as stream:
        for entry in calls:
            stream.write(json.dumps(entry) + "\\n")
    (output_dir / "run-manifest.yaml").write_text(
        "stage_summary:\\n"
        "  stage_1a:\\n"
        "    call_count: 2\\n"
        "  stage_2:\\n"
        "    call_count: 4\\n",
        encoding="utf-8",
    )
    (output_dir / "control-structure.yaml").write_text(
        "coordination_links: []\\n",
        encoding="utf-8",
    )
""",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


def _fixture_environment(world: World) -> dict[str, str]:
    root = world.p4qrm_fixture_root
    environment = {
        "PATH": f"{root / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
        "P4QRM_ROOT": str(root),
        "P4QRM_STANDIN_MODE": world.p4qrm_standin_mode,
    }
    return environment


def _invocations(world: World) -> list[dict[str, Any]]:
    path = getattr(world, "p4qrm_invocation_log", None)
    if path is None or not path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            entries.append(value)
    return entries


def _input_arguments(world: World) -> list[str]:
    root = world.p4qrm_fixture_root
    return [
        "--use-case",
        str(root / "use-case.txt"),
        "--risk-extraction",
        str(root / "risks.json"),
        "--capability-profile",
        str(root / "profile.yaml"),
    ]


def _cleanup_fixture(world: World) -> None:
    tempdir = getattr(world, "p4qrm_tempdir", None)
    if tempdir is not None:
        tempdir.cleanup()
        world.p4qrm_tempdir = None


class _ContactSentinel:
    """Count local TCP contacts without accepting any application traffic."""

    def __init__(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen()
        self._server.settimeout(0.1)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.count = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.getsockname()
        return f"http://{host}:{port}/v1"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.count += 1
            client.close()

    def close(self) -> int:
        self._stop.set()
        self._server.close()
        self._thread.join(timeout=1)
        return self.count


def _start_sentinel(world: World) -> None:
    _finish_sentinel(world)
    sentinel = _ContactSentinel()
    world.p4qrm_sentinel = sentinel
    for name in _ENDPOINT_VARIABLES:
        os.environ[name] = sentinel.url if "BASE_URL" in name else "phase4-sentinel-key"


def _finish_sentinel(world: World) -> None:
    sentinel = getattr(world, "p4qrm_sentinel", None)
    if sentinel is not None:
        world.p4qrm_endpoint_contacts = sentinel.close()
        world.p4qrm_sentinel = None


def _git_show(path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{_BASELINE}:{path}"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def _git_diff_names(*paths: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{_BASELINE}..HEAD", "--", *paths],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def _status_snapshot() -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def _status_paths(status: str) -> list[str]:
    paths: list[str] = []
    for line in status.splitlines():
        if len(line) < 4:
            continue
        value = line[3:]
        if " -> " in value:
            value = value.rsplit(" -> ", 1)[-1]
        paths.append(value)
    return paths


def _digest(path: Path) -> str:
    if not path.exists():
        return "<missing>"
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    entries = []
    for child in sorted(path.rglob("*")):
        if child.is_file():
            entries.append(
                (
                    child.relative_to(path).as_posix(),
                    hashlib.sha256(child.read_bytes()).hexdigest(),
                )
            )
    return repr(entries)


def _content_snapshot(status: str) -> dict[str, str]:
    return {path: _digest(PROJECT_ROOT / path) for path in _status_paths(status)}


def _scope_is_unchanged() -> tuple[bool, str]:
    paths = (
        ".factory/swarmforge/config.sh",
        "scripts/acceptance.sh",
        "scripts/quality.sh",
        ".gitignore",
    )
    changed = [
        path for path in paths if _git_show(path) != (PROJECT_ROOT / path).read_bytes()
    ]
    src_changes = _git_diff_names("src")
    return (
        not changed and not src_changes,
        f"changed={changed} src={src_changes}",
    )


def _h_baseline(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'commit "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse baseline commit: {text}"
    expected = match.group(1)
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", expected, "HEAD"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0, f"baseline {expected} is not an ancestor of HEAD"


def _h_opt_in_unset(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _OPT_IN not in os.environ, f"{_OPT_IN} is set"


def _h_help(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p4qrm_help_result = _run_qa_suite(["--help"])
    return True, ""


def _h_status_zero(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = getattr(world, "p4qrm_help_result", None)
    if result is None:
        return False, "help was not requested"
    return result.returncode == 0, f"help exited with {result.returncode}"


def _h_help_option(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'help advertises option "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse option: {text}"
    expected = match.group(1)
    output = _output(world.p4qrm_help_result)
    return expected in output, f"help does not contain {expected}"


def _h_help_modes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = _output(world.p4qrm_help_result).replace("\n", " ")
    expected = re.compile(r"\(--static\s*\|\s*--pipeline\s*\|\s*--all\)")
    return bool(expected.search(output)), "required mode group is absent from help"


def _h_success_standin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    world.p4qrm_standin_mode = "success"
    _write_pipeline_standin(root, "success")
    _start_sentinel(world)
    world.p4qrm_runs = []
    world.p4qrm_invocation_counts = []
    return True, ""


def _h_run_mode_twice(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'QA mode "([^"]+)" is run twice', text)
    if match is None:
        return False, f"Could not parse QA mode: {text}"
    mode = match.group(1)
    runs: list[subprocess.CompletedProcess[str]] = []
    counts: list[int] = []
    for _ in range(2):
        before = len(_invocations(world))
        result = _run_qa_suite(
            [mode, *_input_arguments(world)],
            env=_fixture_environment(world),
        )
        after = len(_invocations(world))
        runs.append(result)
        counts.append(after - before)
    world.p4qrm_mode = mode
    world.p4qrm_runs = runs
    world.p4qrm_invocation_counts = counts
    _finish_sentinel(world)
    return True, ""


def _h_runs_successful(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = getattr(world, "p4qrm_runs", None)
    if not runs:
        runs = getattr(world, "p4qrm_nested_runs", [])
    return (
        len(runs) == 2 and all(result.returncode == 0 for result in runs),
        f"run statuses={[result.returncode for result in runs]}",
    )


def _h_checks_once(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = getattr(world, "p4qrm_runs", [])
    if len(runs) != 2:
        return False, "two QA runs were not recorded"
    expected_match = re.search(
        r"QA suite: (\d+) passed, 0 failed",
        str(examples.get("summary", "")),
    )
    expected_count = int(expected_match.group(1)) if expected_match else None
    details = []
    for result in runs:
        lines = _check_lines(_output(result))
        details.append((len(lines), len(set(lines))))
        if (
            expected_count is None
            or len(lines) != expected_count
            or len(lines) != len(set(lines))
            or any("[FAIL]" in line for line in lines)
        ):
            return False, f"check line counts={details}"
    return True, ""


def _h_identical_checks(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = getattr(world, "p4qrm_runs", [])
    if len(runs) != 2:
        return False, "two QA runs were not recorded"
    first = _check_lines(_output(runs[0]))
    second = _check_lines(_output(runs[1]))
    return first == second, "ordered check results differ"


def _h_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'run reports "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse summary: {text}"
    summary = match.group(1)
    return all(_output(result).count(summary) == 1 for result in world.p4qrm_runs), (
        f"summary {summary!r} was not emitted once per run"
    )


def _h_standin_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"invoked (\d+) time per run", text)
    if match is None:
        return False, f"Could not parse stand-in count: {text}"
    expected = int(match.group(1))
    actual = getattr(world, "p4qrm_invocation_counts", [])
    return actual == [expected, expected], f"invocation counts={actual}"


def _h_endpoint_zero(world: World, text: str, examples: dict) -> tuple[bool, str]:
    passed = (
        getattr(world, "p4qrm_endpoint_contacts", -1) == 0,
        f"endpoint contacts={getattr(world, 'p4qrm_endpoint_contacts', None)}",
    )
    _cleanup_fixture(world)
    return passed


def _h_invalid_invocation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    world.p4qrm_standin_mode = "success"
    _write_pipeline_standin(root, "success")
    argument_match = re.search(r'invoked with "([^"]+)"', text)
    if argument_match is None:
        return False, f"Could not parse invocation: {text}"
    raw_arguments = argument_match.group(1)
    arguments = [] if raw_arguments == "none" else shlex.split(raw_arguments)
    world.p4qrm_invalid_result = _run_qa_suite(
        arguments,
        env=_fixture_environment(world),
    )
    return True, ""


def _h_invalid_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"exits with status (\d+)", text)
    if match is None:
        return False, f"Could not parse status: {text}"
    expected = int(match.group(1))
    result = getattr(world, "p4qrm_invalid_result", None)
    if result is None:
        result = getattr(world, "p4qrm_failure_result", None)
    if result is None:
        return False, "no QA result was recorded"
    actual = result.returncode
    return actual == expected, f"actual status={actual}"


def _h_output_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'output contains "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse message: {text}"
    expected = match.group(1)
    return expected in _output(world.p4qrm_invalid_result), (
        f"output does not contain {expected!r}"
    )


def _h_no_pipeline_child(world: World, text: str, examples: dict) -> tuple[bool, str]:
    no_child = not _invocations(world)
    _cleanup_fixture(world)
    return no_child, "pipeline stand-in was invoked"


def _h_failure_standin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    world.p4qrm_standin_mode = "failure"
    _write_pipeline_standin(root, "failure")
    return True, ""


def _h_run_failure_pipeline(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.p4qrm_failure_result = _run_qa_suite(
        ["--pipeline", *_input_arguments(world)],
        env=_fixture_environment(world),
    )
    world.p4qrm_failure_invocations = _invocations(world)
    return True, ""


def _failure_invocation(world: World) -> dict[str, Any] | None:
    entries = getattr(world, "p4qrm_failure_invocations", [])
    return entries[0] if entries else None


def _h_failure_arguments(world: World, text: str, examples: dict) -> tuple[bool, str]:
    invocation = _failure_invocation(world)
    if invocation is None:
        return False, "pipeline stand-in did not receive an invocation"
    argv = invocation.get("argv", [])
    root = world.p4qrm_fixture_root
    required = [
        "--use-case",
        str(root / "use-case.txt"),
        "--risk-extraction",
        str(root / "risks.json"),
        "--profile",
        str(root / "profile.yaml"),
    ]
    return (
        argv[:3] == ["run", "scenario-forge", "stpa-run"]
        and all(value in argv for value in required)
        and "--output-dir" in argv,
        f"stand-in argv={argv}",
    )


def _h_failure_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    invocation = _failure_invocation(world)
    return (
        invocation is not None and invocation.get("cwd") == str(PROJECT_ROOT),
        f"stand-in cwd={invocation.get('cwd') if invocation else None}",
    )


def _h_failure_streams(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = world.p4qrm_failure_result
    invocation = _failure_invocation(world)
    return (
        invocation is not None
        and invocation.get("mode") == "failure"
        and result.returncode == 1
        and (world.p4qrm_fixture_root / "stdout.txt").read_text(encoding="utf-8")
        == "phase4 stand-in stdout\n"
        and (world.p4qrm_fixture_root / "stderr.txt").read_text(encoding="utf-8")
        == "phase4 stand-in stderr\n",
        "pipeline failure streams were not preserved",
    )


def _h_failure_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'QA command reports "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse failure summary: {text}"
    return match.group(1) in _output(world.p4qrm_failure_result), (
        f"missing failure summary in {_output(world.p4qrm_failure_result)!r}"
    )


def _h_failure_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.p4qrm_failure_result.returncode == 1,
        f"QA suite status={world.p4qrm_failure_result.returncode}",
    )


def _h_parent_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    environment = getattr(world, "p4qrm_parent_environment", None)
    cwd = getattr(world, "p4qrm_parent_cwd", None)
    if environment is None:
        environment = getattr(world, "aqrc_parent_environment", None)
        cwd = getattr(world, "aqrc_parent_cwd", None)
    if environment is None or cwd is None:
        return False, "parent environment and working directory were not recorded"
    return (
        dict(os.environ) == environment and Path.cwd() == cwd,
        "parent process state changed",
    )


def _h_parent_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p4qrm_parent_environment = dict(os.environ)
    world.p4qrm_parent_cwd = Path.cwd()
    return True, ""


def _h_failure_output_removed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    invocation = _failure_invocation(world)
    output_dir = Path(invocation["output_dir"]) if invocation else None
    removed = output_dir is not None and not output_dir.exists()
    _cleanup_fixture(world)
    return removed, f"temporary output exists: {output_dir}"


def _h_nested_invocation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _QA_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    tempdir = tempfile.TemporaryDirectory(prefix="nested-", dir=str(_QA_TMP_ROOT))
    nested = Path(tempdir.name) / "a" / "b"
    nested.mkdir(parents=True)
    world.p4qrm_nested_tempdir = tempdir
    world.p4qrm_nested_cwd = nested
    world.p4qrm_caller_cwd = Path.cwd()
    return True, ""


def _h_nested_static(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = [
        _run_qa_suite(["--static"], cwd=world.p4qrm_nested_cwd),
        _run_qa_suite(["--static"], cwd=world.p4qrm_nested_cwd),
    ]
    world.p4qrm_nested_runs = runs
    return True, ""


def _h_nested_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p4qrm_nested_runs
    return (
        len(runs) == 2
        and all(
            result.returncode == 0
            and "QA suite: 519 passed, 0 failed" in _output(result)
            for result in runs
        ),
        f"nested statuses={[result.returncode for result in runs]}",
    )


def _h_nested_same(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p4qrm_nested_runs
    return (
        _check_lines(_output(runs[0])) == _check_lines(_output(runs[1])),
        "nested check order differs",
    )


def _h_nested_cwd_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    unchanged = Path.cwd() == world.p4qrm_caller_cwd
    world.p4qrm_nested_tempdir.cleanup()
    return unchanged, "caller working directory changed"


def _generated_test_path(source_feature: str) -> Path:
    return _GENERATED_ROOT / f"{Path(source_feature).stem}_acceptance_test.py"


def _h_source_generated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'source feature "([^"]+)" is generated', text)
    if match is None:
        return False, f"Could not parse source feature: {text}"
    source_feature = match.group(1)
    feature = PROJECT_ROOT / "features" / source_feature
    generated = _generated_test_path(source_feature)
    world.p4qrm_source_feature = source_feature
    world.p4qrm_source_test = generated
    # The acceptance-refresh cleanup feature shares this Given step. Retain
    # its observable state names when this handler wins the overlap.
    world.aqrc_source_feature = source_feature
    world.aqrc_source_test = generated
    return (
        feature.is_file() and generated.is_file(),
        f"missing feature={feature} generated={generated}",
    )


def _h_endpoint_configuration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _start_sentinel(world)
    return True, ""


def _h_run_generated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = [
        _run(
            [sys.executable, "-m", "pytest", str(world.p4qrm_source_test), "-q", "-s"],
            timeout=600,
        ),
        _run(
            [sys.executable, "-m", "pytest", str(world.p4qrm_source_test), "-q", "-s"],
            timeout=600,
        ),
    ]
    world.p4qrm_source_runs = result
    return True, ""


def _h_source_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"exactly (\d+) distinct scenarios as PASS", text)
    if match is None:
        return False, f"Could not parse scenario count: {text}"
    expected = int(match.group(1))
    actual = []
    for result in world.p4qrm_source_runs:
        names = {
            line.split("/example_", 1)[0]
            for line in result.stdout.splitlines()
            if line.startswith("PASS ")
        }
        actual.append((result.returncode, len(names)))
    return all(status == 0 and count == expected for status, count in actual), (
        f"source counts={actual}"
    )


def _h_source_no_failures(world: World, text: str, examples: dict) -> tuple[bool, str]:
    failures = [
        line
        for result in world.p4qrm_source_runs
        for line in _outcome_lines(result.stdout)
        if line.startswith(("FAIL ", "SKIP "))
    ]
    return not failures, f"source failures={failures}"


def _h_source_same(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p4qrm_source_runs
    same = _outcome_lines(runs[0].stdout) == _outcome_lines(runs[1].stdout)
    _finish_sentinel(world)
    return same, "generated scenario outcomes differ"


def _h_change_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p4qrm_qa_changes = _git_diff_names("acceptance/qa")
    return True, ""


def _h_only_refresh_suite(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = "acceptance/qa/acceptance-refresh/qa_suite.py"
    suites = [path for path in world.p4qrm_qa_changes if path.endswith("/qa_suite.py")]
    return suites == [expected], f"changed suites={suites}"


def _h_other_suites(world: World, text: str, examples: dict) -> tuple[bool, str]:
    current = sorted(
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "acceptance" / "qa").rglob("qa_suite.py")
    )
    baseline = [
        path
        for path in _git_tree_paths("acceptance/qa")
        if path.endswith("/qa_suite.py")
    ]
    excluded = "acceptance/qa/acceptance-refresh/qa_suite.py"
    current = [path for path in current if path != excluded]
    baseline = [path for path in baseline if path != excluded]
    common = sorted(set(current) & set(baseline))
    return (
        all(_git_show(path) == (PROJECT_ROOT / path).read_bytes() for path in common),
        f"suite sets differ: current={current} baseline={baseline}",
    )


def _git_tree_paths(root: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", _BASELINE, "--", root],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def _h_harness_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    path = "acceptance/qa/qa_harness.py"
    return _git_show(path) == (PROJECT_ROOT / path).read_bytes(), f"{path} changed"


def _h_refresh_registration_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    path = "acceptance/runtime_features/acceptance_refresh.py"
    return _git_show(path) == (PROJECT_ROOT / path).read_bytes(), f"{path} changed"


def _h_no_src_changes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    changes = _git_diff_names("src")
    return not changes, f"source changes={changes}"


def _h_config_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    unchanged, detail = _scope_is_unchanged()
    return unchanged, detail


def _h_worktree_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    status = _status_snapshot()
    world.p4qrm_status_before = status
    world.p4qrm_content_before = _content_snapshot(status)
    return True, ""


def _h_run_hygiene(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if os.environ.get("P4QRM_HYGIENE_CHILD") == "1":
        world.p4qrm_hygiene_result = subprocess.CompletedProcess(
            ["phase4-hygiene-child"], 0, "", ""
        )
        return True, ""
    result = _run_qa_suite(["--static"])
    generated_test = _generated_test_path("phase4_qa_refresh_migration.feature")
    child_environment = dict(os.environ)
    child_environment["P4QRM_HYGIENE_CHILD"] = "1"
    generated_result = _run(
        [sys.executable, "-m", "pytest", str(generated_test), "-q", "-s"],
        env=child_environment,
        timeout=600,
    )
    world.p4qrm_hygiene_result = result
    world.p4qrm_generated_result = generated_result
    return (
        result.returncode == 0 and generated_result.returncode == 0,
        f"migrated suite status={result.returncode}, generated status={generated_result.returncode}",
    )


def _h_artifacts_untracked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    tracked = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "build/acceptance",
            "build/acceptance-mutation",
            "tmp/qa-phase4-qa-refresh-migration",
            "coverage.lcov",
            "lcov.info",
            "lcov_stpa_report.info",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return not tracked.stdout.strip(), f"tracked generated files={tracked.stdout}"


def _h_generated_paths(world: World, text: str, examples: dict) -> tuple[bool, str]:
    allowed = (_IR_ROOT, _DRY_ROOT, _GENERATED_ROOT, _MUTATION_ROOT)
    offenders = []
    for root in (PROJECT_ROOT / "build" / "acceptance", _MUTATION_ROOT):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if not any(path.is_relative_to(base) for base in allowed):
                offenders.append(str(path))
    return not offenders, f"generated path offenders={offenders}"


def _h_metadata_relative(world: World, text: str, examples: dict) -> tuple[bool, str]:
    metadata_root = _GENERATED_ROOT / "metadata"
    offenders = []
    for path in metadata_root.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            offenders.append(str(path))
            continue
        values = [value for value in data.values() if isinstance(value, str)]
        if any(
            Path(value).is_absolute() or str(PROJECT_ROOT) in value for value in values
        ):
            offenders.append(str(path))
    return not offenders, f"absolute metadata paths={offenders}"


def _h_scope_stable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _scope_is_unchanged()


def _h_worktree_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    after = _status_snapshot()
    before_content = world.p4qrm_content_before
    after_content = _content_snapshot(after)
    return (
        after == world.p4qrm_status_before and after_content == before_content,
        "unrelated worktree status or content changed",
    )


def register(api: object) -> None:
    """Register Phase 4 characterization steps in one global scope."""
    api.set_feature(None)
    api.register(r'the Phase 4 migration baseline is commit "([^"]+)"', _h_baseline)
    api.register(r"live endpoint opt-in is unset", _h_opt_in_unset)
    api.register(r"acceptance-refresh QA help is requested", _h_help)
    api.register(r"acceptance-refresh QA exits with status 0", _h_status_zero)
    api.register(r'help advertises option "([^"]+)"', _h_help_option)
    api.register(
        r'help identifies "--static", "--pipeline", and "--all" as required mutually exclusive modes',
        _h_help_modes,
    )
    api.register(
        r"a successful local pipeline stand-in supplies the characterized acceptance-refresh artifacts",
        _h_success_standin,
    )
    api.register(
        r'acceptance-refresh QA mode "([^"]+)" is run twice with all input options',
        _h_run_mode_twice,
    )
    api.register(r"both runs exit with status 0", _h_runs_successful)
    api.register(
        r"each recorded check is emitted once in recording order", _h_checks_once
    )
    api.register(r"both runs have identical ordered check results", _h_identical_checks)
    api.register(r'each run reports "([^"]+)"', _h_summary)
    api.register(
        r"the pipeline stand-in is invoked (\d+) time per run", _h_standin_count
    )
    api.register(r"the endpoint contact count remains 0", _h_endpoint_zero)
    api.register(
        r'acceptance-refresh QA is invoked with "([^"]+)"', _h_invalid_invocation
    )
    api.register(r"acceptance-refresh QA exits with status \d+", _h_invalid_status)
    api.register(r'output contains "([^"]+)"', _h_output_contains)
    api.register(r"no pipeline child is started", _h_no_pipeline_child)
    api.register(
        r"a local pipeline stand-in emits distinct standard output and standard error and exits with status 7",
        _h_failure_standin,
    )
    api.register(
        r"the parent environment and working directory are recorded",
        _h_parent_recorded,
    )
    api.register(
        r'acceptance-refresh QA is run in "--pipeline" mode with all input options',
        _h_run_failure_pipeline,
    )
    api.register(
        r"the pipeline child receives the documented stpa-run arguments",
        _h_failure_arguments,
    )
    api.register(r"the pipeline child runs from the repository root", _h_failure_root)
    api.register(
        r"its exit status, standard output, and standard error remain separately observable",
        _h_failure_streams,
    )
    api.register(r'QA command reports "([^"]+)"', _h_failure_summary)
    api.register(r"acceptance-refresh QA exits with status 1", _h_failure_status)
    api.register_first(
        r"^the parent environment and working directory remain unchanged$",
        _h_parent_unchanged,
    )
    api.register(
        r"temporary pipeline output is removed after the run",
        _h_failure_output_removed,
    )
    api.register(
        r"acceptance-refresh QA is invoked by absolute path from a nested temporary directory",
        _h_nested_invocation,
    )
    api.register(r'"--static" mode is run twice', _h_nested_static)
    api.register(r"both runs discover the repository root", _h_nested_root)
    api.register(
        r'both runs emit the same ordered checks and "QA suite: 519 passed, 0 failed"',
        _h_nested_same,
    )
    api.register(
        r"neither run changes the caller working directory",
        _h_nested_cwd_unchanged,
    )
    api.register_first(
        r'^the acceptance-refresh source feature "([^"]+)" is generated$',
        _h_source_generated,
    )
    api.register(
        r"endpoint URLs target a local contact sentinel", _h_endpoint_configuration
    )
    api.register_first(
        r"its generated acceptance test is run twice with live opt-in unset",
        _h_run_generated,
    )
    api.register(
        r"each run reports exactly \d+ distinct scenarios as PASS",
        _h_source_count,
    )
    api.register(
        r"neither run reports an acceptance-refresh scenario as FAIL or SKIP",
        _h_source_no_failures,
    )
    api.register(r"both runs report the same ordered scenario outcomes", _h_source_same)
    api.register(
        r"the migration change set is compared with the Phase 4 migration baseline",
        _h_change_set,
    )
    api.register(
        r'"acceptance/qa/acceptance-refresh/qa_suite.py" is the only existing QA suite changed',
        _h_only_refresh_suite,
    )
    api.register(
        r"every other existing QA suite is byte-for-byte unchanged",
        _h_other_suites,
    )
    api.register(
        r"the shared QA harness is byte-for-byte unchanged", _h_harness_unchanged
    )
    api.register(
        r"acceptance-refresh runtime registration is byte-for-byte unchanged",
        _h_refresh_registration_unchanged,
    )
    api.register_first(
        r'^no production path beneath "src/" is added, modified, or deleted$',
        _h_no_src_changes,
    )
    api.register(
        r"acceptance configuration and generation commands are byte-for-byte unchanged",
        _h_config_unchanged,
    )
    api.register(
        r"the complete unrelated worktree status and content are recorded",
        _h_worktree_recorded,
    )
    api.register(
        r"the migrated suite and generated Phase 4 acceptance test are run",
        _h_run_hygiene,
    )
    api.register(
        r"IR, dry reports, generated tests, metadata, coverage, mutation, and QA capture artifacts remain untracked",
        _h_artifacts_untracked,
    )
    api.register(
        r"generated artifacts remain within their configured generated-output paths",
        _h_generated_paths,
    )
    api.register(
        r"generated metadata contains no absolute checkout path", _h_metadata_relative
    )
    api.register(
        r"no source-analysis or generated-output scope changes", _h_scope_stable
    )
    api.register(
        r"every unrelated worktree path retains its original status and content",
        _h_worktree_unchanged,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
