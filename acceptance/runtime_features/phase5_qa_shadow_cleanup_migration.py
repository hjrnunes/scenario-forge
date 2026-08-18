"""Black-box acceptance handlers for the Phase 5 shadow-cleanup migration."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from runtime_shared import PROJECT_ROOT, World

FEATURE_ID = "phase5_qa_shadow_cleanup_migration"
_BASELINE = "5a79d55b35"
_OPT_IN = "SCENARIO_FORGE_QA_PIPELINE"
_QA_ROOT = PROJECT_ROOT / "tmp" / "qa-phase5-shadow-cleanup-migration"
_QA_SUITE = PROJECT_ROOT / "acceptance" / "qa" / "shadow-cleanup" / "qa_suite.py"
_INDEPENDENT_PHASE4_SUITE = "acceptance/qa/phase4-qa-refresh-migration/qa_suite.py"
_SHADOW_RUNTIME = "acceptance/runtime_features/shadow_cleanup.py"
_PROPERTY_TEST = PROJECT_ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"
_GENERATED_ROOT = PROJECT_ROOT / "build" / "acceptance" / "generated"
_IR_ROOT = PROJECT_ROOT / "build" / "acceptance" / "ir"
_DRY_ROOT = PROJECT_ROOT / "build" / "acceptance" / "dry"
_MUTATION_ROOT = PROJECT_ROOT / "build" / "acceptance-mutation"
_SCENARIO_NODE_IDS = [
    f"{_PROPERTY_TEST}::TestNoPatternShadowing::"
    "test_no_global_pattern_conflicts_on_ir_steps",
    f"{_PROPERTY_TEST}::TestNoPatternShadowing::"
    "test_no_global_pattern_conflicts_on_synthetic_steps",
]


def _run(
    argv: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: Mapping[str, str] | None = None,
    timeout: int | float = 600,
) -> subprocess.CompletedProcess[str]:
    """Run a child process without inheriting live-LLM authorization."""
    environment = dict(os.environ)
    environment.pop(_OPT_IN, None)
    if env is not None:
        environment.update(env)
        environment.pop(_OPT_IN, None)
    return subprocess.run(
        argv,
        cwd=str(cwd),
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _run_qa(
    arguments: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(
        [sys.executable, str(_QA_SUITE), *arguments],
        cwd=cwd,
        env=env,
        timeout=1200,
    )


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}{result.stderr}"


def _check_lines(output: str) -> list[str]:
    return [
        line.strip()
        for line in output.splitlines()
        if re.match(r"^\s+\[(?:PASS|FAIL|SKIP)\] ", line)
    ]


def _outcome_lines(output: str) -> list[str]:
    return [
        line
        for line in output.splitlines()
        if line.startswith(("PASS ", "FAIL ", "SKIP "))
    ]


def _new_temp_root(world: World) -> Path:
    previous = getattr(world, "p5_tempdir", None)
    if previous is not None:
        previous.cleanup()
    _QA_ROOT.mkdir(parents=True, exist_ok=True)
    tempdir = tempfile.TemporaryDirectory(prefix="run-", dir=str(_QA_ROOT))
    root = Path(tempdir.name)
    world.p5_tempdir = tempdir
    world.p5_fixture_root = root
    return root


def _cleanup_temp_root(world: World) -> None:
    tempdir = getattr(world, "p5_tempdir", None)
    if tempdir is not None:
        tempdir.cleanup()
        world.p5_tempdir = None


class _ContactSentinel:
    """Count local TCP contacts while never serving an endpoint response."""

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
                client, _address = self._server.accept()
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
    world.p5_sentinel = sentinel
    names = (
        "SCENARIO_FORGE_MODEL_BASE_URL",
        "OPENAI_BASE_URL",
        "SCENARIO_FORGE_API_KEY",
        "OPENAI_API_KEY",
    )
    world.p5_endpoint_environment = {name: os.environ.get(name) for name in names}
    for name in names:
        os.environ[name] = sentinel.url if "BASE_URL" in name else "phase5-sentinel-key"


def _finish_sentinel(world: World) -> None:
    sentinel = getattr(world, "p5_sentinel", None)
    if sentinel is not None:
        world.p5_endpoint_contacts = sentinel.close()
        world.p5_sentinel = None
    original = getattr(world, "p5_endpoint_environment", None)
    if original is not None:
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        world.p5_endpoint_environment = None


def _h_baseline(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'commit "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse baseline commit: {text}"
    baseline = match.group(1)
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", baseline, "HEAD"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        check=False,
    )
    return result.returncode == 0, f"baseline {baseline} is not an ancestor of HEAD"


def _h_opt_in_unset(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p5_endpoint_contacts = 0
    return _OPT_IN not in os.environ, f"{_OPT_IN} is set"


def _h_help(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p5_help_result = _run_qa(["--help"])
    return True, ""


def _h_status_zero(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = getattr(world, "p5_help_result", None)
    if result is None:
        return False, "help was not requested"
    return result.returncode == 0, f"help exited with {result.returncode}"


def _h_help_option(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'option "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse option: {text}"
    option = match.group(1)
    return option in _output(world.p5_help_result), f"help does not contain {option}"


def _h_help_modes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = _output(world.p5_help_result)
    options = ("--static", "--dynamic", "--pipeline", "--all")
    independent = all(option in output for option in options)
    grouped = re.search(r"\{--static|--dynamic.*--pipeline.*--all\}", output)
    return independent and grouped is None, "mode options are not independently listed"


def _h_run_twice(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'invocation "([^"]+)" is run twice', text)
    if match is None:
        return False, f"Could not parse invocation: {text}"
    raw_arguments = match.group(1)
    arguments = [] if raw_arguments == "none" else shlex.split(raw_arguments)
    world.p5_runs = [_run_qa(arguments), _run_qa(arguments)]
    try:
        world.p5_expected_counts = tuple(
            int(examples[name]) for name in ("passed", "failed", "skipped")
        )
    except (KeyError, TypeError, ValueError):
        world.p5_expected_counts = None
    return True, ""


def _h_runs_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"both shadow-cleanup runs exit with status (\d+)", text)
    if match is None:
        return False, f"Could not parse status: {text}"
    expected = int(match.group(1))
    runs = getattr(world, "p5_runs", None) or getattr(world, "p5_nested_runs", [])
    actual = [result.returncode for result in runs]
    return actual == [expected, expected], f"run statuses={actual}"


def _h_checks_once(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = world.p5_expected_counts
    if expected is None:
        return False, "expected result counts were not supplied by the example"
    total = sum(expected)
    details = []
    for result in world.p5_runs:
        lines = _check_lines(_output(result))
        details.append((len(lines), len(set(lines))))
        if len(lines) != total or len(lines) != len(set(lines)):
            return False, f"check line counts={details}"
    return True, ""


def _h_identical_results(world: World, text: str, examples: dict) -> tuple[bool, str]:
    first, second = (_check_lines(_output(result)) for result in world.p5_runs)
    return first == second, "ordered check results differ"


def _h_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'reports "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse summary: {text}"
    expected = match.group(1)
    return all(_output(result).count(expected) == 1 for result in world.p5_runs), (
        f"summary {expected!r} was not emitted once per run"
    )


def _h_result_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"emits (\d+) PASS, (\d+) FAIL, and (\d+) SKIP", text)
    if match is None:
        return False, f"Could not parse result counts: {text}"
    expected = tuple(int(value) for value in match.groups())
    actual = []
    for result in world.p5_runs:
        lines = _check_lines(_output(result))
        actual.append(
            (
                sum("[PASS]" in line for line in lines),
                sum("[FAIL]" in line for line in lines),
                sum("[SKIP]" in line for line in lines),
            )
        )
    return all(counts == expected for counts in actual), f"result counts={actual}"


def _h_endpoint_zero(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        getattr(world, "p5_endpoint_contacts", 0) == 0,
        f"endpoint contacts={getattr(world, 'p5_endpoint_contacts', None)}",
    )


def _h_invalid_invocation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'invalid arguments "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse invalid arguments: {text}"
    world.p5_invalid_result = _run_qa(shlex.split(match.group(1)))
    return True, ""


def _h_invalid_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = getattr(world, "p5_invalid_result", None)
    match = re.search(r"exits with status (\d+)", text)
    if result is None or match is None:
        return False, "invalid invocation was not recorded"
    return result.returncode == int(
        match.group(1)
    ), f"actual status={result.returncode}"


def _h_invalid_output(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'output contains "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse message: {text}"
    expected = match.group(1)
    return expected in _output(world.p5_invalid_result), f"missing {expected!r}"


def _h_no_check_or_child(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = _output(world.p5_invalid_result)
    started = any(
        marker in output for marker in ("[PASS]", "[FAIL]", "[SKIP]", "QA suite:")
    )
    return not started, "a check or child process was started"


def _h_child_standin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    standin = root / "pytest.py"
    world.p5_child_log = root / "child.json"
    standin.write_text(
        """import json
import os
import sys
from pathlib import Path

Path(os.environ["P5QSCM_CHILD_LOG"]).write_text(
    json.dumps(
        {
            "argv": sys.argv[1:],
            "cwd": os.getcwd(),
            "environment": {
                "SCENARIO_FORGE_QA_PIPELINE": os.environ.get(
                    "SCENARIO_FORGE_QA_PIPELINE"
                ),
                "P5QSCM_CHILD_MARKER": os.environ.get("P5QSCM_CHILD_MARKER"),
            },
        }
    ),
    encoding="utf-8",
)
print("P5-CHILD-STDOUT")
print("P5-CHILD-STDERR", file=sys.stderr)
raise SystemExit(7)
""",
        encoding="utf-8",
    )
    return True, ""


def _h_parent_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p5_parent_environment = dict(os.environ)
    world.p5_parent_cwd = Path.cwd()
    return True, ""


def _h_run_child_standin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = world.p5_fixture_root
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(root), environment.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    environment["P5QSCM_CHILD_LOG"] = str(world.p5_child_log)
    environment["P5QSCM_CHILD_MARKER"] = "present"
    world.p5_child_result = _run_qa(["--dynamic"], env=environment)
    return True, ""


def _child_record(world: World) -> dict[str, Any] | None:
    path = getattr(world, "p5_child_log", None)
    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _h_child_argv(world: World, text: str, examples: dict) -> tuple[bool, str]:
    record = _child_record(world)
    if record is None:
        return False, "property-test stand-in did not start"
    argv = record.get("argv", [])
    expected = [
        *_SCENARIO_NODE_IDS,
        "-v",
        "--tb=short",
        "--no-header",
        "-p",
        "no:cacheprovider",
    ]
    return argv == expected, f"child argv={argv!r}"


def _h_child_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    record = _child_record(world)
    return (
        record is not None and record.get("cwd") == str(PROJECT_ROOT),
        f"child record={record}",
    )


def _h_child_streams(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = _output(world.p5_child_result)
    return (
        "rc=7" in output
        and "stdout=" in output
        and "stderr=" in output
        and "P5-CHILD-STDOUT" in output
        and "P5-CHILD-STDERR" in output
        and world.p5_child_result.returncode == 1,
        "child streams or status were not separately observable",
    )


def _h_child_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'reports "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse child summary: {text}"
    return match.group(1) in _output(world.p5_child_result), "missing child summary"


def _h_child_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.p5_child_result.returncode == 1,
        f"QA suite status={world.p5_child_result.returncode}",
    )


def _h_parent_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    unchanged = (
        dict(os.environ) == world.p5_parent_environment
        and Path.cwd() == world.p5_parent_cwd
    )
    _cleanup_temp_root(world)
    return unchanged, "parent process state changed"


def _h_nested_invocation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = _new_temp_root(world)
    nested = root / "nested" / "a" / "b"
    nested.mkdir(parents=True)
    world.p5_nested_cwd = nested
    world.p5_caller_cwd = Path.cwd()
    return True, ""


def _h_nested_static(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p5_nested_runs = [
        _run_qa(["--static"], cwd=world.p5_nested_cwd),
        _run_qa(["--static"], cwd=world.p5_nested_cwd),
    ]
    return True, ""


def _h_nested_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    statuses = [result.returncode for result in world.p5_nested_runs]
    return statuses == [1, 1], f"nested statuses={statuses}"


def _h_nested_results(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p5_nested_runs
    expected = 'same ordered results and "QA suite: 50 passed, 1 failed"'
    return (
        len(runs) == 2
        and all("QA suite: 50 passed, 1 failed" in _output(run) for run in runs)
        and _check_lines(_output(runs[0])) == _check_lines(_output(runs[1])),
        f"nested result mismatch ({expected})",
    )


def _h_nested_cwd(world: World, text: str, examples: dict) -> tuple[bool, str]:
    unchanged = Path.cwd() == world.p5_caller_cwd
    _cleanup_temp_root(world)
    return unchanged, "caller working directory changed"


def _generated_test_path(source_feature: str) -> Path:
    return _GENERATED_ROOT / f"{Path(source_feature).stem}_acceptance_test.py"


def _h_source_generated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'source feature "([^"]+)" is generated', text)
    if match is None:
        return False, f"Could not parse source feature: {text}"
    source = match.group(1)
    feature = PROJECT_ROOT / "features" / source
    generated = _generated_test_path(source)
    world.p5_source_test = generated
    return (
        feature.is_file() and generated.is_file(),
        f"missing feature={feature} generated={generated}",
    )


def _h_endpoint_configuration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _start_sentinel(world)
    return True, ""


def _h_run_source(world: World, text: str, examples: dict) -> tuple[bool, str]:
    command = [sys.executable, "-m", "pytest", str(world.p5_source_test), "-q", "-s"]
    world.p5_source_runs = [_run(command), _run(command)]
    return True, ""


def _h_source_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"exactly (\d+) distinct shadow-cleanup scenarios as PASS", text)
    if match is None:
        return False, f"Could not parse scenario count: {text}"
    expected = int(match.group(1))
    actual = []
    for result in world.p5_source_runs:
        names = {
            line.split("/example_", 1)[0]
            for line in _outcome_lines(result.stdout)
            if line.startswith("PASS ShadowCleanup-")
        }
        actual.append((result.returncode, len(names)))
    return all(status == 0 and count == expected for status, count in actual), (
        f"source counts={actual}"
    )


def _h_source_no_failures(world: World, text: str, examples: dict) -> tuple[bool, str]:
    failures = [
        line
        for result in world.p5_source_runs
        for line in _outcome_lines(_output(result))
        if line.startswith(("FAIL ShadowCleanup-", "SKIP ShadowCleanup-"))
    ]
    return not failures, f"shadow-cleanup failures={failures}"


def _h_source_same(world: World, text: str, examples: dict) -> tuple[bool, str]:
    runs = world.p5_source_runs
    same = _outcome_lines(runs[0].stdout) == _outcome_lines(runs[1].stdout)
    _finish_sentinel(world)
    return same, "generated scenario outcomes differ"


def _git_show(ref: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def _git_diff_names(ref: str, *paths: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{ref}..HEAD", "--", *paths],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def _git_tree_paths(ref: str, root: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "--", root],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def _h_change_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.p5_qa_changes = _git_diff_names(_BASELINE, "acceptance/qa")
    return True, ""


def _h_only_shadow_suite(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = "acceptance/qa/shadow-cleanup/qa_suite.py"
    changed_suites = (
        [expected] if _git_show(_BASELINE, expected) != _QA_SUITE.read_bytes() else []
    )
    return changed_suites == [expected], f"changed suites={changed_suites}"


def _h_other_suites(world: World, text: str, examples: dict) -> tuple[bool, str]:
    baseline = {
        path
        for path in _git_tree_paths(_BASELINE, "acceptance/qa")
        if path.endswith("/qa_suite.py")
    }
    current = {
        path
        for path in _git_tree_paths("HEAD", "acceptance/qa")
        if path.endswith("/qa_suite.py")
    }
    expected = "acceptance/qa/shadow-cleanup/qa_suite.py"
    independently_characterized = {expected, _INDEPENDENT_PHASE4_SUITE}
    common = (baseline & current) - independently_characterized
    unchanged = all(
        _git_show(_BASELINE, path) == _git_show("HEAD", path) for path in common
    )
    return unchanged and baseline - current == set(), (
        f"baseline-only suites={sorted(baseline - current)}"
    )


def _h_shadow_runtime_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    baseline = _git_show(_BASELINE, _SHADOW_RUNTIME)
    current = _git_show("HEAD", _SHADOW_RUNTIME)
    return baseline is not None and baseline == current, "shadow_cleanup.py changed"


def _registration_signature(source: bytes) -> tuple[Any, ...]:
    tree = ast.parse(source.decode("utf-8"))
    feature_id = None
    entries: list[tuple[str, str, str | None, int | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "FEATURE_ID":
                    if isinstance(node.value, ast.Constant):
                        feature_id = node.value.value
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"register", "register_first"}
            and len(node.args) >= 2
        ):
            continue
        pattern = ast.literal_eval(node.args[0])
        handler = ast.unparse(node.args[1])
        source_order = None
        for keyword in node.keywords:
            if keyword.arg == "source_order":
                source_order = ast.literal_eval(keyword.value)
        entries.append((node.func.attr, pattern, handler, source_order))
    return feature_id, tuple(sorted(entries, key=lambda entry: entry[3] or 0))


def _h_shadow_registration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    baseline = _git_show(_BASELINE, _SHADOW_RUNTIME)
    current = _git_show("HEAD", _SHADOW_RUNTIME)
    if baseline is None or current is None:
        return False, "shadow-cleanup runtime feature is missing"
    try:
        signature = _registration_signature(current)
        baseline_signature = _registration_signature(baseline)
    except (SyntaxError, TypeError, ValueError):
        return False, "could not inspect shadow-cleanup registration"
    return (
        signature == baseline_signature
        and signature[0] == "shadow_cleanup"
        and all(entry[3] is not None for entry in signature[1]),
        "shadow-cleanup identity, registration, or source priorities changed",
    )


def _h_no_src_changes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    changes = _git_diff_names(_BASELINE, "src")
    return not changes, f"source changes={changes}"


def _h_config_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    paths = (
        ".factory/swarmforge/config.sh",
        "scripts/acceptance.sh",
        "scripts/quality.sh",
        ".gitignore",
    )
    changed = [
        path for path in paths if _git_show(_BASELINE, path) != _git_show("HEAD", path)
    ]
    return not changed, f"changed configuration={changed}"


def _status_snapshot() -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def _status_paths(status: str) -> list[str]:
    paths = []
    for line in status.splitlines():
        if len(line) >= 4:
            paths.append(line[3:].rsplit(" -> ", 1)[-1])
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


def _h_worktree_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    status = _status_snapshot()
    world.p5_status_before = status
    world.p5_content_before = _content_snapshot(status)
    return True, ""


def _h_run_hygiene(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if os.environ.get("P5QSCM_HYGIENE_CHILD") == "1":
        return True, ""
    static = _run_qa(["--static"])
    generated = _generated_test_path("phase5_qa_shadow_cleanup_migration.feature")
    environment = dict(os.environ)
    environment["P5QSCM_HYGIENE_CHILD"] = "1"
    generated_result = _run(
        [sys.executable, "-m", "pytest", str(generated), "-q", "-s"],
        env=environment,
        timeout=1200,
    )
    world.p5_hygiene_results = (static, generated_result)
    return (
        static.returncode == 1
        and "QA suite: 50 passed, 1 failed" in _output(static)
        and generated_result.returncode == 0,
        f"migrated suite status={static.returncode}, generated status={generated_result.returncode}",
    )


def _h_artifacts_untracked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "build/acceptance",
            "build/acceptance-mutation",
            str(_QA_ROOT.relative_to(PROJECT_ROOT)),
            "coverage.lcov",
            "lcov.info",
            "lcov_stpa_report.info",
        ],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return not result.stdout.strip(), f"tracked generated files={result.stdout}"


def _h_generated_paths(world: World, text: str, examples: dict) -> tuple[bool, str]:
    allowed = (_IR_ROOT, _DRY_ROOT, _GENERATED_ROOT, _MUTATION_ROOT)
    offenders = []
    for root in (PROJECT_ROOT / "build" / "acceptance", _MUTATION_ROOT):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and not any(
                path.is_relative_to(base) for base in allowed
            ):
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
    return _h_no_src_changes(world, text, examples)[0] and _h_config_unchanged(
        world, text, examples
    )[0], "source-analysis or generated-output scope changed"


def _h_worktree_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    after = _status_snapshot()
    unchanged = (
        after == world.p5_status_before
        and _content_snapshot(after) == world.p5_content_before
    )
    return unchanged, "unrelated worktree status or content changed"


def register(api: object) -> None:
    """Register Phase 5 handlers in their own feature scope."""
    api.set_feature(FEATURE_ID)
    api.register_first(
        r'the Phase 5 migration baseline is commit "([^"]+)"',
        _h_baseline,
        source_order=24001,
    )
    api.register_first(
        r"live endpoint opt-in is unset for shadow-cleanup QA",
        _h_opt_in_unset,
        source_order=24002,
    )
    api.register_first(
        r"shadow-cleanup QA help is requested", _h_help, source_order=24003
    )
    api.register_first(
        r"shadow-cleanup QA exits with status 0", _h_status_zero, source_order=24004
    )
    api.register_first(
        r'help advertises shadow-cleanup option "([^"]+)"',
        _h_help_option,
        source_order=24005,
    )
    api.register_first(
        r'help identifies "--static", "--dynamic", "--pipeline", and "--all" as independently selectable modes',
        _h_help_modes,
        source_order=24006,
    )
    api.register_first(
        r'shadow-cleanup QA invocation "([^"]+)" is run twice',
        _h_run_twice,
        source_order=24007,
    )
    api.register_first(
        r"both shadow-cleanup runs exit with status \d+",
        _h_runs_status,
        source_order=24008,
    )
    api.register_first(
        r"each shadow-cleanup check is emitted once in recording order",
        _h_checks_once,
        source_order=24009,
    )
    api.register_first(
        r"both runs have identical ordered shadow-cleanup results",
        _h_identical_results,
        source_order=24010,
    )
    api.register_first(r'each run reports "([^"]+)"', _h_summary, source_order=24011)
    api.register_first(
        r"each run emits \d+ PASS, \d+ FAIL, and \d+ SKIP results",
        _h_result_counts,
        source_order=24012,
    )
    api.register_first(
        r"the endpoint contact count remains 0", _h_endpoint_zero, source_order=24013
    )
    api.register_first(
        r'shadow-cleanup QA is invoked with invalid arguments "([^"]+)"',
        _h_invalid_invocation,
        source_order=24014,
    )
    api.register_first(
        r"shadow-cleanup QA exits with status 2", _h_invalid_status, source_order=24015
    )
    api.register_first(
        r'shadow-cleanup output contains "([^"]+)"',
        _h_invalid_output,
        source_order=24016,
    )
    api.register_first(
        r"no shadow-cleanup check or child process is started",
        _h_no_check_or_child,
        source_order=24017,
    )
    api.register_first(
        r"a local property-test stand-in emits distinct standard output and standard error and exits with status 7",
        _h_child_standin,
        source_order=24018,
    )
    api.register_first(
        r"the parent environment and working directory are recorded for shadow-cleanup QA",
        _h_parent_recorded,
        source_order=24019,
    )
    api.register_first(
        r'shadow-cleanup QA is run in "--dynamic" mode with the property-test stand-in',
        _h_run_child_standin,
        source_order=24020,
    )
    api.register_first(
        r"the property-test child receives the two characterized no-shadowing test node identifiers",
        _h_child_argv,
        source_order=24021,
    )
    api.register_first(
        r"the property-test child runs once from the repository root",
        _h_child_root,
        source_order=24022,
    )
    api.register_first(
        r"its exit status, standard output, and standard error remain separately observable",
        _h_child_streams,
        source_order=24023,
    )
    api.register_first(
        r'shadow-cleanup QA reports "([^"]+)"', _h_child_summary, source_order=24024
    )
    api.register_first(
        r"shadow-cleanup QA exits with status 1", _h_child_status, source_order=24025
    )
    api.register_first(
        r"the parent environment and working directory remain unchanged",
        _h_parent_unchanged,
        source_order=24026,
    )
    api.register_first(
        r"shadow-cleanup QA is invoked by absolute path from a nested temporary directory",
        _h_nested_invocation,
        source_order=24027,
    )
    api.register_first(
        r'shadow-cleanup "--static" mode is run twice',
        _h_nested_static,
        source_order=24028,
    )
    api.register_first(
        r"both shadow-cleanup runs discover the repository root",
        _h_nested_status,
        source_order=24029,
    )
    api.register_first(
        r'both runs emit the same ordered results and "QA suite: 50 passed, 1 failed"',
        _h_nested_results,
        source_order=24030,
    )
    api.register_first(
        r"neither run changes the caller working directory",
        _h_nested_cwd,
        source_order=24031,
    )
    api.register_first(
        r'^the source feature "([^"]+)" is generated$',
        _h_source_generated,
        source_order=24032,
    )
    api.register_first(
        r"endpoint URLs target a local contact sentinel",
        _h_endpoint_configuration,
        source_order=24033,
    )
    api.register_first(
        r"its generated acceptance test is run twice with live opt-in unset",
        _h_run_source,
        source_order=24034,
    )
    api.register_first(
        r"each run reports exactly \d+ distinct shadow-cleanup scenarios as PASS",
        _h_source_count,
        source_order=24035,
    )
    api.register_first(
        r"neither run reports a shadow-cleanup scenario as FAIL or SKIP",
        _h_source_no_failures,
        source_order=24036,
    )
    api.register_first(
        r"both runs report the same ordered shadow-cleanup scenario outcomes",
        _h_source_same,
        source_order=24037,
    )
    api.register_first(
        r"the migration change set is compared with the Phase 5 migration baseline",
        _h_change_set,
        source_order=24038,
    )
    api.register_first(
        r'"acceptance/qa/shadow-cleanup/qa_suite.py" is the only existing QA suite changed',
        _h_only_shadow_suite,
        source_order=24039,
    )
    api.register_first(
        r"every other existing QA suite is byte-for-byte unchanged outside the independent Phase 4 characterization",
        _h_other_suites,
        source_order=24040,
    )
    api.register_first(
        r"the pre-existing shadow-cleanup runtime feature is byte-for-byte unchanged",
        _h_shadow_runtime_unchanged,
        source_order=24041,
    )
    api.register_first(
        r"the shadow-cleanup feature identity, handler patterns, priorities, and scopes are unchanged",
        _h_shadow_registration,
        source_order=24042,
    )
    api.register_first(
        r'no production path beneath "src/" is added, modified, or deleted',
        _h_no_src_changes,
        source_order=24043,
    )
    api.register_first(
        r"acceptance configuration and generation commands are byte-for-byte unchanged",
        _h_config_unchanged,
        source_order=24044,
    )
    api.register_first(
        r"the complete unrelated worktree status and content are recorded for Phase 5",
        _h_worktree_recorded,
        source_order=24045,
    )
    api.register_first(
        r"the migrated shadow-cleanup suite and generated Phase 5 acceptance test are run",
        _h_run_hygiene,
        source_order=24046,
    )
    api.register_first(
        r"IR, dry reports, generated tests, metadata, coverage, mutation, and QA capture artifacts remain untracked",
        _h_artifacts_untracked,
        source_order=24047,
    )
    api.register_first(
        r"generated artifacts remain within their configured generated-output paths",
        _h_generated_paths,
        source_order=24048,
    )
    api.register_first(
        r"generated metadata contains no absolute checkout path",
        _h_metadata_relative,
        source_order=24049,
    )
    api.register_first(
        r"no source-analysis or generated-output scope changes",
        _h_scope_stable,
        source_order=24050,
    )
    api.register_first(
        r"every unrelated worktree path retains its original status and content",
        _h_worktree_unchanged,
        source_order=24051,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
