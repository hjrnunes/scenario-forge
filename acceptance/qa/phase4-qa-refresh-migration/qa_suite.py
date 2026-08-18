#!/usr/bin/env python3
"""Black-box final QA for the Phase 4 acceptance-refresh migration.

The suite invokes command-line entrypoints only. It observes process output,
exit status, filesystem artifacts, and Git state without importing project
modules. All captures and stand-ins live below the repository ``tmp/`` tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
QA_ROOT = PROJECT_ROOT / "tmp" / "qa-phase4-qa-refresh-migration"
CAPTURE_ROOT = QA_ROOT / "captures"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"
REFRESH_SUITE = (
    PROJECT_ROOT / "acceptance" / "qa" / "acceptance-refresh" / "qa_suite.py"
)
PHASE4_TEST = (
    PROJECT_ROOT
    / "build"
    / "acceptance"
    / "generated"
    / "phase4_qa_refresh_migration_acceptance_test.py"
)
ACCEPTANCE_SH = PROJECT_ROOT / "scripts" / "acceptance.sh"
QUALITY_SH = PROJECT_ROOT / "scripts" / "quality.sh"
BASE_COMMIT = "9e112ea23a"
SELF_PATH = "acceptance/qa/phase4-qa-refresh-migration/qa_suite.py"
EXPECTED_ADDED_STATIC = {
    "IR: every scenario in phase4_qa_refresh_migration.json "
    "is present in a feature file",
    "entry point: phase4_qa_refresh_migration_acceptance_test.py "
    "references an existing IR file",
    "coverage: IR phase4_qa_refresh_migration.json "
    "is executed by a generated entry point",
    "canonical: phase4_qa_refresh_migration_acceptance_test.py references IR in ir/",
}
REFRESH_TESTS = (
    ("stage1b-entry-point-guidance", 8),
    ("stage1b-grounding", 7),
    ("stage2-coordination-analysis", 12),
    ("stage2-assembly-fallback", 8),
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        rendered = f"  [{status}] {self.name}"
        if self.detail:
            rendered += f"\n         {self.detail}"
        return rendered


class QARunner:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        result = CheckResult(name, bool(passed), detail)
        self.results.append(result)
        print(result, flush=True)
        return result.passed

    def summary(self) -> int:
        passed = sum(result.passed for result in self.results)
        failed = len(self.results) - passed
        print(f"\nQA suite: {passed} passed, {failed} failed", flush=True)
        return 0 if failed == 0 else 1


def git_command(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
    )


def child_env(**updates: str | None) -> dict[str, str]:
    environment = dict(os.environ)
    for key, value in updates.items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = value
    return environment


def run_capture(
    label: str,
    argv: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 3600,
) -> subprocess.CompletedProcess[str]:
    target = CAPTURE_ROOT / label
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    environment = dict(os.environ if env is None else env)
    status = git_command("status", "--porcelain=v1", "-z", "--untracked-files=all")
    (target / "before.json").write_text(
        json.dumps(
            {
                "argv": argv,
                "cwd": str(cwd),
                "environment": environment,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (target / "git-status-before.bin").write_bytes(status.stdout)
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    (target / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (target / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (target / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return result


def combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + "\n" + result.stderr


def qa_result_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("[PASS]", "[FAIL]"))
    ]


def qa_check_names(text: str, status: str = "PASS") -> list[str]:
    prefix = f"[{status}] "
    return [
        line.strip()[len(prefix) :]
        for line in text.splitlines()
        if line.strip().startswith(prefix)
    ]


def runtime_lines(text: str, status: str | None = None) -> list[str]:
    prefixes = (f"{status} ",) if status else ("PASS ", "FAIL ", "SKIP ")
    found = []
    for raw in text.splitlines():
        line = ANSI_ESCAPE.sub("", raw).strip().lstrip(".")
        if line.startswith(prefixes):
            found.append(line)
    return found


def summary_line(text: str) -> str:
    matches = re.findall(r"^QA suite: \d+ passed, \d+ failed$", text, re.MULTILINE)
    return matches[-1] if matches else ""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def worktree_snapshot() -> tuple[bytes, dict[str, str]]:
    status = git_command("status", "--porcelain=v1", "-z", "--untracked-files=all")
    digests: dict[str, str] = {}
    for item in status.stdout.decode("utf-8", errors="surrogateescape").split("\0"):
        if not item:
            continue
        path_text = item[3:].split(" -> ")[-1]
        path = PROJECT_ROOT / path_text
        if path.is_file():
            digests[path_text] = sha256(path)
        elif path.is_dir():
            digests[path_text] = "<directory>"
        else:
            digests[path_text] = "<absent>"
    return status.stdout, digests


def make_pipeline_standin() -> Path:
    standin_dir = QA_ROOT / "standin-bin"
    standin_dir.mkdir(parents=True, exist_ok=True)
    standin = standin_dir / "uv"
    standin.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

argv = sys.argv[1:]
log = Path(os.environ["QA_STANDIN_LOG"])
record = {
    "argv": argv,
    "cwd": os.getcwd(),
    "environment": {
        key: os.environ.get(key)
        for key in (
            "SCENARIO_FORGE_QA_PIPELINE",
            "SCENARIO_FORGE_MODEL_BASE_URL",
            "OPENAI_BASE_URL",
        )
    },
}
log.parent.mkdir(parents=True, exist_ok=True)
log.write_text(json.dumps(record, indent=2), encoding="utf-8")
if os.environ.get("QA_STANDIN_MODE") == "fail":
    print("CHILD_STDOUT_SENTINEL")
    print("CHILD_STDERR_SENTINEL", file=sys.stderr)
    raise SystemExit(7)

output_dir = Path(argv[argv.index("--output-dir") + 1])
output_dir.mkdir(parents=True, exist_ok=True)
calls = [
    ("stage_1a", "risk_derivation"),
    ("stage_1a", "gap_analysis"),
    ("stage_1b", "capability_profile"),
    ("stage_2", "call_1_requirements"),
    ("stage_2", "call_2a_responsibilities"),
    ("stage_2", "call_2b_control_elements"),
    ("stage_2", "call_3_coordination"),
]
(output_dir / "calls.jsonl").write_text(
    "".join(json.dumps({"stage": stage, "step": step}) + "\\n"
            for stage, step in calls),
    encoding="utf-8",
)
(output_dir / "run-manifest.yaml").write_text(
    "stage_summary:\\n"
    "  stage_1a:\\n"
    "    call_count: 2\\n"
    "  stage_2:\\n"
    "    call_count: 4\\n",
    encoding="utf-8",
)
(output_dir / "control-structure.yaml").write_text(
    "coordination_links:\\n"
    "  - source: controller\\n"
    "    target: controlled_process\\n",
    encoding="utf-8",
)
""",
        encoding="utf-8",
    )
    standin.chmod(0o755)
    return standin


def make_uv_runner() -> Path:
    runner_dir = QA_ROOT / "runner-bin"
    runner_dir.mkdir(parents=True, exist_ok=True)
    runner = runner_dir / "uv"
    runner.write_text(
        f"""#!{PYTHON}
import os
import sys

args = sys.argv[1:]
if not args or args.pop(0) != "run" or not args:
    raise SystemExit("unsupported uv invocation")
command = args.pop(0)
if command == "ruff":
    executable = {str(PROJECT_ROOT / ".venv" / "bin" / "ruff")!r}
    os.execv(executable, [executable, *args])
if command == "pytest":
    executable = {str(PYTHON)!r}
    os.execv(executable, [executable, "-m", "pytest", *args])
if command == "python":
    executable = {str(PYTHON)!r}
    os.execv(executable, [executable, *args])
raise SystemExit(f"unsupported uv run command: {{command}}")
""",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    return runner


def pipeline_command(mode: str) -> list[str]:
    return [
        str(PYTHON),
        str(REFRESH_SUITE),
        mode,
        "--use-case",
        str(QA_ROOT / "use-case.txt"),
        "--risk-extraction",
        str(QA_ROOT / "risks.json"),
        "--capability-profile",
        str(QA_ROOT / "profile.yaml"),
    ]


def qa_p4qrm_01(runner: QARunner) -> tuple[list[str], dict[str, str]]:
    environment = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    help_result = run_capture(
        "p4qrm-01-help",
        [str(PYTHON), str(REFRESH_SUITE), "--help"],
        env=environment,
    )
    help_text = combined(help_result)
    runner.check(
        "QA-P4QRM-01 help exposes the characterized CLI",
        help_result.returncode == 0
        and all(
            option in help_text
            for option in (
                "--static",
                "--pipeline",
                "--all",
                "--use-case",
                "--risk-extraction",
                "--capability-profile",
            )
        ),
        f"exit={help_result.returncode}",
    )

    no_mode = run_capture(
        "p4qrm-01-no-mode",
        [str(PYTHON), str(REFRESH_SUITE)],
        env=environment,
    )
    runner.check(
        "QA-P4QRM-01 no mode is an argparse error",
        no_mode.returncode == 2
        and "one of the arguments --static --pipeline --all is required"
        in no_mode.stderr,
        f"exit={no_mode.returncode}",
    )

    standin = make_pipeline_standin()
    missing_results = []
    child_started = False
    for mode in ("--pipeline", "--all"):
        log = QA_ROOT / f"missing-{mode[2:]}.json"
        log.unlink(missing_ok=True)
        missing_env = child_env(
            SCENARIO_FORGE_QA_PIPELINE=None,
            PATH=f"{standin.parent}:{environment.get('PATH', '')}",
            QA_STANDIN_LOG=str(log),
        )
        result = run_capture(
            f"p4qrm-01-missing-{mode[2:]}",
            [str(PYTHON), str(REFRESH_SUITE), mode],
            env=missing_env,
        )
        missing_results.append(
            result.returncode == 1
            and result.stdout.strip()
            == "ERROR: --use-case and --risk-extraction required for pipeline checks"
        )
        child_started = child_started or log.exists()
    runner.check(
        "QA-P4QRM-01 pipeline modes reject missing inputs before a child starts",
        all(missing_results) and not child_started,
    )

    static_command = [str(PYTHON), str(REFRESH_SUITE), "--static"]
    first = run_capture(
        "p4qrm-01-static-first", static_command, env=environment, timeout=1200
    )
    second = run_capture(
        "p4qrm-01-static-second", static_command, env=environment, timeout=1200
    )
    first_lines = qa_result_lines(first.stdout)
    second_lines = qa_result_lines(second.stdout)
    first_names = qa_check_names(first.stdout)
    base_lines = [
        line
        for line in first_lines
        if line.removeprefix("[PASS] ") not in EXPECTED_ADDED_STATIC
    ]
    runner.check(
        "QA-P4QRM-01 static mode reports 519 ordered PASS checks twice",
        first.returncode == second.returncode == 0
        and first.stdout.count("=== Static checks (no LLM required) ===") == 1
        and second.stdout.count("=== Static checks (no LLM required) ===") == 1
        and first_lines == second_lines
        and len(first_lines) == 519
        and all(line.startswith("[PASS] ") for line in first_lines)
        and summary_line(first.stdout) == "QA suite: 519 passed, 0 failed"
        and summary_line(second.stdout) == "QA suite: 519 passed, 0 failed",
        f"first={first.returncode}/{len(first_lines)} second={second.returncode}",
    )
    runner.check(
        "QA-P4QRM-01 migration adds only four static corpus checks",
        len(base_lines) == 515
        and set(first_names) - set(line.removeprefix("[PASS] ") for line in base_lines)
        == EXPECTED_ADDED_STATIC
        and len(first_names) == len(set(first_names)),
        f"base={len(base_lines)} added={sorted(set(first_names) - set(line.removeprefix('[PASS] ') for line in base_lines))}",
    )
    return first_lines, environment


def qa_p4qrm_02_and_03(
    runner: QARunner,
    root_static_lines: list[str],
    base_environment: dict[str, str],
) -> None:
    standin = make_pipeline_standin()
    (QA_ROOT / "use-case.txt").write_text("QA stand-in use case\n", encoding="utf-8")
    (QA_ROOT / "risks.json").write_text('{"risks": []}\n', encoding="utf-8")
    (QA_ROOT / "profile.yaml").write_text("zones: []\n", encoding="utf-8")
    temp_root = QA_ROOT / "temporary"
    temp_root.mkdir(parents=True, exist_ok=True)
    parent_cwd = Path.cwd()
    parent_env = dict(os.environ)

    successes: list[subprocess.CompletedProcess[str]] = []
    logs: list[dict[str, object]] = []
    output_dirs: list[Path] = []
    for ordinal in ("first", "second"):
        log = QA_ROOT / f"pipeline-{ordinal}.json"
        environment = child_env(
            SCENARIO_FORGE_QA_PIPELINE=None,
            PATH=f"{standin.parent}:{base_environment.get('PATH', '')}",
            QA_STANDIN_LOG=str(log),
            QA_STANDIN_MODE="success",
            TMPDIR=str(temp_root),
        )
        result = run_capture(
            f"p4qrm-02-pipeline-{ordinal}",
            pipeline_command("--pipeline"),
            env=environment,
        )
        successes.append(result)
        record = json.loads(log.read_text(encoding="utf-8"))
        logs.append(record)
        argv = record["argv"]
        output_dirs.append(Path(argv[argv.index("--output-dir") + 1]))

    success_lines = [qa_result_lines(result.stdout) for result in successes]
    expected_prefix = ["run", "scenario-forge", "stpa-run"]
    runner.check(
        "QA-P4QRM-02 stand-in receives the documented root CLI invocation",
        all(record["argv"][:3] == expected_prefix for record in logs)
        and all(record["cwd"] == str(PROJECT_ROOT) for record in logs)
        and all(
            option in record["argv"]
            for record in logs
            for option in (
                "--use-case",
                "--risk-extraction",
                "--profile",
                "--output-dir",
            )
        ),
    )
    runner.check(
        "QA-P4QRM-02 successful pipeline runs are isolated and deterministic",
        all(result.returncode == 0 for result in successes)
        and success_lines[0] == success_lines[1]
        and len(success_lines[0]) == 18
        and all(line.startswith("[PASS] ") for line in success_lines[0])
        and all(
            summary_line(result.stdout) == "QA suite: 18 passed, 0 failed"
            for result in successes
        )
        and all(not output.exists() for output in output_dirs),
        f"counts={[len(lines) for lines in success_lines]}",
    )

    all_log = QA_ROOT / "pipeline-all.json"
    all_environment = child_env(
        SCENARIO_FORGE_QA_PIPELINE=None,
        PATH=f"{standin.parent}:{base_environment.get('PATH', '')}",
        QA_STANDIN_LOG=str(all_log),
        QA_STANDIN_MODE="success",
        TMPDIR=str(temp_root),
    )
    all_result = run_capture(
        "p4qrm-02-all",
        pipeline_command("--all"),
        env=all_environment,
        timeout=1800,
    )
    runner.check(
        "QA-P4QRM-02 all mode combines static and pipeline checks",
        all_result.returncode == 0
        and len(qa_result_lines(all_result.stdout)) == 537
        and summary_line(all_result.stdout) == "QA suite: 537 passed, 0 failed",
        f"exit={all_result.returncode}",
    )

    failure_log = QA_ROOT / "pipeline-failure.json"
    failure_environment = child_env(
        SCENARIO_FORGE_QA_PIPELINE=None,
        PATH=f"{standin.parent}:{base_environment.get('PATH', '')}",
        QA_STANDIN_LOG=str(failure_log),
        QA_STANDIN_MODE="fail",
        TMPDIR=str(temp_root),
    )
    failure = run_capture(
        "p4qrm-02-pipeline-failure",
        pipeline_command("--pipeline"),
        env=failure_environment,
    )
    failure_lines = qa_result_lines(failure.stdout)
    runner.check(
        "QA-P4QRM-02 child exit 7 becomes exactly two reported failures",
        failure.returncode == 1
        and len(failure_lines) == 2
        and all(line.startswith("[FAIL] ") for line in failure_lines)
        and summary_line(failure.stdout) == "QA suite: 0 passed, 2 failed",
        f"exit={failure.returncode} lines={failure_lines}",
    )
    runner.check(
        "QA-P4QRM-02 child streams and parent process remain isolated",
        "CHILD_STDERR_SENTINEL" in failure.stdout
        and "CHILD_STDOUT_SENTINEL" not in failure.stdout
        and not failure.stderr
        and Path.cwd() == parent_cwd
        and dict(os.environ) == parent_env,
    )

    nested_dir = QA_ROOT / "nested" / "a" / "b"
    nested_dir.mkdir(parents=True, exist_ok=True)
    nested_command = [str(PYTHON), str(REFRESH_SUITE), "--static"]
    nested_first = run_capture(
        "p4qrm-03-nested-first",
        nested_command,
        cwd=nested_dir,
        env=base_environment,
        timeout=1200,
    )
    nested_second = run_capture(
        "p4qrm-03-nested-second",
        nested_command,
        cwd=nested_dir,
        env=base_environment,
        timeout=1200,
    )
    runner.check(
        "QA-P4QRM-03 nested invocations discover the repository deterministically",
        nested_first.returncode == nested_second.returncode == 0
        and qa_result_lines(nested_first.stdout) == root_static_lines
        and qa_result_lines(nested_second.stdout) == root_static_lines
        and summary_line(nested_first.stdout) == "QA suite: 519 passed, 0 failed"
        and Path.cwd() == parent_cwd
        and dict(os.environ) == parent_env,
    )


class EndpointSentinel:
    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen()
        self._socket.settimeout(0.1)
        self.port = int(self._socket.getsockname()[1])
        self.contacts = 0
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)

    def _watch(self) -> None:
        while not self._stopped.is_set():
            try:
                connection, _address = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.contacts += 1
            connection.close()

    def __enter__(self) -> EndpointSentinel:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        time.sleep(0.2)
        self._stopped.set()
        self._socket.close()
        self._thread.join(timeout=1)


def refresh_command() -> list[str]:
    return [
        str(PYTHON),
        "-m",
        "pytest",
        *[
            str(
                PROJECT_ROOT
                / "build"
                / "acceptance"
                / "generated"
                / f"{name}_acceptance_test.py"
            )
            for name, _count in REFRESH_TESTS
        ],
        "-q",
        "-s",
    ]


def refresh_outcomes(text: str) -> dict[str, list[str]]:
    outcomes: dict[str, list[str]] = {}
    for name, _count in REFRESH_TESTS:
        outcomes[name] = sorted(
            {
                line.split("/example_", 1)[0]
                for line in runtime_lines(text, "PASS")
                if line.startswith(f"PASS {name}-")
            }
        )
    return outcomes


def qa_p4qrm_04(runner: QARunner) -> None:
    with EndpointSentinel() as sentinel:
        url = f"http://127.0.0.1:{sentinel.port}/v1"
        environment = child_env(
            SCENARIO_FORGE_QA_PIPELINE=None,
            SCENARIO_FORGE_MODEL_BASE_URL=url,
            OPENAI_BASE_URL=url,
            SCENARIO_FORGE_API_KEY="qa-sentinel",
            OPENAI_API_KEY="qa-sentinel",
        )
        first = run_capture(
            "p4qrm-04-refresh-first", refresh_command(), env=environment
        )
        second = run_capture(
            "p4qrm-04-refresh-second", refresh_command(), env=environment
        )
    first_text = combined(first)
    second_text = combined(second)
    first_outcomes = refresh_outcomes(first_text)
    counts = {name: len(outcomes) for name, outcomes in first_outcomes.items()}
    expected = dict(REFRESH_TESTS)
    runner.check(
        "QA-P4QRM-04 refresh parity is 8/7/12/8 with no FAIL or SKIP",
        first.returncode == second.returncode == 0
        and counts == expected
        and not runtime_lines(first_text, "FAIL")
        and not runtime_lines(first_text, "SKIP"),
        f"counts={counts}",
    )
    runner.check(
        "QA-P4QRM-04 refresh rerun is ordered and makes no endpoint contact",
        runtime_lines(first_text) == runtime_lines(second_text)
        and sentinel.contacts == 0,
        f"endpoint_contacts={sentinel.contacts}",
    )


def qa_p4qrm_05(runner: QARunner) -> None:
    qa_diff = git_command(
        "diff", "--name-status", f"{BASE_COMMIT}..HEAD", "--", "acceptance/qa"
    )
    qa_changes = qa_diff.stdout.decode().splitlines()
    changed_suites = [line for line in qa_changes if line.endswith("/qa_suite.py")]
    runner.check(
        "QA-P4QRM-05 exactly one existing QA suite is migrated",
        changed_suites
        in (
            ["M\tacceptance/qa/acceptance-refresh/qa_suite.py"],
            [
                "M\tacceptance/qa/acceptance-refresh/qa_suite.py",
                f"A\t{SELF_PATH}",
            ],
        )
        and all(
            line == "A\tacceptance/qa/phase4-qa-refresh-migration/qa_suite.md"
            or line.endswith("/qa_suite.py")
            for line in qa_changes
        ),
        f"changes={qa_changes}",
    )

    baseline_harness = git_command("show", f"{BASE_COMMIT}:acceptance/qa/qa_harness.py")
    current_harness = PROJECT_ROOT / "acceptance" / "qa" / "qa_harness.py"
    runner.check(
        "QA-P4QRM-05 shared QA harness remains byte-for-byte unchanged",
        baseline_harness.returncode == 0
        and baseline_harness.stdout == current_harness.read_bytes(),
    )

    runtime_diff = git_command(
        "diff",
        "--name-status",
        f"{BASE_COMMIT}..HEAD",
        "--",
        "acceptance/runtime_manifest.py",
        "acceptance/runtime_features",
    )
    runtime_changes = runtime_diff.stdout.decode().splitlines()
    allowed_runtime = {
        "M\tacceptance/runtime_features/__init__.py",
        "M\tacceptance/runtime_manifest.py",
        *{
            f"A\tacceptance/runtime_features/phase4_qa_refresh_migration{suffix}.py"
            for suffix in (
                "",
                "_cli",
                "_generated",
                "_isolation",
                "_process",
                "_scope",
                "_support",
            )
        },
    }
    runner.check(
        "QA-P4QRM-05 runtime registration changes only add Phase 4",
        set(runtime_changes) == allowed_runtime,
        f"changes={runtime_changes}",
    )

    src_diff = git_command("diff", "--name-only", f"{BASE_COMMIT}..HEAD", "--", "src")
    worktree_src = git_command(
        "status", "--porcelain=v1", "--untracked-files=all", "--", "src"
    )
    runner.check(
        "QA-P4QRM-05 no committed or worktree src change exists",
        not src_diff.stdout.strip() and not worktree_src.stdout.strip(),
    )


def qa_p4qrm_06(
    runner: QARunner,
    before_status: bytes,
    before_digests: dict[str, str],
) -> None:
    unchanged_paths = (
        ".factory/swarmforge/config.sh",
        "scripts/acceptance.sh",
        "scripts/quality.sh",
        ".gitignore",
    )
    config_diff = git_command(
        "diff", "--name-only", f"{BASE_COMMIT}..HEAD", "--", *unchanged_paths
    )
    config = (PROJECT_ROOT / ".factory" / "swarmforge" / "config.sh").read_text(
        encoding="utf-8"
    )
    quality = QUALITY_SH.read_text(encoding="utf-8")
    runner.check(
        "QA-P4QRM-06 configuration and ignore rules remain unchanged",
        not config_diff.stdout.strip(),
        config_diff.stdout.decode().strip(),
    )
    runner.check(
        "QA-P4QRM-06 generated-output and source-analysis scopes remain configured",
        'SWARMFORGE_FILE_POLICY="generated-output"' in config
        and 'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and 'SWARMFORGE_MUTATION_CMD="mutate4py src/' in config
        and "uv run ruff check src acceptance" in quality
        and "uv run ruff format --check src acceptance" in quality,
    )

    tracked = git_command(
        "ls-files",
        "build/acceptance",
        "build/acceptance-mutation",
        "tmp/qa-phase4-qa-refresh-migration",
        "lcov.info",
        "coverage.lcov",
        "lcov_stpa_report.info",
    )
    generated_roots = (
        PROJECT_ROOT / "build" / "acceptance" / "ir",
        PROJECT_ROOT / "build" / "acceptance" / "dry",
        PROJECT_ROOT / "build" / "acceptance" / "generated",
    )
    absolute_hits = []
    project_bytes = str(PROJECT_ROOT).encode()
    for root in generated_roots:
        for path in root.rglob("*"):
            if (
                path.is_file()
                and path.suffix in {".json", ".py", ".txt", ".yaml", ".yml"}
                and project_bytes in path.read_bytes()
            ):
                absolute_hits.append(path.relative_to(PROJECT_ROOT).as_posix())
    runner.check(
        "QA-P4QRM-06 generated artifacts are present and untracked",
        tracked.returncode == 0
        and not tracked.stdout.strip()
        and all(root.is_dir() and any(root.iterdir()) for root in generated_roots),
        tracked.stdout.decode().strip(),
    )
    runner.check(
        "QA-P4QRM-06 generated metadata contains no absolute checkout path",
        not absolute_hits,
        f"absolute_path_hits={absolute_hits[:8]}",
    )

    after_status, after_digests = worktree_snapshot()
    runner.check(
        "QA-P4QRM-06 unrelated worktree paths retain status and content",
        before_status == after_status and before_digests == after_digests,
        "worktree status or path digest changed during QA",
    )


def qa_release_workflows(runner: QARunner) -> None:
    runner_uv = make_uv_runner()
    environment = child_env(
        SCENARIO_FORGE_QA_PIPELINE=None,
        PATH=f"{runner_uv.parent}:{os.environ.get('PATH', '')}",
    )
    quality = run_capture(
        "release-quality", [str(QUALITY_SH)], env=environment, timeout=1200
    )
    runner.check(
        "Release quality script passes through its CLI",
        quality.returncode == 0 and "All checks passed!" in combined(quality),
        f"exit={quality.returncode}",
    )

    with EndpointSentinel() as sentinel:
        url = f"http://127.0.0.1:{sentinel.port}/v1"
        acceptance_environment = dict(environment)
        acceptance_environment.update(
            {
                "SCENARIO_FORGE_MODEL_BASE_URL": url,
                "OPENAI_BASE_URL": url,
                "SCENARIO_FORGE_API_KEY": "qa-sentinel",
                "OPENAI_API_KEY": "qa-sentinel",
            }
        )
        acceptance_environment.pop("SCENARIO_FORGE_QA_PIPELINE", None)
        phase4_first = run_capture(
            "release-phase4-first",
            [str(PYTHON), str(PHASE4_TEST), "-q", "-s"],
            env=acceptance_environment,
        )
        phase4_second = run_capture(
            "release-phase4-second",
            [str(PYTHON), str(PHASE4_TEST), "-q", "-s"],
            env=acceptance_environment,
        )
        default = run_capture(
            "release-default-acceptance",
            [str(ACCEPTANCE_SH), "--test"],
            env=acceptance_environment,
            timeout=3600,
        )
    phase4_first_lines = runtime_lines(combined(phase4_first))
    phase4_second_lines = runtime_lines(combined(phase4_second))
    runner.check(
        "Generated Phase 4 acceptance reports 21 deterministic PASS outcomes",
        phase4_first.returncode == phase4_second.returncode == 0
        and len(phase4_first_lines) == 21
        and phase4_first_lines == phase4_second_lines
        and all(line.startswith("PASS ") for line in phase4_first_lines),
        f"count={len(phase4_first_lines)}",
    )
    default_text = combined(default)
    default_text_without_ansi = ANSI_ESCAPE.sub("", default_text)
    runner.check(
        "Default acceptance passes 103 tests with 4 warnings and live opt-in unset",
        default.returncode == 0
        and re.search(r"\b103 passed, 4 warnings\b", default_text_without_ansi)
        is not None
        and "FAIL " not in default_text
        and sentinel.contacts == 0,
        f"exit={default.returncode} endpoint_contacts={sentinel.contacts}",
    )


def main() -> int:
    QA_ROOT.mkdir(parents=True, exist_ok=True)
    CAPTURE_ROOT.mkdir(parents=True, exist_ok=True)
    before_status, before_digests = worktree_snapshot()
    runner = QARunner()
    print("End-to-end QA: Phase 4 acceptance-refresh migration", flush=True)
    root_static_lines, environment = qa_p4qrm_01(runner)
    qa_p4qrm_02_and_03(runner, root_static_lines, environment)
    qa_p4qrm_04(runner)
    qa_p4qrm_05(runner)
    qa_release_workflows(runner)
    qa_p4qrm_06(runner, before_status, before_digests)
    return runner.summary()


if __name__ == "__main__":
    raise SystemExit(main())
