#!/usr/bin/env python3
"""Black-box QA suite for the acceptance QA runtime cleanup.

This executable form of ``qa_suite.md`` invokes only checked-in command-line
entrypoints and generated tests. It observes process output, exit status,
filesystem artifacts, and Git state without importing project Python modules.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
QA_ROOT = PROJECT_ROOT / "tmp" / "qa-acceptance-qa-runtime-cleanup"
CAPTURE_ROOT = QA_ROOT / "captures"
PYTHON = Path(sys.executable)
ACCEPTANCE_SH = PROJECT_ROOT / "scripts" / "acceptance.sh"
AFR_SUITE = (
    PROJECT_ROOT / "acceptance" / "qa" / "acceptance-framework-refactor" / "qa_suite.py"
)
AQRC_TEST = (
    PROJECT_ROOT
    / "build"
    / "acceptance"
    / "generated"
    / "acceptance_qa_runtime_cleanup_acceptance_test.py"
)
BASE_COMMIT = "9604d45"
LIVE_MARKER = 'live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"'
LIVE_SKIP_REASON = 'live LLM acceptance requires SCENARIO_FORGE_QA_PIPELINE "1"'
REFRESH_TESTS = (
    ("stage1b-entry-point-guidance", 8),
    ("stage1b-grounding", 7),
    ("stage2-coordination-analysis", 12),
    ("stage2-assembly-fallback", 8),
)
EXPECTED_AFR_CAPTURES = (
    "qa-afr-02-test",
    "qa-afr-03-first",
    "qa-afr-03-second",
    "qa-afr-04-namespace",
    "qa-afr-04-nested",
    "qa-afr-05-worker",
    "qa-afr-06-status",
)
EXPECTED_CLEANUP_PATHS = {
    "acceptance/qa/acceptance-framework-refactor/qa_suite.py",
    "acceptance/qa/acceptance-framework-refactor/qa_suite_generation.py",
    "acceptance/qa/acceptance-framework-refactor/qa_suite_support.py",
    "acceptance/qa/qa_harness.py",
    "acceptance/runtime_features/__init__.py",
    "acceptance/runtime_features/acceptance_qa_runtime_cleanup.py",
    "acceptance/runtime_features/acceptance_qa_runtime_cleanup_checks.py",
    "acceptance/runtime_features/acceptance_qa_runtime_cleanup_harness.py",
    "acceptance/runtime_features/acceptance_refresh.py",
    "acceptance/runtime_features/acceptance_refresh_coordination.py",
    "acceptance/runtime_features/acceptance_refresh_stage2.py",
    "acceptance/runtime_manifest.py",
    "tests/stpa/test_qa_runtime_cleanup.py",
}
SELF_PATH = "acceptance/qa/acceptance-qa-runtime-cleanup/qa_suite.py"
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


def child_env(**updates: str | None) -> dict[str, str]:
    environment = dict(os.environ)
    for key, value in updates.items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = value
    environment["PATH"] = (
        f"/opt/homebrew/bin:/usr/local/bin:{environment.get('PATH', '')}"
    )
    return environment


def run_capture(
    label: str,
    argv: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 2400,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    target = CAPTURE_ROOT / label
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    (target / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (target / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (target / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return result


def combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + "\n" + result.stderr


def result_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("[PASS]", "[FAIL]", "[SKIP]"))
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


def file_digests(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def git_output(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def worktree_snapshot() -> tuple[str, dict[str, str]]:
    status = git_output("status", "--porcelain=v1", "-z", "--untracked-files=all")
    digests: dict[str, str] = {}
    for item in status.stdout.split("\0"):
        if not item:
            continue
        path_text = item[3:].split(" -> ")[-1]
        path = PROJECT_ROOT / path_text
        if path.is_file():
            digests[path_text] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            digests[path_text] = "<directory>"
        else:
            digests[path_text] = "<absent>"
    return status.stdout, digests


def qa_aqrc_01(runner: QARunner) -> None:
    parent_env = dict(os.environ)
    parent_cwd = Path.cwd()
    environment = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    command = [str(PYTHON), str(AFR_SUITE), "--skip-generate"]
    first = run_capture("aqrc-01-afr-root", command, env=environment)
    nested_dir = QA_ROOT / "nested" / "working-directory"
    nested_dir.mkdir(parents=True, exist_ok=True)
    nested = run_capture(
        "aqrc-01-afr-nested",
        command,
        cwd=nested_dir,
        env=environment,
    )
    first_output = combined(first)
    nested_output = combined(nested)
    lines = result_lines(first_output)
    nested_lines = result_lines(nested_output)
    positions = [
        next(
            (index for index, line in enumerate(lines) if f"QA-AFR-0{number}" in line),
            -1,
        )
        for number in range(2, 7)
    ]
    expected_summary = summary_line(first_output)
    summary_match = re.fullmatch(
        r"QA suite: (\d+) passed, (\d+) failed", expected_summary
    )
    failed = int(summary_match.group(2)) if summary_match else -1

    runner.check(
        "QA-AQRC-01 --skip-generate is accepted and AFR succeeds",
        first.returncode == 0,
        f"exit={first.returncode}",
    )
    runner.check(
        "QA-AQRC-01 AFR checks emit once in recording order",
        first_output.count("QA-AFR-01 skipped by --skip-generate") == 1
        and positions == sorted(positions)
        and all(position >= 0 for position in positions)
        and len(lines) == len(set(lines)),
        f"positions={positions} result_lines={len(lines)} unique={len(set(lines))}",
    )
    runner.check(
        "QA-AQRC-01 shared summary and exit status agree",
        bool(summary_match) and (first.returncode == 0) == (failed == 0),
        f"summary={expected_summary!r} exit={first.returncode}",
    )
    capture_root = PROJECT_ROOT / "tmp" / "qa-acceptance-framework" / "captures"
    missing = [
        f"{label}/{name}"
        for label in EXPECTED_AFR_CAPTURES
        for name in ("stdout.txt", "stderr.txt", "exit.txt")
        if not (capture_root / label / name).is_file()
    ]
    runner.check(
        "QA-AQRC-01 shared harness keeps separate captures",
        not missing,
        f"missing={missing[:6]}",
    )
    runner.check(
        "QA-AQRC-01 nested invocation preserves ordered output",
        nested.returncode == first.returncode
        and nested_lines == lines
        and summary_line(nested_output) == expected_summary,
        f"root_exit={first.returncode} nested_exit={nested.returncode}",
    )
    changed_suites = git_output(
        "diff",
        "--name-only",
        f"{BASE_COMMIT}..HEAD",
        "--",
        "acceptance/qa",
        "tests/stpa",
    )
    migrated = [
        path
        for path in changed_suites.stdout.splitlines()
        if (
            Path(path).name == "qa_suite.py"
            or (
                path.startswith("tests/stpa/")
                and "qa_suite" in Path(path).name
                and path.endswith(".py")
            )
        )
    ]
    runner.check(
        "QA-AQRC-01 only the AFR executable suite was migrated",
        migrated == ["acceptance/qa/acceptance-framework-refactor/qa_suite.py"],
        f"migrated={migrated}",
    )
    runner.check(
        "QA-AQRC-01 parent process state remains unchanged",
        dict(os.environ) == parent_env and Path.cwd() == parent_cwd,
    )


def qa_aqrc_02_and_03(runner: QARunner) -> None:
    parent_env = dict(os.environ)
    parent_cwd = Path.cwd()
    environment = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    command = [str(PYTHON), str(AQRC_TEST)]
    first = run_capture("aqrc-02-generated-first", command, env=environment)
    second = run_capture("aqrc-02-generated-second", command, env=environment)
    first_lines = runtime_lines(combined(first))
    second_lines = runtime_lines(combined(second))

    expected_ids = {f"AQRC-0{number}" for number in range(1, 8)}
    found_ids = {
        code
        for code in expected_ids
        if any(code in line for line in first_lines if line.startswith("PASS "))
    }
    runner.check(
        "QA-AQRC-02 generated AQRC-01..07 checks pass",
        first.returncode == second.returncode == 0
        and found_ids == expected_ids
        and not runtime_lines(combined(first), "FAIL"),
        f"first={first.returncode} second={second.returncode} ids={sorted(found_ids)}",
    )
    runner.check(
        "QA-AQRC-02 reruns have identical ordered outcomes",
        first_lines == second_lines,
        f"first_lines={len(first_lines)} second_lines={len(second_lines)}",
    )
    first_capture = CAPTURE_ROOT / "aqrc-02-generated-first"
    second_capture = CAPTURE_ROOT / "aqrc-02-generated-second"
    runner.check(
        "QA-AQRC-02 independent runs have distinct complete captures",
        first_capture != second_capture
        and all(
            (path / name).is_file()
            for path in (first_capture, second_capture)
            for name in ("stdout.txt", "stderr.txt", "exit.txt")
        ),
    )
    runner.check(
        "QA-AQRC-02 child isolation contract passes without parent mutation",
        any(
            "AQRC-02 isolates child execution and captures" in line
            for line in first_lines
        )
        and dict(os.environ) == parent_env
        and Path.cwd() == parent_cwd,
    )

    ir_path = (
        PROJECT_ROOT
        / "build"
        / "acceptance"
        / "ir"
        / "acceptance_qa_runtime_cleanup.json"
    )
    ir_text = ir_path.read_text(encoding="utf-8")
    registration_requirements = (
        "registers exactly 38 handlers once",
        "13 handlers retain feature scope",
        "25 handlers retain global scope",
        "pattern text, relative priority, scope, and observable handler results",
        "registration restores the active feature scope to no feature",
    )
    registration_pass = [
        line
        for line in first_lines
        if "AQRC-04 preserves acceptance-refresh registration" in line
    ]
    runner.check(
        "QA-AQRC-03 registration count, scope, and parity pass black-box",
        len(registration_pass) == 1
        and registration_pass[0].startswith("PASS ")
        and all(requirement in ir_text for requirement in registration_requirements),
        f"registration_results={registration_pass}",
    )


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


def refresh_outcomes(text: str) -> dict[str, set[str]]:
    outcomes: dict[str, set[str]] = {}
    for name, _count in REFRESH_TESTS:
        outcomes[name] = {
            line.split("/example_", 1)[0]
            for line in runtime_lines(text, "PASS")
            if line.startswith(f"PASS {name}-")
        }
    return outcomes


def qa_aqrc_04(runner: QARunner) -> None:
    environment = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    first = run_capture("aqrc-04-refresh-first", refresh_command(), env=environment)
    second = run_capture("aqrc-04-refresh-second", refresh_command(), env=environment)
    first_text = combined(first)
    second_text = combined(second)
    first_runtime = runtime_lines(first_text)
    second_runtime = runtime_lines(second_text)
    counts = {
        name: len(outcomes) for name, outcomes in refresh_outcomes(first_text).items()
    }
    expected = {name: count for name, count in REFRESH_TESTS}

    runner.check(
        "QA-AQRC-04 all 35 acceptance-refresh scenarios pass",
        first.returncode == 0
        and counts == expected
        and not runtime_lines(first_text, "FAIL")
        and not runtime_lines(first_text, "SKIP"),
        f"exit={first.returncode} counts={counts}",
    )
    runner.check(
        "QA-AQRC-04 acceptance-refresh rerun preserves ordered outcomes",
        second.returncode == first.returncode and second_runtime == first_runtime,
        f"first={first.returncode} second={second.returncode}",
    )


def expected_live_skips() -> Counter[str]:
    expected: Counter[str] = Counter()
    ir_root = PROJECT_ROOT / "build" / "acceptance" / "ir"
    for path in sorted(ir_root.rglob("*.json")):
        if path.name.endswith("_dry.json"):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        background = document.get("background") or []
        background_live = any(step.get("text") == LIVE_MARKER for step in background)
        for scenario in document.get("scenarios") or []:
            scenario_live = background_live or any(
                step.get("text") == LIVE_MARKER for step in scenario.get("steps") or []
            )
            if not scenario_live:
                continue
            examples = scenario.get("examples") or [{}]
            for index, _example in enumerate(examples, 1):
                expected[
                    f"SKIP {scenario['name']}/example_{index}: {LIVE_SKIP_REASON}"
                ] += 1
    return expected


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
        self._stopped.set()
        self._socket.close()
        self._thread.join(timeout=1)


def qa_aqrc_05(runner: QARunner) -> None:
    with EndpointSentinel() as sentinel:
        url = f"http://127.0.0.1:{sentinel.port}/v1"
        environment = child_env(
            SCENARIO_FORGE_QA_PIPELINE=None,
            SCENARIO_FORGE_MODEL_BASE_URL=url,
            OPENAI_BASE_URL=url,
            SCENARIO_FORGE_API_KEY="qa-sentinel",
            OPENAI_API_KEY="qa-sentinel",
        )
        result = run_capture(
            "aqrc-05-default-acceptance",
            [str(ACCEPTANCE_SH), "--test"],
            env=environment,
        )
    output = combined(result)
    lines = runtime_lines(output)
    actual_skips = Counter(runtime_lines(output, "SKIP"))
    expected_skips = expected_live_skips()
    first_runtime_at = min(
        (
            output.find(prefix)
            for prefix in ("PASS ", "FAIL ", "SKIP ")
            if output.find(prefix) >= 0
        ),
        default=-1,
    )
    quality_at = output.find("All checks passed!")
    aqrc_ids = {
        code
        for code in (f"AQRC-0{number}" for number in range(1, 8))
        if any(line.startswith("PASS ") and code in line for line in lines)
    }
    refresh_counts = {
        name: len(outcomes) for name, outcomes in refresh_outcomes(output).items()
    }

    runner.check(
        "QA-AQRC-05 quality runs before the default generated suite",
        0 <= quality_at < first_runtime_at,
        f"quality_at={quality_at} first_runtime_at={first_runtime_at}",
    )
    runner.check(
        "QA-AQRC-05 default acceptance passes AQRC-01..07 and refresh parity",
        result.returncode == 0
        and aqrc_ids == {f"AQRC-0{number}" for number in range(1, 8)}
        and refresh_counts == dict(REFRESH_TESTS)
        and not runtime_lines(output, "FAIL"),
        f"exit={result.returncode} aqrc={sorted(aqrc_ids)} refresh={refresh_counts}",
    )
    runner.check(
        "QA-AQRC-05 exact live-marked scenarios skip only",
        bool(expected_skips) and actual_skips == expected_skips,
        f"actual={sum(actual_skips.values())} expected={sum(expected_skips.values())}",
    )
    runner.check(
        "QA-AQRC-05 skipped live scenarios make no endpoint contact",
        sentinel.contacts == 0,
        f"endpoint_contacts={sentinel.contacts}",
    )


def qa_aqrc_06(runner: QARunner) -> None:
    generation_root = QA_ROOT / "generated"
    if generation_root.exists():
        shutil.rmtree(generation_root)
    layout = {
        "ir": generation_root / "ir",
        "dry": generation_root / "dry",
        "tests": generation_root / "generated",
        "mutation": generation_root / "mutation",
    }
    before_status, before_digests = worktree_snapshot()
    environment = child_env(
        SCENARIO_FORGE_QA_PIPELINE=None,
        SCENARIO_FORGE_MODEL_BASE_URL="http://127.0.0.1:9/v1",
        SCENARIO_FORGE_API_KEY="qa-no-contact",
        SWARMFORGE_FEATURES_DIR="features",
        SWARMFORGE_ACCEPTANCE_IR_DIR=layout["ir"].relative_to(PROJECT_ROOT).as_posix(),
        SWARMFORGE_ACCEPTANCE_DRY_DIR=layout["dry"]
        .relative_to(PROJECT_ROOT)
        .as_posix(),
        SWARMFORGE_ACCEPTANCE_GENERATED_DIR=layout["tests"]
        .relative_to(PROJECT_ROOT)
        .as_posix(),
        SWARMFORGE_ACCEPTANCE_MUTATION_DIR=layout["mutation"]
        .relative_to(PROJECT_ROOT)
        .as_posix(),
        PYTHONDONTWRITEBYTECODE="1",
        PYTEST_ADDOPTS=(
            "--ignore="
            + (layout["tests"] / "acceptance_qa_runtime_cleanup_acceptance_test.py")
            .relative_to(PROJECT_ROOT)
            .as_posix()
        ),
    )
    first = run_capture(
        "aqrc-06-generate-first",
        [str(ACCEPTANCE_SH)],
        env=environment,
        timeout=3600,
    )
    first_digests = file_digests(generation_root)
    second = run_capture(
        "aqrc-06-generate-second",
        [str(ACCEPTANCE_SH)],
        env=environment,
        timeout=3600,
    )
    second_digests = file_digests(generation_root)
    after_status, after_digests = worktree_snapshot()
    expected_roots = ("ir", "dry", "tests")
    absolute_path_hits = [
        relative
        for relative in second_digests
        if str(PROJECT_ROOT).encode() in (generation_root / relative).read_bytes()
    ]

    runner.check(
        "QA-AQRC-06 redirected generation completes twice",
        first.returncode == second.returncode
        and first.returncode in {0, 1}
        and runtime_lines(combined(first), "FAIL")
        == runtime_lines(combined(second), "FAIL")
        == [
            "FAIL AHG-08 generated-output paths remain unchanged/example_1: "
            "Unexpected IR path: "
            "tmp/qa-acceptance-qa-runtime-cleanup/generated/ir/group/example.json"
        ],
        f"first={first.returncode} second={second.returncode}",
    )
    runner.check(
        "QA-AQRC-06 artifacts stay in configured generated-output trees",
        all(layout[name].is_dir() for name in expected_roots)
        and bool(second_digests)
        and all(
            Path(relative).parts[0] in {"ir", "dry", "generated", "mutation"}
            for relative in second_digests
        ),
        f"files={len(second_digests)}",
    )
    runner.check(
        "QA-AQRC-06 repeated generation is byte-for-byte deterministic",
        first_digests == second_digests,
        f"first_files={len(first_digests)} second_files={len(second_digests)}",
    )
    runner.check(
        "QA-AQRC-06 generated metadata contains no absolute checkout path",
        not absolute_path_hits,
        f"absolute_path_hits={absolute_path_hits[:6]}",
    )
    tracked = git_output(
        "ls-files",
        "build/acceptance",
        "build/acceptance-mutation",
        "tmp/qa-acceptance-qa-runtime-cleanup",
    )
    runner.check(
        "QA-AQRC-06 generated and capture artifacts remain untracked",
        tracked.returncode == 0 and not tracked.stdout.strip(),
        tracked.stdout.strip(),
    )
    runner.check(
        "QA-AQRC-06 unrelated worktree state and content are preserved",
        before_status == after_status and before_digests == after_digests,
        "worktree status or unrelated file content changed during generation",
    )


def qa_aqrc_07(runner: QARunner) -> None:
    committed = git_output("diff", "--name-only", f"{BASE_COMMIT}..HEAD")
    committed_paths = set(committed.stdout.splitlines())
    src_diff = git_output("diff", "--name-only", f"{BASE_COMMIT}..HEAD", "--", "src")
    worktree_src = git_output(
        "status", "--porcelain=v1", "--untracked-files=all", "--", "src"
    )
    config = (PROJECT_ROOT / ".factory" / "swarmforge" / "config.sh").read_text(
        encoding="utf-8"
    )
    quality = (PROJECT_ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")

    runner.check(
        "QA-AQRC-07 cleanup has no committed or worktree src change",
        not src_diff.stdout.strip() and not worktree_src.stdout.strip(),
        f"committed={src_diff.stdout.strip()} worktree={worktree_src.stdout.strip()}",
    )
    runner.check(
        "QA-AQRC-07 source-analysis and generated-output scopes are preserved",
        'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and 'SWARMFORGE_MUTATION_CMD="mutate4py src/' in config
        and 'SWARMFORGE_FILE_POLICY="generated-output"' in config,
    )
    runner.check(
        "QA-AQRC-07 quality remains scoped to src and acceptance",
        "uv run ruff check src acceptance" in quality
        and "uv run ruff format --check src acceptance" in quality,
    )
    runner.check(
        "QA-AQRC-07 committed cleanup scope contains only intended paths",
        committed.returncode == 0
        and frozenset(committed_paths)
        in {
            frozenset(EXPECTED_CLEANUP_PATHS),
            frozenset(EXPECTED_CLEANUP_PATHS | {SELF_PATH}),
        },
        f"unexpected={sorted(committed_paths - EXPECTED_CLEANUP_PATHS - {SELF_PATH})}",
    )


def main() -> int:
    QA_ROOT.mkdir(parents=True, exist_ok=True)
    runner = QARunner()
    print("End-to-end QA: acceptance QA runtime cleanup", flush=True)
    qa_aqrc_01(runner)
    qa_aqrc_02_and_03(runner)
    qa_aqrc_04(runner)
    qa_aqrc_05(runner)
    qa_aqrc_06(runner)
    qa_aqrc_07(runner)
    return runner.summary()


if __name__ == "__main__":
    raise SystemExit(main())
