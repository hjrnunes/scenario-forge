#!/usr/bin/env python3
"""Independent black-box QA for the Phase 5 shadow-cleanup migration.

Only command-line entrypoints, process streams, filesystem artifacts, and Git
observations are used. The project packages are never imported.
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
    parent
    for parent in Path(__file__).resolve().parents
    if (parent / "pyproject.toml").is_file()
)
QA_ROOT = PROJECT_ROOT / "tmp" / "qa-phase5-shadow-cleanup-migration"
CAPTURES = QA_ROOT / "captures"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"
SHADOW_SUITE = PROJECT_ROOT / "acceptance/qa/shadow-cleanup/qa_suite.py"
BASE_COMMIT = "5a79d55b35"
OPT_IN = "SCENARIO_FORGE_QA_PIPELINE"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SUMMARY = re.compile(r"^QA suite: (\d+) passed, (\d+) failed$", re.MULTILINE)
PROPERTY_NODES = [
    str(PROJECT_ROOT / "tests/stpa/test_acceptance_harness_property.py") + "::"
    "TestNoPatternShadowing::test_no_global_pattern_conflicts_on_ir_steps",
    str(PROJECT_ROOT / "tests/stpa/test_acceptance_harness_property.py") + "::"
    "TestNoPatternShadowing::test_no_global_pattern_conflicts_on_synthetic_steps",
]


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        text = f"  [{'PASS' if self.passed else 'FAIL'}] {self.name}"
        return f"{text}\n         {self.detail}" if self.detail else text


class Runner:
    def __init__(self) -> None:
        self.results: list[Check] = []

    def check(self, name: str, passed: bool, detail: str = "") -> None:
        result = Check(name, bool(passed), detail)
        self.results.append(result)
        print(result, flush=True)

    def finish(self) -> int:
        passed = sum(result.passed for result in self.results)
        failed = len(self.results) - passed
        print(f"\nQA suite: {passed} passed, {failed} failed", flush=True)
        return int(failed != 0)


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=PROJECT_ROOT, capture_output=True, check=False
    )


def environment(**updates: str | None) -> dict[str, str]:
    result = dict(os.environ)
    for key, value in updates.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = value
    return result


def _safe_environment(value: dict[str, str]) -> dict[str, str]:
    sensitive = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    return {
        key: "<redacted>" if any(word in key.upper() for word in sensitive) else item
        for key, item in value.items()
    }


def capture(
    label: str,
    argv: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 3600,
) -> subprocess.CompletedProcess[str]:
    target = CAPTURES / label
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    child_environment = dict(os.environ if env is None else env)
    (target / "invocation.json").write_text(
        json.dumps(
            {
                "argv": argv,
                "cwd": str(cwd),
                "environment": _safe_environment(child_environment),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (target / "git-status-before.bin").write_bytes(
        git("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    )
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=child_environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    (target / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (target / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (target / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return result


def output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


def qa_lines(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        line.strip()
        for line in output(result).splitlines()
        if line.strip().startswith(("[PASS]", "[FAIL]", "[SKIP]"))
    ]


def outcome_lines(result: subprocess.CompletedProcess[str]) -> list[str]:
    lines = []
    for raw in output(result).splitlines():
        line = ANSI.sub("", raw).strip().lstrip(".")
        if line.startswith(("PASS ", "FAIL ", "SKIP ")):
            lines.append(line)
    return lines


def exact_counts(
    result: subprocess.CompletedProcess[str],
    passed: int,
    failed: int,
    skipped: int,
    status: int,
) -> bool:
    lines = qa_lines(result)
    summaries = SUMMARY.findall(output(result))
    return (
        result.returncode == status
        and sum("[PASS]" in line for line in lines) == passed
        and sum("[FAIL]" in line for line in lines) == failed
        and sum("[SKIP]" in line for line in lines) == skipped
        and summaries == [(str(passed), str(failed))]
        and output(result)
        .strip()
        .endswith(f"QA suite: {passed} passed, {failed} failed")
    )


def digest(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if path.is_dir():
        entries = [
            (
                child.relative_to(path).as_posix(),
                hashlib.sha256(child.read_bytes()).hexdigest(),
            )
            for child in sorted(path.rglob("*"))
            if child.is_file()
        ]
        return hashlib.sha256(repr(entries).encode()).hexdigest()
    return "<absent>"


def worktree_snapshot() -> tuple[bytes, dict[str, str]]:
    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    paths: list[str] = []
    for entry in status.decode(errors="surrogateescape").split("\0"):
        if entry:
            paths.append(entry[3:].rsplit(" -> ", 1)[-1])
    return status, {path: digest(PROJECT_ROOT / path) for path in paths}


class ContactSentinel:
    def __init__(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.server.settimeout(0.1)
        self.port = int(self.server.getsockname()[1])
        self.contacts = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def _watch(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.contacts += 1
            connection.close()

    def __enter__(self) -> "ContactSentinel":
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        time.sleep(0.2)
        self.stop.set()
        self.server.close()
        self.thread.join(timeout=1)


def make_uv_shim() -> Path:
    directory = QA_ROOT / "bin"
    directory.mkdir(parents=True, exist_ok=True)
    shim = directory / "uv"
    shim.write_text(
        f"""#!{PYTHON}
import os
import sys

args = sys.argv[1:]
if not args or args.pop(0) != "run" or not args:
    raise SystemExit("unsupported uv invocation")
command = args.pop(0)
if command == "python":
    executable = {str(PYTHON)!r}
    os.execv(executable, [executable, *args])
if command == "pytest":
    executable = {str(PYTHON)!r}
    os.execv(executable, [executable, "-m", "pytest", *args])
if command == "ruff":
    executable = {str(PROJECT_ROOT / ".venv/bin/ruff")!r}
    os.execv(executable, [executable, *args])
raise SystemExit(f"unsupported uv command: {{command}}")
""",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return directory


def run_shadow(
    label: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    cwd: Path = PROJECT_ROOT,
) -> subprocess.CompletedProcess[str]:
    return capture(
        label,
        [str(PYTHON), str(SHADOW_SUITE), *arguments],
        cwd=cwd,
        env=env,
        timeout=1200,
    )


def verify_cli(runner: Runner, env: dict[str, str]) -> None:
    help_result = run_shadow("cli-help", ["--help"], env)
    help_text = output(help_result)
    runner.check(
        "CLI help exposes independent mode and run-directory options",
        help_result.returncode == 0
        and all(
            option in help_text
            for option in (
                "--help",
                "--static",
                "--dynamic",
                "--pipeline",
                "--all",
                "--run-dir RUN_DIR",
            )
        )
        and "{--static" not in help_text,
    )

    invalid = [
        (
            "unknown",
            ["--not-an-option"],
            "unrecognized arguments: --not-an-option",
        ),
        ("missing-run-dir", ["--run-dir"], "argument --run-dir: expected one argument"),
    ]
    invalid_results = []
    for label, arguments, message in invalid:
        result = run_shadow(f"cli-invalid-{label}", arguments, env)
        text = output(result)
        invalid_results.append(
            result.returncode == 2
            and message in text
            and not any(
                marker in text for marker in ("[PASS]", "[FAIL]", "[SKIP]", "QA suite:")
            )
        )
    runner.check(
        "Invalid invocations exit 2 before checks or children start",
        all(invalid_results),
    )

    cases = [
        ("static", ["--static"], 50, 1, 0, 1),
        ("dynamic", ["--dynamic"], 58, 0, 0, 0),
        ("pipeline", ["--pipeline"], 0, 0, 2, 0),
        ("static-dynamic", ["--static", "--dynamic"], 108, 1, 0, 1),
        ("all", ["--all"], 108, 1, 2, 1),
        ("default", [], 108, 1, 2, 1),
    ]
    for label, arguments, passed, failed, skipped, status in cases:
        first = run_shadow(f"modes-{label}-first", arguments, env)
        second = run_shadow(f"modes-{label}-second", arguments, env)
        first_lines = qa_lines(first)
        second_lines = qa_lines(second)
        expected_reason = (
            "requires SCENARIO_FORGE_QA_PIPELINE=1 and --run-dir <completed run>; "
            "no live LLM endpoint in this environment"
        )
        pipeline_ok = True
        if skipped:
            text = output(first)
            pipeline_ok = (
                "sc-pipeline-01" in text
                and "sc-pipeline-02" in text
                and text.count(expected_reason) == 2
            )
        runner.check(
            f"Mode {label} is deterministic with {passed}/{failed}/{skipped}",
            exact_counts(first, passed, failed, skipped, status)
            and exact_counts(second, passed, failed, skipped, status)
            and first_lines == second_lines
            and len(first_lines) == len(set(first_lines))
            and pipeline_ok,
            f"statuses={first.returncode},{second.returncode}; lines={len(first_lines)}",
        )


def verify_property_isolation(runner: Runner, env: dict[str, str]) -> None:
    standin_root = QA_ROOT / "standin"
    standin_root.mkdir(parents=True, exist_ok=True)
    log = standin_root / "child.json"
    (standin_root / "pytest.py").write_text(
        """import json
import os
import sys
from pathlib import Path

Path(os.environ["P5_CHILD_LOG"]).write_text(
    json.dumps({
        "argv": sys.argv[1:],
        "cwd": os.getcwd(),
        "opt_in": os.environ.get("SCENARIO_FORGE_QA_PIPELINE"),
    }),
    encoding="utf-8",
)
print("P5-CHILD-STDOUT")
print("P5-CHILD-STDERR", file=sys.stderr)
raise SystemExit(7)
""",
        encoding="utf-8",
    )
    parent_cwd = Path.cwd()
    parent_env = dict(os.environ)
    standin_env = dict(env)
    standin_env["PYTHONPATH"] = os.pathsep.join(
        [str(standin_root), standin_env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    standin_env["P5_CHILD_LOG"] = str(log)
    result = run_shadow("property-standin", ["--dynamic"], standin_env)
    record = json.loads(log.read_text(encoding="utf-8")) if log.is_file() else {}
    detail_text = output(result)
    runner.check(
        "Property stand-in runs once at repository root with exact pytest arguments",
        record.get("cwd") == str(PROJECT_ROOT)
        and record.get("argv")
        == [
            *PROPERTY_NODES,
            "-v",
            "--tb=short",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ]
        and record.get("opt_in") is None,
        repr(record),
    )
    runner.check(
        "Property child failure preserves separate streams and 57/1 result",
        exact_counts(result, 57, 1, 0, 1)
        and "rc=7" in detail_text
        and "stdout=" in detail_text
        and "stderr=" in detail_text
        and "P5-CHILD-STDOUT" in detail_text
        and "P5-CHILD-STDERR" in detail_text
        and (CAPTURES / "property-standin/stdout.txt").is_file()
        and (CAPTURES / "property-standin/stderr.txt").is_file()
        and (CAPTURES / "property-standin/exit.txt").is_file(),
    )
    real_first = run_shadow("property-real-first", ["--dynamic"], env)
    real_second = run_shadow("property-real-second", ["--dynamic"], env)
    runner.check(
        "Real dynamic reruns are isolated and deterministically 58 PASS",
        exact_counts(real_first, 58, 0, 0, 0)
        and exact_counts(real_second, 58, 0, 0, 0)
        and qa_lines(real_first) == qa_lines(real_second)
        and "P5-CHILD-" not in output(real_first)
        and Path.cwd() == parent_cwd
        and dict(os.environ) == parent_env,
    )


def verify_nested(runner: Runner, env: dict[str, str]) -> None:
    nested = QA_ROOT / "nested/a/b"
    nested.mkdir(parents=True, exist_ok=True)
    parent_cwd = Path.cwd()
    parent_env = dict(os.environ)
    first = run_shadow("nested-first", ["--static"], env, cwd=nested)
    second = run_shadow("nested-second", ["--static"], env, cwd=nested)
    runner.check(
        "Nested absolute invocation discovers the root without parent-state changes",
        exact_counts(first, 50, 1, 0, 1)
        and exact_counts(second, 50, 1, 0, 1)
        and qa_lines(first) == qa_lines(second)
        and Path.cwd() == parent_cwd
        and dict(os.environ) == parent_env,
    )


def verify_generated(runner: Runner, env: dict[str, str]) -> None:
    generated = PROJECT_ROOT / "build/acceptance/generated"
    shadow_test = generated / "no-shadowing-invariant_acceptance_test.py"
    command = [str(PYTHON), "-m", "pytest", str(shadow_test), "-q", "-s"]
    first = capture("generated-shadow-first", command, env=env)
    second = capture("generated-shadow-second", command, env=env)

    def shadow_names(result: subprocess.CompletedProcess[str]) -> list[str]:
        return list(
            dict.fromkeys(
                line.removeprefix("PASS ").split(" ", 1)[0].split("/example_", 1)[0]
                for line in outcome_lines(result)
                if line.startswith("PASS ShadowCleanup-")
            )
        )

    expected = [f"ShadowCleanup-{index:02d}" for index in range(1, 6)]
    runner.check(
        "Generated shadow-cleanup acceptance has five deterministic PASS scenarios",
        first.returncode == second.returncode == 0
        and shadow_names(first) == shadow_names(second) == expected
        and not any(
            line.startswith(("FAIL ShadowCleanup-", "SKIP ShadowCleanup-"))
            for result in (first, second)
            for line in outcome_lines(result)
        ),
        f"names={shadow_names(first)}",
    )

    phase_counts: list[int] = []
    for phase, filename, expected_count in (
        ("phase4", "phase4_qa_refresh_migration_acceptance_test.py", 21),
        ("phase5", "phase5_qa_shadow_cleanup_migration_acceptance_test.py", 19),
    ):
        result = capture(
            f"generated-{phase}",
            [str(PYTHON), "-m", "pytest", str(generated / filename), "-q", "-s"],
            env=env,
            timeout=1800,
        )
        lines = outcome_lines(result)
        passes = [line for line in lines if line.startswith("PASS ")]
        phase_counts.append(len(passes))
        runner.check(
            f"Generated {phase.title()} acceptance reports {expected_count} PASS",
            result.returncode == 0
            and len(passes) == expected_count
            and not any(line.startswith(("FAIL ", "SKIP ")) for line in lines),
            f"exit={result.returncode}; count={len(passes)}",
        )
    runner.check(
        "Generated Phase 4 and Phase 5 scenario total is 40",
        phase_counts == [21, 19],
        repr(phase_counts),
    )


def show_bytes(ref: str, path: str) -> bytes | None:
    result = git("show", f"{ref}:{path}")
    return result.stdout if result.returncode == 0 else None


def tree_suites(ref: str) -> set[str]:
    result = git("ls-tree", "-r", "--name-only", ref, "--", "acceptance/qa")
    return {
        line
        for line in result.stdout.decode().splitlines()
        if line.endswith("/qa_suite.py")
    }


def verify_scope(runner: Runner) -> None:
    shadow = "acceptance/qa/shadow-cleanup/qa_suite.py"
    phase4 = "acceptance/qa/phase4-qa-refresh-migration/qa_suite.py"
    baseline_suites = tree_suites(BASE_COMMIT)
    head_suites = tree_suites("HEAD")
    unchanged_others = all(
        show_bytes(BASE_COMMIT, path) == show_bytes("HEAD", path)
        for path in (baseline_suites & head_suites) - {shadow, phase4}
    )
    runner.check(
        "Exactly one pre-existing Phase 5 suite changed, with Phase 4 excepted",
        show_bytes(BASE_COMMIT, shadow) != show_bytes("HEAD", shadow)
        and unchanged_others
        and not (baseline_suites - head_suites),
        f"baseline-only={sorted(baseline_suites - head_suites)}",
    )

    protected = "acceptance/runtime_features/shadow_cleanup.py"
    current = (PROJECT_ROOT / protected).read_bytes()
    runner.check(
        "Protected shadow runtime and registration remain byte-for-byte unchanged",
        show_bytes(BASE_COMMIT, protected) == current
        and hashlib.sha256(current).hexdigest()
        == "bdcd184067c345559ac7646d9b24723c4a85eccc1e1ac3a8d0a7bd69e50adc45",
    )

    src_diff = git("diff", "--name-only", f"{BASE_COMMIT}..HEAD", "--", "src")
    src_status = git("status", "--porcelain=v1", "--untracked-files=all", "--", "src")
    runner.check(
        "No committed or worktree production source change exists",
        not src_diff.stdout.strip() and not src_status.stdout.strip(),
    )

    fixed_paths = (
        ".factory/swarmforge/config.sh",
        "scripts/acceptance.sh",
        "scripts/quality.sh",
        ".gitignore",
    )
    unchanged = all(
        show_bytes(BASE_COMMIT, path) == show_bytes("HEAD", path)
        for path in fixed_paths
    )
    config = (PROJECT_ROOT / fixed_paths[0]).read_text(encoding="utf-8")
    quality = (PROJECT_ROOT / fixed_paths[2]).read_text(encoding="utf-8")
    runner.check(
        "Configuration, generation commands, and analysis scopes are unchanged",
        unchanged
        and 'SWARMFORGE_FILE_POLICY="generated-output"' in config
        and 'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and 'SWARMFORGE_MUTATION_CMD="mutate4py src/' in config
        and "ruff check src acceptance" in quality
        and "ruff format --check src acceptance" in quality,
    )


def verify_release(runner: Runner, env: dict[str, str]) -> None:
    static = run_shadow("release-static", ["--static"], env)
    dynamic = run_shadow("release-dynamic", ["--dynamic"], env)
    pipeline = run_shadow("release-pipeline", ["--pipeline"], env)
    all_modes = run_shadow("release-all", ["--all"], env)
    runner.check(
        "Release shadow modes preserve 50/1, 58, two SKIP baseline",
        exact_counts(static, 50, 1, 0, 1)
        and exact_counts(dynamic, 58, 0, 0, 0)
        and exact_counts(pipeline, 0, 0, 2, 0)
        and exact_counts(all_modes, 108, 1, 2, 1),
    )

    quality = capture(
        "release-quality",
        [str(PROJECT_ROOT / "scripts/quality.sh")],
        env=env,
        timeout=1800,
    )
    runner.check(
        "Project quality script passes",
        quality.returncode == 0 and "All checks passed!" in output(quality),
        f"exit={quality.returncode}",
    )

    default = capture(
        "release-default-acceptance",
        [str(PROJECT_ROOT / "scripts/acceptance.sh"), "--test"],
        env=env,
        timeout=3600,
    )
    clean_default = ANSI.sub("", output(default))
    runner.check(
        "Default acceptance passes 104 tests with four warnings and opt-in unset",
        default.returncode == 0
        and re.search(r"\b104 passed, 4 warnings\b", clean_default) is not None
        and "FAIL " not in clean_default,
        f"exit={default.returncode}",
    )


def verify_hardening_evidence(runner: Runner) -> None:
    mutation_root = (
        PROJECT_ROOT / "tmp/hardender-phase5-hardening/gherkin/phase5/mutations"
    )
    mutations = sorted(path for path in mutation_root.iterdir() if path.is_dir())
    mutation_features = [
        path / "feature.json" for path in mutations if (path / "feature.json").is_file()
    ]
    score = (PROJECT_ROOT / ".swarmforge/reports/mutation-score.txt").read_text(
        encoding="utf-8"
    )
    runner.check(
        "Hardener soft-mutation evidence contains 46 of 46 mutation artifacts",
        len(mutations) == len(mutation_features) == 46,
        f"directories={len(mutations)} artifacts={len(mutation_features)}",
    )
    runner.check(
        "Hardener mutation score report records 100",
        score.strip() == "score: 100",
        score.strip(),
    )


def verify_hygiene(
    runner: Runner,
    before_status: bytes,
    before_digests: dict[str, str],
) -> None:
    tracked = git(
        "ls-files",
        "--",
        "build/acceptance",
        "build/acceptance-mutation",
        "tmp/qa-phase5-shadow-cleanup-migration",
        "coverage.lcov",
        "lcov.info",
        "lcov_stpa_report.info",
    )
    roots = [
        PROJECT_ROOT / "build/acceptance/ir",
        PROJECT_ROOT / "build/acceptance/dry",
        PROJECT_ROOT / "build/acceptance/generated",
    ]
    runner.check(
        "Generated acceptance, mutation, coverage, and QA artifacts are untracked",
        not tracked.stdout.strip()
        and all(root.is_dir() and any(root.iterdir()) for root in roots),
        tracked.stdout.decode().strip(),
    )

    project_bytes = str(PROJECT_ROOT).encode()
    offenders = [
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "build/acceptance/generated/metadata").glob(
            "*.json"
        )
        if project_bytes in path.read_bytes()
    ]
    runner.check(
        "Generated metadata contains no absolute checkout path",
        not offenders,
        repr(offenders),
    )

    after_status, after_digests = worktree_snapshot()
    runner.check(
        "All unrelated worktree statuses and content digests are unchanged",
        before_status == after_status and before_digests == after_digests,
        "status or digest changed during executable QA",
    )


def main() -> int:
    QA_ROOT.mkdir(parents=True, exist_ok=True)
    CAPTURES.mkdir(parents=True, exist_ok=True)
    uv_bin = make_uv_shim()
    before_status, before_digests = worktree_snapshot()
    runner = Runner()
    print("End-to-end QA: Phase 5 shadow-cleanup migration", flush=True)

    with ContactSentinel() as sentinel:
        url = f"http://127.0.0.1:{sentinel.port}/v1"
        child_env = environment(
            SCENARIO_FORGE_QA_PIPELINE=None,
            SCENARIO_FORGE_MODEL_BASE_URL=url,
            OPENAI_BASE_URL=url,
            SCENARIO_FORGE_API_KEY="qa-contact-sentinel",
            OPENAI_API_KEY="qa-contact-sentinel",
            PATH=f"{uv_bin}:{os.environ.get('PATH', '')}",
        )
        verify_cli(runner, child_env)
        verify_property_isolation(runner, child_env)
        verify_nested(runner, child_env)
        verify_generated(runner, child_env)
        verify_release(runner, child_env)

    runner.check(
        "No command contacted a configured model endpoint",
        sentinel.contacts == 0,
        f"contacts={sentinel.contacts}",
    )
    verify_scope(runner)
    verify_hardening_evidence(runner)
    verify_hygiene(runner, before_status, before_digests)
    return runner.finish()


if __name__ == "__main__":
    raise SystemExit(main())
