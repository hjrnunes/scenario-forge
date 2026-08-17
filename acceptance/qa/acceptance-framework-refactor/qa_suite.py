#!/usr/bin/env python3
"""End-to-end QA suite for the acceptance framework refactor.

Executable form of ``acceptance/qa/acceptance-framework-refactor/qa_suite.md``.
Exercises only checked-in command-line entrypoints and the mutation worker's
JSON-lines interface. Does not import project modules.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
QA_ROOT = PROJECT_ROOT / "tmp" / "qa-acceptance-framework"
FEATURES_DIR = PROJECT_ROOT / "features"
ACCEPTANCE_SH = PROJECT_ROOT / "scripts" / "acceptance.sh"
QUALITY_SH = PROJECT_ROOT / "scripts" / "quality.sh"
CONFIG_SH = PROJECT_ROOT / ".factory" / "swarmforge" / "config.sh"
RUNNER_ADAPTER = PROJECT_ROOT / "acceptance" / "runner_adapter.py"
AFR_TEST = (
    "build/acceptance/generated/acceptance_framework_refactor_acceptance_test.py"
    "::test_acceptance"
)
NESTED_TEST = (
    "build/acceptance/generated/stage1_ordering_acceptance_test.py::test_acceptance"
)
JPKW_FALLBACK = (
    "JPKW-07-FALLBACK .feature file uses gherkin_raw when structured "
    "Gherkin is unavailable"
)
LIVE_MARKER = 'live LLM acceptance is enabled with SCENARIO_FORGE_QA_PIPELINE "1"'
OPT_IN_REASON = 'SCENARIO_FORGE_QA_PIPELINE "1"'
AFR_EXPECTED = (
    "AFR-01",
    "AFR-02",
    "AFR-03",
    "AFR-04",
    "AFR-05",
    "AFR-06",
    "AFR-07",
    "AFR-08",
    "AFR-09",
)


class CheckResult:
    def __init__(self, name: str, passed: bool, detail: str = "") -> None:
        self.name = name
        self.passed = passed
        self.detail = detail

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        text = f"  [{status}] {self.name}"
        if self.detail:
            text += f"\n         {self.detail}"
        return text


class QARunner:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def record(self, name: str, passed: bool, detail: str = "") -> None:
        result = CheckResult(name, passed, detail)
        self.results.append(result)
        print(result, flush=True)

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.record(name, passed, detail)
        return passed

    def summary(self) -> int:
        passed = sum(1 for item in self.results if item.passed)
        failed = len(self.results) - passed
        print(f"\nQA suite: {passed} passed, {failed} failed", flush=True)
        return 0 if failed == 0 else 1


def run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd or PROJECT_ROOT),
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def write_capture(label: str, result: subprocess.CompletedProcess[str]) -> Path:
    target = QA_ROOT / "captures" / label
    target.mkdir(parents=True, exist_ok=True)
    (target / "stdout.txt").write_text(result.stdout)
    (target / "stderr.txt").write_text(result.stderr)
    (target / "exit.txt").write_text(f"{result.returncode}\n")
    return target


def child_env(**updates: str | None) -> dict[str, str]:
    env = os.environ.copy()
    for key, value in updates.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def feature_paths() -> list[Path]:
    return sorted(FEATURES_DIR.rglob("*.feature"))


def qa_layout() -> dict[str, Path]:
    return {
        "ir": QA_ROOT / "ir",
        "dry": QA_ROOT / "dry",
        "generated": QA_ROOT / "generated",
        "mutation": QA_ROOT / "mutation",
    }


def generation_env() -> dict[str, str]:
    layout = qa_layout()
    return child_env(
        SWARMFORGE_FEATURES_DIR="features",
        SWARMFORGE_ACCEPTANCE_IR_DIR=str(layout["ir"].relative_to(PROJECT_ROOT)),
        SWARMFORGE_ACCEPTANCE_DRY_DIR=str(layout["dry"].relative_to(PROJECT_ROOT)),
        SWARMFORGE_ACCEPTANCE_GENERATED_DIR=str(
            layout["generated"].relative_to(PROJECT_ROOT)
        ),
        SWARMFORGE_ACCEPTANCE_MUTATION_DIR=str(
            layout["mutation"].relative_to(PROJECT_ROOT)
        ),
        SCENARIO_FORGE_QA_PIPELINE=None,
        SCENARIO_FORGE_MODEL_BASE_URL="http://127.0.0.1:9/v1",
    )


def collect_generated(root: Path, pattern: str) -> set[str]:
    if not root.exists():
        return set()
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob(pattern)
        if path.is_file()
    }


def file_digest_map(root: Path, pattern: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not root.exists():
        return mapping
    for path in root.rglob(pattern):
        if path.is_file():
            mapping[path.relative_to(root).as_posix()] = path.read_text()
    return mapping


def metadata_has_absolute_paths(path: Path) -> list[str]:
    problems: list[str] = []
    data = json.loads(path.read_text())
    for key in ("feature_path", "ir_path"):
        value = data.get(key, "")
        if not isinstance(value, str) or not value:
            problems.append(f"{path.name}: missing {key}")
            continue
        if Path(value).is_absolute() or value.startswith(str(PROJECT_ROOT)):
            problems.append(f"{path.name}: {key} is absolute ({value})")
    return problems


def parse_runtime_lines(text: str) -> dict[str, list[str]]:
    found = {"PASS": [], "FAIL": [], "SKIP": []}
    for raw in text.splitlines():
        line = raw.strip()
        for status in found:
            if line.startswith(f"{status} "):
                found[status].append(line)
    return found


def write_ir(path: Path, name: str, step_text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "name": name,
                "background": [],
                "scenarios": [
                    {
                        "name": name,
                        "steps": [{"keyword": "Given", "text": step_text}],
                        "examples": [],
                    }
                ],
            }
        )
        + "\n"
    )


def qa_afr_01(runner: QARunner) -> None:
    layout = qa_layout()
    for path in layout.values():
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    first = run_command([str(ACCEPTANCE_SH)], env=generation_env(), timeout=2400)
    write_capture("qa-afr-01-generate", first)
    runner.check(
        "QA-AFR-01 generate completes",
        first.returncode in {0, 1},
        f"exit={first.returncode}",
    )
    first_ir = collect_generated(layout["ir"], "*.json")
    first_tests = collect_generated(layout["generated"], "*_acceptance_test.py")
    first_meta = collect_generated(layout["generated"] / "metadata", "*.json")
    first_contents = {
        "ir": file_digest_map(layout["ir"], "*.json"),
        "tests": file_digest_map(layout["generated"], "*_acceptance_test.py"),
        "meta": file_digest_map(layout["generated"] / "metadata", "*.json"),
    }

    missing: list[str] = []
    for feature in feature_paths():
        rel = feature.relative_to(FEATURES_DIR)
        ir = layout["ir"] / rel.with_suffix(".json")
        dry = layout["dry"] / rel.with_suffix(".txt")
        test = layout["generated"] / f"{feature.stem}_acceptance_test.py"
        meta = layout["generated"] / "metadata" / f"{_slug(feature.stem)}.json"
        for artifact in (ir, dry, test, meta):
            if not artifact.is_file():
                missing.append(str(artifact.relative_to(PROJECT_ROOT)))
    runner.check(
        "QA-AFR-01 every feature has nested IR/DRY and flat test/metadata",
        not missing,
        f"missing={missing[:8]}",
    )

    abs_problems: list[str] = []
    for meta in (layout["generated"] / "metadata").glob("*.json"):
        abs_problems.extend(metadata_has_absolute_paths(meta))
    runner.check(
        "QA-AFR-01 metadata paths are repo-relative",
        not abs_problems,
        "; ".join(abs_problems[:6]),
    )

    stale_ir = layout["ir"] / "stale-orphan.json"
    stale_test = layout["generated"] / "stale_orphan_acceptance_test.py"
    stale_meta = layout["generated"] / "metadata" / "stale-orphan.json"
    unrelated = layout["generated"] / "keep-me.txt"
    stale_ir.write_text("{}\n")
    stale_test.write_text("# stale\n")
    stale_meta.write_text("{}\n")
    unrelated.write_text("keep\n")

    second = run_command([str(ACCEPTANCE_SH)], env=generation_env(), timeout=2400)
    write_capture("qa-afr-01-refresh", second)
    runner.check(
        "QA-AFR-01 stale mapped artifacts are removed",
        not stale_ir.exists() and not stale_test.exists() and not stale_meta.exists(),
        f"ir={stale_ir.exists()} test={stale_test.exists()} meta={stale_meta.exists()}",
    )
    runner.check(
        "QA-AFR-01 unrelated file is preserved",
        unrelated.is_file() and unrelated.read_text() == "keep\n",
    )

    third = run_command([str(ACCEPTANCE_SH)], env=generation_env(), timeout=2400)
    write_capture("qa-afr-01-repeat", third)
    after_ir = collect_generated(layout["ir"], "*.json")
    after_tests = collect_generated(layout["generated"], "*_acceptance_test.py")
    after_meta = collect_generated(layout["generated"] / "metadata", "*.json")
    after_contents = {
        "ir": file_digest_map(layout["ir"], "*.json"),
        "tests": file_digest_map(layout["generated"], "*_acceptance_test.py"),
        "meta": file_digest_map(layout["generated"] / "metadata", "*.json"),
    }
    runner.check(
        "QA-AFR-01 third refresh is deterministic",
        after_ir == first_ir
        and after_tests == first_tests
        and after_meta == first_meta
        and after_contents == first_contents,
        f"ir_delta={sorted(after_ir ^ first_ir)[:6]} "
        f"test_delta={sorted(after_tests ^ first_tests)[:6]}",
    )


def _slug(stem: str) -> str:
    cleaned = []
    last_dash = False
    for char in stem.lower():
        if char.isalnum():
            cleaned.append(char)
            last_dash = False
        elif not last_dash:
            cleaned.append("-")
            last_dash = True
    return "".join(cleaned).strip("-")


def qa_afr_02(runner: QARunner) -> subprocess.CompletedProcess[str]:
    env = child_env(
        SCENARIO_FORGE_QA_PIPELINE=None,
        SCENARIO_FORGE_MODEL_BASE_URL="http://127.0.0.1:9/v1",
    )
    result = run_command(
        ["env", "-u", "SCENARIO_FORGE_QA_PIPELINE", str(ACCEPTANCE_SH), "--test"],
        env=env,
        timeout=1800,
    )
    write_capture("qa-afr-02-test", result)
    combined = result.stdout + "\n" + result.stderr
    outcomes = parse_runtime_lines(combined)

    runner.check(
        "QA-AFR-02 quality gate runs before generated tests",
        "All checks passed!" in combined or "ruff" in combined.lower(),
        "expected ruff/quality output in --test logs",
    )
    script = ACCEPTANCE_SH.read_text()
    quality_at = script.find("scripts/quality.sh")
    pytest_at = script.find("exec uv run pytest")
    runner.check(
        "QA-AFR-02 acceptance.sh invokes quality before pytest",
        0 <= quality_at < pytest_at,
    )

    afr_lines = [
        line
        for status in outcomes.values()
        for line in status
        if "Acceptance framework refactor AFR-" in line or "AFR-0" in line
    ]
    afr_fails = [line for line in outcomes["FAIL"] if "AFR-0" in line]
    afr_passes = [line for line in outcomes["PASS"] if "AFR-0" in line]
    found_ids = {
        code for code in AFR_EXPECTED if any(code in line for line in afr_passes)
    }
    runner.check(
        "QA-AFR-02 AFR-01..09 report PASS",
        found_ids == set(AFR_EXPECTED) and not afr_fails,
        f"passed={sorted(found_ids)} fails={afr_fails} lines={len(afr_lines)}",
    )

    live_fail = [
        line
        for line in outcomes["FAIL"]
        if "requires SCENARIO_FORGE_QA_PIPELINE" in line
    ]
    live_pass = [
        line
        for line in outcomes["PASS"]
        if "requires SCENARIO_FORGE_QA_PIPELINE" in line
    ]
    live_skip = [
        line
        for line in outcomes["SKIP"]
        if "requires SCENARIO_FORGE_QA_PIPELINE" in line
    ]
    runner.check(
        "QA-AFR-02 marked live-LLM scenarios are SKIP only",
        bool(live_skip) and not live_fail and not live_pass,
        f"skip={len(live_skip)} fail={live_fail[:3]} pass={live_pass[:3]}",
    )
    runner.check(
        "QA-AFR-02 unmarked deterministic scenarios execute",
        bool(outcomes["PASS"]),
        f"pass={len(outcomes['PASS'])} fail={len(outcomes['FAIL'])} skip={len(outcomes['SKIP'])}",
    )

    jpkw_pass = any(JPKW_FALLBACK in line for line in outcomes["PASS"])
    jpkw_fail = any(JPKW_FALLBACK in line for line in outcomes["FAIL"])
    runner.check(
        "QA-AFR-02 JPKW canonical/raw fallback retains PASS",
        jpkw_pass and not jpkw_fail,
        f"pass={jpkw_pass} fail={jpkw_fail}",
    )
    return result


def qa_afr_03(runner: QARunner) -> None:
    parent_before = dict(os.environ)
    env = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    first = run_command(
        [
            "uv",
            "run",
            "pytest",
            AFR_TEST,
            "-q",
            "-s",
        ],
        env=env,
        timeout=300,
    )
    write_capture("qa-afr-03-first", first)
    second = run_command(
        [
            "uv",
            "run",
            "pytest",
            AFR_TEST,
            "-q",
            "-s",
        ],
        env=env,
        timeout=300,
    )
    write_capture("qa-afr-03-second", second)
    parent_after = dict(os.environ)

    first_out = parse_runtime_lines(first.stdout + first.stderr)
    afr05 = [
        line for status in first_out.values() for line in status if "AFR-05" in line
    ]
    runner.check(
        "QA-AFR-03 AFR-05 passing-first and failing-first rows complete",
        first.returncode == 0 and len(afr05) >= 2,
        f"exit={first.returncode} rows={afr05}",
    )
    runner.check(
        "QA-AFR-03 parent environment is unchanged",
        parent_before == parent_after,
    )
    runner.check(
        "QA-AFR-03 rerun output does not depend on the preceding run",
        parse_runtime_lines(first.stdout) == parse_runtime_lines(second.stdout)
        and first.returncode == second.returncode,
    )


def qa_afr_04(runner: QARunner) -> None:
    env = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    env.pop("PYTHONPATH", None)
    result = run_command(
        ["uv", "run", "pytest", AFR_TEST, "-q", "-s"],
        env=env,
        timeout=300,
    )
    write_capture("qa-afr-04-namespace", result)
    combined = result.stdout + result.stderr
    runner.check(
        "QA-AFR-04 AFR-07 namespaced manifest loading passes",
        result.returncode == 0 and "AFR-07" in combined and "FAIL" not in combined,
        f"exit={result.returncode}",
    )

    nested = run_command(
        ["uv", "run", "pytest", NESTED_TEST, "-q", "-s"],
        env=env,
        timeout=300,
    )
    write_capture("qa-afr-04-nested", nested)
    generated = (
        PROJECT_ROOT / "build/acceptance/generated/stage1_ordering_acceptance_test.py"
    ).read_text()
    runner.check(
        "QA-AFR-04 nested feature resolves IR under project-root IR directory",
        nested.returncode == 0
        and "build/acceptance/ir/stage1-split-reorder/stage1_ordering.json"
        in generated,
        f"exit={nested.returncode}",
    )


def _worker_response(line: str) -> dict:
    return json.loads(line)


def qa_afr_05(runner: QARunner) -> None:
    fixtures = QA_ROOT / "worker"
    fixtures.mkdir(parents=True, exist_ok=True)
    passing = fixtures / "pass.json"
    failing = fixtures / "fail.json"
    write_ir(passing, "ok", LIVE_MARKER)
    write_ir(failing, "bad", "this step is definitely unsupported xyzzy-12345")

    jobs = [
        json.dumps(
            {
                "id": "pass-1",
                "feature_json": str(passing),
                "timeout": "30s",
            }
        ),
        json.dumps(
            {
                "id": "fail-1",
                "feature_json": str(failing),
                "timeout": "30s",
            }
        ),
        "not-json",
        json.dumps(
            {
                "id": "pass-2",
                "feature_json": str(passing),
                "timeout": "30s",
            }
        ),
        json.dumps(
            {
                "id": "timeout-1",
                "feature_json": str(passing),
                "timeout": "0s",
            }
        ),
        json.dumps(
            {
                "id": "boom-1",
                "feature_json": str(passing),
                "timeout": "bogus",
            }
        ),
    ]
    payload = "\n".join(jobs) + "\n"
    env = child_env(SCENARIO_FORGE_QA_PIPELINE=None)
    result = run_command(
        [sys.executable, str(RUNNER_ADAPTER)],
        cwd=PROJECT_ROOT / "acceptance",
        env=env,
        input_text=payload,
        timeout=120,
    )
    write_capture("qa-afr-05-worker", result)
    runner.check(
        "QA-AFR-05 ready appears on stderr, not stdout",
        "runner_adapter: ready" in result.stderr
        and "runner_adapter: ready" not in result.stdout,
        f"stderr={result.stderr.strip()!r}",
    )
    runner.check("QA-AFR-05 worker exits 0 after stdin close", result.returncode == 0)

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    runner.check(
        "QA-AFR-05 one JSON response per input line",
        len(lines) == len(jobs),
        f"responses={len(lines)} jobs={len(jobs)} stdout={result.stdout!r}",
    )
    if len(lines) != len(jobs):
        return

    parsed = [_worker_response(line) for line in lines]
    pass_job, fail_job, bad_job, pass_again, timeout_job, boom_job = parsed

    runner.check(
        "QA-AFR-05 passing IR maps to test_success",
        pass_job["id"] == "pass-1"
        and pass_job["outcome"] == "test_success"
        and "output" in pass_job
        and "error" in pass_job
        and isinstance(pass_job["duration"], int)
        and pass_job["duration"] >= 0
        and "SKIP" in pass_job["output"],
        json.dumps(pass_job)[:300],
    )
    runner.check(
        "QA-AFR-05 unsupported step maps to test_failure",
        fail_job["id"] == "fail-1" and fail_job["outcome"] == "test_failure",
        json.dumps(fail_job)[:300],
    )
    runner.check(
        "QA-AFR-05 malformed JSON stays in-band as unknown infrastructure_error",
        bad_job["id"] == "unknown"
        and bad_job["outcome"] == "infrastructure_error"
        and pass_again["id"] == "pass-2"
        and pass_again["outcome"] == "test_success",
        json.dumps({"bad": bad_job, "next": pass_again})[:400],
    )
    runner.check(
        "QA-AFR-05 timeout maps to infrastructure_error",
        timeout_job["id"] == "timeout-1"
        and timeout_job["outcome"] == "infrastructure_error",
        json.dumps(timeout_job)[:300],
    )
    runner.check(
        "QA-AFR-05 subprocess/worker exception maps to infrastructure_error",
        boom_job["id"] == "boom-1" and boom_job["outcome"] == "infrastructure_error",
        json.dumps(boom_job)[:300],
    )


def qa_afr_06(runner: QARunner) -> None:
    status = run_command(["git", "status", "--short", "--untracked-files=all"])
    write_capture("qa-afr-06-status", status)
    tracked_generated = [
        line
        for line in status.stdout.splitlines()
        if not line.startswith("?")
        and (
            "build/acceptance/" in line
            or "build/acceptance-mutation" in line
            or line.endswith("lcov.info")
            or "tmp/qa-acceptance-framework/" in line
        )
    ]
    runner.check(
        "QA-AFR-06 generated and temporary QA artifacts are untracked",
        not tracked_generated,
        "; ".join(tracked_generated[:8]),
    )

    config = CONFIG_SH.read_text()
    runner.check(
        "QA-AFR-06 permanent CRAP/DRY/mutation stay scoped to src/",
        'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and "mutate4py src/" in config,
    )
    quality = QUALITY_SH.read_text()
    runner.check(
        "QA-AFR-06 quality.sh still checks src and acceptance",
        "uv run ruff check src acceptance" in quality
        and "uv run ruff format --check src acceptance" in quality,
    )
    src_diff = run_command(["git", "diff", "--name-only", "799f5a9", "--", "src"])
    runner.check(
        "QA-AFR-06 no production src/ change for this refactor",
        src_diff.stdout.strip() == "",
        src_diff.stdout.strip(),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="skip QA-AFR-01 full generation against temporary output trees",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    QA_ROOT.mkdir(parents=True, exist_ok=True)
    runner = QARunner()
    print("End-to-end QA: acceptance framework refactor", flush=True)
    if not args.skip_generate:
        qa_afr_01(runner)
    else:
        runner.record("QA-AFR-01 skipped by --skip-generate", True)
    qa_afr_02(runner)
    qa_afr_03(runner)
    qa_afr_04(runner)
    qa_afr_05(runner)
    qa_afr_06(runner)
    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
