"""Small, deterministic helpers shared by command-line acceptance QA suites.

The harness deliberately has no dependency on the acceptance runtime.  QA
suites use it to report checks, run child commands, and preserve the child
process observations that make a run reproducible.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


def find_project_root(start: Path | str | None = None) -> Path:
    """Find the nearest ancestor containing the repository manifest."""
    candidate = Path(start or __file__).resolve()
    if candidate.is_file():
        candidate = candidate.parent
    for path in (candidate, *candidate.parents):
        if (path / "pyproject.toml").is_file():
            return path
    raise FileNotFoundError(f"could not find project root from {candidate}")


PROJECT_ROOT = find_project_root()


@dataclass(frozen=True)
class CheckResult:
    """One recorded QA check and its optional diagnostic detail."""

    name: str
    passed: bool
    detail: str = ""
    status: str | None = None

    def __str__(self) -> str:
        status = self.status or ("PASS" if self.passed else "FAIL")
        text = f"  [{status}] {self.name}"
        if self.detail:
            text += f"\n         {self.detail}"
        return text


class QARunner:
    """Record checks once, emit them in order, and return a stable exit code."""

    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def record(self, name: str, passed: bool, detail: str = "") -> CheckResult:
        result = CheckResult(name, bool(passed), detail)
        self.results.append(result)
        print(result, flush=True)
        return result

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.record(name, passed, detail)
        return bool(passed)

    def skip(self, name: str, reason: str) -> CheckResult:
        """Record a visible skip without treating it as a failure."""
        result = CheckResult(name, True, reason, "SKIP")
        self.results.append(result)
        print(result, flush=True)
        return result

    def summary(self) -> int:
        passed = sum(
            result.passed and result.status != "SKIP" for result in self.results
        )
        failed = sum(
            not result.passed and result.status != "SKIP" for result in self.results
        )
        print(f"\nQA suite: {passed} passed, {failed} failed", flush=True)
        return 0 if failed == 0 else 1


def child_env(
    base: Mapping[str, str] | None = None,
    **updates: str | None,
) -> dict[str, str]:
    """Copy the parent environment and apply child-only updates.

    A ``None`` update removes a variable from the child without mutating
    ``os.environ`` or a caller-owned mapping.
    """
    environment = dict(os.environ if base is None else base)
    for key, value in updates.items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = value
    return environment


def run_command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | float | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a child command with separate text streams and exit capture."""
    return subprocess.run(
        list(argv),
        cwd=str(cwd or PROJECT_ROOT),
        env=dict(env) if env is not None else None,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def fresh_capture_dir(label: str, *, root: Path) -> Path:
    """Create an empty capture directory for one labeled child run."""
    target = Path(root) / "captures" / label
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    return target


def write_capture(
    label: str,
    result: subprocess.CompletedProcess[str],
    *,
    root: Path,
) -> Path:
    """Write stdout, stderr, and exit status into a fresh capture directory."""
    target = fresh_capture_dir(label, root=root)
    (target / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (target / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (target / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return target


__all__ = [
    "PROJECT_ROOT",
    "CheckResult",
    "QARunner",
    "child_env",
    "find_project_root",
    "fresh_capture_dir",
    "run_command",
    "write_capture",
]
