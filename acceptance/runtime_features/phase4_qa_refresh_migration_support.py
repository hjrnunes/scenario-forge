"""Process and filesystem helpers for the Phase 4 QA migration handlers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from runtime_shared import PROJECT_ROOT, World

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


def _generated_test_path(source_feature: str) -> Path:
    return _GENERATED_ROOT / f"{Path(source_feature).stem}_acceptance_test.py"


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
    _finish_sentinel(world)
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
    world.p4qrm_endpoint_environment = {
        name: os.environ.get(name) for name in _ENDPOINT_VARIABLES
    }
    for name in _ENDPOINT_VARIABLES:
        os.environ[name] = sentinel.url if "BASE_URL" in name else "phase4-sentinel-key"


def _finish_sentinel(world: World) -> None:
    sentinel = getattr(world, "p4qrm_sentinel", None)
    if sentinel is not None:
        world.p4qrm_endpoint_contacts = sentinel.close()
        world.p4qrm_sentinel = None
    original_environment = getattr(world, "p4qrm_endpoint_environment", None)
    if original_environment is not None:
        for name, value in original_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        world.p4qrm_endpoint_environment = None


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
