from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
_SUITE = _PROJECT_ROOT / "acceptance" / "qa" / "output-ingress-zone" / "qa_suite.py"
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))
sys.path.insert(0, str(_SUITE.parent))

from qa_harness import child_env, find_project_root, run_command  # noqa: E402
from qa_suite import (  # noqa: E402
    EXPECTED,
    OutputIngressQARunner,
    generated_profile,
    main,
    observed_values,
    require_cli_success,
    run_cli,
)

_NORMALIZED_PROFILE = """\
zones_active:
  - input
  - reasoning
entry_points:
  - name: Audit Logs
    direction: output
    ingress_zone: null
  - name: Notifications
    direction: output
    ingress_zone: null
  - name: User Prompt
    direction: input
    ingress_zone: reasoning
  - name: Admin Console
    direction: bidirectional
    ingress_zone: input
confidence: high
kc_subcodes:
  - KC1.1
"""


def _success_proc(stdout: str = "Pipeline complete.\n") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["uv", "run", "scenario-forge", "generate"],
        0,
        stdout=stdout,
        stderr="",
    )


def _write_profile(directory: Path, text: str = _NORMALIZED_PROFILE) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "capability-profile.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_output_ingress_suite_uses_shared_harness_without_local_framework() -> None:
    tree = ast.parse(_SUITE.read_text(encoding="utf-8"), filename=str(_SUITE))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]

    assert "qa_harness" in imports
    assert not any(
        isinstance(node, ast.ClassDef) and node.name in {"CheckResult", "QARunner"}
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.ClassDef) and node.name == "OutputIngressQARunner"
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_command"
        for node in ast.walk(tree)
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "child_env"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.ImportFrom) and node.module == "argparse"
        for node in ast.walk(tree)
    )


def test_output_ingress_cli_has_no_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _SUITE.read_text(encoding="utf-8")
    assert "argparse" not in source
    assert "--static" not in source
    assert "--pipeline" not in source
    assert "add_argument" not in source

    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("qa_suite.QA_ROOT", tmp_path / "tmp" / "qa-output-ingress-zone")
    monkeypatch.setattr(sys, "argv", [str(_SUITE), "--help", "--static", "--bogus"])

    def fake_run_cli(_profile: Path, out_dir: Path, *_args: Path):
        _write_profile(out_dir)
        return _success_proc()

    monkeypatch.setattr("qa_suite.run_cli", fake_run_cli)
    assert main() == 0
    output = capsys.readouterr()
    assert "unrecognized arguments" not in output.err
    assert "usage:" not in output.out.lower()
    assert output.out.splitlines()[0].startswith("PASS QA-OIZ-01")


def test_output_ingress_success_preserves_pass_order_and_artifact_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    qa_root = tmp_path / "tmp" / "qa-output-ingress-zone"
    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("qa_suite.QA_ROOT", qa_root)
    calls: list[tuple[Path, Path]] = []

    def fake_run_cli(profile: Path, out_dir: Path, *_args: Path):
        calls.append((profile, out_dir))
        _write_profile(out_dir)
        return _success_proc()

    monkeypatch.setattr("qa_suite.run_cli", fake_run_cli)

    assert main() == 0
    output = capsys.readouterr().out.splitlines()
    assert output[0] == (
        "PASS QA-OIZ-01: contradictory output ingress zone was normalized"
    )
    assert output[1] == "PASS QA-OIZ-02: normalized profile reuse was idempotent"
    assert output[2].startswith("Artifacts: ")
    assert "QA suite:" not in "\n".join(output)
    assert "[PASS]" not in "\n".join(output)

    artifact = Path(output[2].removeprefix("Artifacts: "))
    work_dirs = list(qa_root.glob("run-*"))
    assert len(work_dirs) == 1
    work_dir = work_dirs[0]
    assert work_dir.name.startswith("run-")
    assert artifact == work_dir.relative_to(tmp_path)
    assert (work_dir / "use-case.txt").is_file()
    assert (work_dir / "risk-extraction.json").is_file()
    assert (work_dir / "mappings.sssom.tsv").is_file()
    assert len(calls) == 2
    assert calls[0][1] == work_dir / "output-1"
    assert calls[1][1] == work_dir / "output-2"
    assert calls[1][0] == work_dir / "output-1" / "capability-profile.yaml"


def test_output_ingress_short_circuits_before_second_generate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("qa_suite.QA_ROOT", tmp_path / "tmp" / "qa-output-ingress-zone")
    calls: list[Path] = []

    def fake_run_cli(_profile: Path, out_dir: Path, *_args: Path):
        calls.append(out_dir)
        return subprocess.CompletedProcess(
            ["uv", "run", "scenario-forge", "generate"],
            3,
            stdout="",
            stderr="cannot have an ingress zone",
        )

    monkeypatch.setattr("qa_suite.run_cli", fake_run_cli)

    with pytest.raises(AssertionError, match="QA-OIZ-01 exited 3"):
        main()

    assert len(calls) == 1
    assert calls[0].name == "output-1"
    output = capsys.readouterr().out
    assert "PASS QA-OIZ-01" not in output
    assert "PASS QA-OIZ-02" not in output
    assert "Artifacts:" not in output


def test_output_ingress_unexpected_profile_skips_second_generate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("qa_suite.QA_ROOT", tmp_path / "tmp" / "qa-output-ingress-zone")
    calls: list[Path] = []

    def fake_run_cli(_profile: Path, out_dir: Path, *_args: Path):
        calls.append(out_dir)
        _write_profile(
            out_dir,
            """\
entry_points:
  - name: Audit Logs
    direction: output
    ingress_zone: reasoning
""",
        )
        return _success_proc()

    monkeypatch.setattr("qa_suite.run_cli", fake_run_cli)

    with pytest.raises(AssertionError, match="QA-OIZ-01 generated unexpected entry points"):
        main()

    assert len(calls) == 1
    assert calls[0].name == "output-1"
    output = capsys.readouterr().out
    assert "PASS QA-OIZ-02" not in output
    assert "Artifacts:" not in output


def test_output_ingress_child_argv_cwd_env_and_stream_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    seen: dict[str, object] = {}

    def fake_run_command(argv, *, cwd=None, env=None, timeout=None, input_text=None):
        seen["argv"] = list(argv)
        seen["cwd"] = Path(cwd) if cwd is not None else None
        seen["env"] = dict(env) if env is not None else None
        seen["timeout"] = timeout
        seen["input_text"] = input_text
        seen["parent_cwd"] = Path.cwd()
        return SimpleNamespace(
            returncode=0,
            stdout="Pipeline complete.\n",
            stderr="child-stderr\n",
        )

    monkeypatch.setattr("qa_suite.run_command", fake_run_command)
    profile = tmp_path / "capability-profile.yaml"
    out_dir = tmp_path / "output"
    use_case = tmp_path / "use-case.txt"
    risks = tmp_path / "risks.json"
    mapping = tmp_path / "map.tsv"
    for path in (profile, use_case, risks, mapping):
        path.write_text("", encoding="utf-8")

    result = run_cli(profile, out_dir, use_case, risks, mapping)

    assert result.returncode == 0
    assert result.stdout == "Pipeline complete.\n"
    assert result.stderr == "child-stderr\n"
    assert seen["argv"] == [
        "uv",
        "run",
        "scenario-forge",
        "generate",
        "--use-case",
        f"@{use_case}",
        "--risk-extraction",
        str(risks),
        "--sssom",
        str(mapping),
        "--output-dir",
        str(out_dir),
        "--profile",
        str(profile),
        "--base-url",
        "http://127.0.0.1:1/v1",
        "--api-key",
        "qa-unused",
        "--model",
        "qa-no-network",
        "--no-eval",
    ]
    assert seen["cwd"] == _PROJECT_ROOT
    assert seen["timeout"] == 120
    assert seen["input_text"] is None
    assert seen["env"] is not None
    assert seen["env"]["QA_PARENT_ONLY"] == "present"
    assert seen["parent_cwd"] == nested
    assert Path.cwd() == nested
    assert os.environ["QA_PARENT_ONLY"] == "present"
    assert find_project_root() == _PROJECT_ROOT


def test_output_ingress_require_cli_success_keeps_stdout_and_stderr_separate() -> None:
    ok = subprocess.CompletedProcess(
        ["cmd"],
        0,
        stdout="Pipeline complete.\n",
        stderr="validationerror cannot have an ingress zone\n",
    )
    with pytest.raises(AssertionError, match="reported entry-point validation failure"):
        require_cli_success("QA-OIZ-01", ok)

    missing = subprocess.CompletedProcess(
        ["cmd"], 0, stdout="still running\n", stderr=""
    )
    with pytest.raises(AssertionError, match="omitted completion message"):
        require_cli_success("QA-OIZ-01", missing)


def test_output_ingress_adapter_defers_legacy_pass_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = OutputIngressQARunner()
    runner.check("QA-OIZ-01: contradictory output ingress zone was normalized", True)
    runner.check("QA-OIZ-02: normalized profile reuse was idempotent", True)
    assert capsys.readouterr().out == ""

    artifacts = tmp_path / "run-fixture"
    artifacts.mkdir()
    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    assert runner.summary(artifacts) == 0
    output = capsys.readouterr().out.splitlines()
    assert output == [
        "PASS QA-OIZ-01: contradictory output ingress zone was normalized",
        "PASS QA-OIZ-02: normalized profile reuse was idempotent",
        "Artifacts: run-fixture",
    ]


def test_output_ingress_adapter_failure_does_not_print_pass(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = OutputIngressQARunner()
    with pytest.raises(AssertionError, match="boom"):
        runner.check("QA-OIZ-01: contradictory output ingress zone was normalized", False, "boom")
    assert capsys.readouterr().out == ""


def test_output_ingress_work_dirs_are_left_in_place_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    qa_root = tmp_path / "tmp" / "qa-output-ingress-zone"
    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("qa_suite.QA_ROOT", qa_root)

    def fake_run_cli(_profile: Path, out_dir: Path, *_args: Path):
        _write_profile(out_dir)
        return _success_proc()

    monkeypatch.setattr("qa_suite.run_cli", fake_run_cli)
    assert main() == 0
    leftover = list(qa_root.glob("run-*"))
    assert leftover
    assert all(path.is_dir() for path in leftover)
    assert (leftover[0] / "output-1" / "capability-profile.yaml").is_file()
    assert (leftover[0] / "output-2" / "capability-profile.yaml").is_file()


def test_output_ingress_work_dirs_are_left_in_place_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    qa_root = tmp_path / "tmp" / "qa-output-ingress-zone"
    monkeypatch.setattr("qa_suite.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("qa_suite.QA_ROOT", qa_root)

    def fake_run_cli(_profile: Path, out_dir: Path, *_args: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "partial.txt").write_text("partial\n", encoding="utf-8")
        return subprocess.CompletedProcess(["uv"], 1, stdout="", stderr="boom")

    monkeypatch.setattr("qa_suite.run_cli", fake_run_cli)
    with pytest.raises(AssertionError):
        main()
    leftover = list(qa_root.glob("run-*"))
    assert leftover
    assert (leftover[0] / "output-1" / "partial.txt").is_file()
    assert not (leftover[0] / "output-2").exists()


def test_output_ingress_observed_values_and_generated_profile(tmp_path: Path) -> None:
    path = _write_profile(tmp_path / "output-1")
    assert generated_profile(tmp_path / "output-1") == path
    assert observed_values(path) == EXPECTED
    _write_profile(tmp_path / "output-1" / "nested")
    with pytest.raises(AssertionError, match="Expected one generated capability profile"):
        generated_profile(tmp_path / "output-1")


def test_output_ingress_run_command_defaults_to_project_root_from_nested_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "invocation"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)

    result = run_command(
        [sys.executable, "-c", "from pathlib import Path; print(Path.cwd())"]
    )

    assert result.returncode == 0
    assert result.stdout.strip() == str(_PROJECT_ROOT)
    assert result.stderr == ""
    assert Path.cwd() == nested


def test_output_ingress_child_env_does_not_mutate_parent() -> None:
    parent = {"KEEP": "yes", "DROP": "no"}
    isolated = child_env(parent, DROP=None, CHILD="only")
    assert parent == {"KEEP": "yes", "DROP": "no"}
    assert isolated == {"KEEP": "yes", "CHILD": "only"}
