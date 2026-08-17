from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance" / "qa"))

from qa_harness import (  # noqa: E402
    QARunner,
    child_env,
    find_project_root,
    run_command,
    write_capture,
)
from runtime_features import acceptance_refresh  # noqa: E402


def test_qa_runner_reports_recording_order_and_deterministic_status(capsys):
    runner = QARunner()

    runner.record("first", True)
    runner.record("second", False, "details")

    assert runner.summary() == 1
    output = capsys.readouterr().out
    assert output.index("[PASS] first") < output.index("[FAIL] second")
    assert output.count("[PASS] first") == 1
    assert output.count("[FAIL] second") == 1
    assert "         details" in output
    assert "QA suite: 1 passed, 1 failed" in output


def test_qa_child_execution_is_isolated_and_captures_streams(tmp_path, monkeypatch):
    original_cwd = Path.cwd()
    monkeypatch.setenv("QA_PARENT_ONLY", "present")
    command = [
        sys.executable,
        "-c",
        (
            "import os, pathlib, sys; "
            "print(pathlib.Path.cwd()); "
            "print(os.environ.get('QA_PARENT_ONLY', 'missing'), file=sys.stderr); "
            "sys.exit(7)"
        ),
    ]

    result = run_command(
        command,
        env=child_env(QA_PARENT_ONLY=None),
    )

    assert result.returncode == 7
    assert result.stdout.strip() == str(_PROJECT_ROOT)
    assert result.stderr.strip() == "missing"
    assert Path.cwd() == original_cwd
    import os

    assert os.environ["QA_PARENT_ONLY"] == "present"

    capture = write_capture(
        "isolated-child",
        result,
        root=tmp_path,
    )
    assert (capture / "stdout.txt").read_text() == result.stdout
    assert (capture / "stderr.txt").read_text() == result.stderr
    assert (capture / "exit.txt").read_text() == "7\n"


def test_write_capture_replaces_stale_capture_files(tmp_path):
    first = subprocess.CompletedProcess(
        ["first"], 3, stdout="old stdout\n", stderr="old stderr\n"
    )
    second = subprocess.CompletedProcess(
        ["second"], 0, stdout="new stdout\n", stderr="new stderr\n"
    )

    write_capture("fresh", first, root=tmp_path)
    stale = tmp_path / "captures" / "fresh" / "stale.txt"
    stale.write_text("stale")
    capture = write_capture("fresh", second, root=tmp_path)

    assert not stale.exists()
    assert capture == tmp_path / "captures" / "fresh"
    assert (capture / "stdout.txt").read_text() == "new stdout\n"
    assert (capture / "stderr.txt").read_text() == "new stderr\n"
    assert (capture / "exit.txt").read_text() == "0\n"


def test_acceptance_refresh_registration_preserves_characterization():
    class RecordingAPI:
        def __init__(self):
            self.feature = None
            self.entries = []

        def set_feature(self, feature):
            self.feature = feature

        def register_first(self, pattern, handler, *, source_order=None):
            self.entries.append((pattern, handler, source_order, self.feature))

        def register(self, pattern, handler, *, source_order=None):
            self.entries.append((pattern, handler, source_order, self.feature))

    api = RecordingAPI()
    acceptance_refresh.register(api)

    assert acceptance_refresh.FEATURE_ID == "acceptance_refresh"
    assert len(api.entries) == 38
    feature_entries = [entry for entry in api.entries if entry[3] is not None]
    global_entries = [entry for entry in api.entries if entry[3] is None]
    assert len(feature_entries) == 13
    assert len(global_entries) == 25
    assert [entry[2] for entry in feature_entries] == list(range(21826, 21839))
    assert [entry[2] for entry in global_entries] == list(range(21916, 21941))
    assert all(entry[3] == "acceptance_refresh" for entry in feature_entries)
    assert api.feature is None

    expected_patterns = [
        "the `CoordinationAnalysis` model (?:does not )?declare",
        "(?:an LLM that returns a )?(?:valid )?CoordinationAnalysis",
        "Stage 2 Call 3 coordination derivation is run",
        "the Stage 2 coordination link addition with fallback is executed",
        "a CoordinationAnalysis model is produced",
        "the CoordinationAnalysis contains coordination link CL-1",
        "the CoordinationAnalysis integrity_findings list is not empty",
        "the CoordinationAnalysis contains no coordination links",
        "the ControlStructure contains (?:responsibility|controlled process)",
        "CL-1 has source RESP-1 and target RESP-2",
        "the warnings list includes a warning naming step",
        "no assembly failure is logged",
        "the SP1RunResult stage_errors contains the assemble_control_structure failure",
        "the control_structure module (?:does not )?exports?",
        "the SP2 prompts directory contains",
        "the SP3 prompts directory contains",
        "the Call 2a user prompt is rendered with the capability profile",
        "(?:an LLM that returns a )?ControlElementSet from Call 2b with",
        "a valid ResponsibilitySet from Call 2a",
        "a ResponsibilitySet from Call 2a with responsibilities",
        "an LLM that returns valid responses for (?:Stage 2 calls 1, 2a, and 2b|all four Stage 2 calls|Stage 2 calls 1 and 2a)",
        "the Stage 2 assembly with fallback is executed",
        "Stage 2 control structure derivation is run",
        "Stage 2 calls 1 through 3 are run in sequence",
        "Stage 2 Call 2a responsibilities derivation is run",
        "Stage 2 Call 2b control elements derivation is run",
        "Stage 2 calls 1 through 2[ab] are run in sequence",
        "an LLM that returns a valid ControlElementSet JSON",
        "an LLM that returns a valid CoordinationAnalysis",
        "a CoordinationAnalysis with",
        "a call log entry exists with step",
        "no call log entry has step",
        "each responsibility has at least one responsibility constraint and one process model part",
        "the `ResponsibilitySet` model does not declare",
        "a ControlElementSet model is produced",
        "the ControlElementSet contains controlled process CP-1",
        "the Call 2[ab] user prompt contains",
        "the Call 3 user prompt contains the assembled responsibilities and controlled processes",
    ]
    assert [entry[0] for entry in api.entries] == expected_patterns


def test_find_project_root_accepts_nested_start(tmp_path):
    nested = tmp_path / "repository" / "nested"
    nested.parent.mkdir()
    (nested.parent / "pyproject.toml").write_text("[project]\nname = 'fixture'\n")
    nested.mkdir()

    assert find_project_root(nested) == nested.parent
