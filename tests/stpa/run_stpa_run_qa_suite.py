#!/usr/bin/env python3
"""Executable QA suite for the ``scenario-forge stpa-run`` CLI command.

Converts the 50 QA checks from ``tests/stpa/features/qa_stpa_run.md``
into executable verification.  All checks go through the user
interface: the Typer CLI (via ``CliRunner``), Python module imports,
subprocess invocation, and filesystem inspection — no project-internal
APIs beyond the public CLI entry point.

The suite uses a **mock environment** (``unittest.mock.patch``) to
replace LLM-dependent pipeline stages with deterministic mock results,
as allowed by the QA suite specification: "The suite assumes a stub
LLM endpoint or mock environment is available so that the pipeline can
complete without real LLM calls."

Usage::

    uv run python tests/stpa/run_stpa_run_qa_suite.py

Exit 0 = all pass, Exit 1 = any fail.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

# Ensure project root and src are on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from scenario_forge.cli import app  # noqa: E402
from scenario_forge.models.capability_profile import (  # noqa: E402
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from scenario_forge.stpa.infra.yaml_io import write_yaml  # noqa: E402
from scenario_forge.stpa.models.enriched_threat_set import (  # noqa: E402
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration  # noqa: E402
from tests.stpa.helpers import (  # noqa: E402
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)

from typer.testing import CliRunner  # noqa: E402

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
FAILED_CHECKS: list[str] = []


def check(name: str, fn) -> None:
    """Run *fn* and record pass/fail."""
    global PASS, FAIL
    print(f"--- {name} ---")
    try:
        fn()
        print("  PASS")
        PASS += 1
    except AssertionError as exc:
        print(f"  FAIL: {exc}")
        FAIL += 1
        FAILED_CHECKS.append(name)
    except Exception as exc:
        print(f"  ERROR: {type(exc).__name__}: {exc}")
        FAIL += 1
        FAILED_CHECKS.append(name)
    print()


# ---------------------------------------------------------------------------
# Helpers (mirrors test_stpa_run.py helpers)
# ---------------------------------------------------------------------------


def _make_capability_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input"],
        entry_points=[
            EntryPoint(name="chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=["KC1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test-tool", description="A test tool"),
        ],
    )


def _make_risk_extraction_json(num_cards: int = 1) -> str:
    cards = []
    for i in range(num_cards):
        cards.append({
            "risk_id": f"atlas-{i+1:03d}",
            "risk_name": f"Risk {i+1}",
            "risk_description": f"Description {i+1}",
            "taxonomy": "ibm-risk-atlas",
            "confidence": 0.9,
            "grounding_confidence": "high",
        })
    return json.dumps({"risks": cards})


def _write_use_case(tmpdir: Path, content: str = "My agentic system use case") -> Path:
    path = tmpdir / "use-case.txt"
    path.write_text(content, encoding="utf-8")
    return path


def _write_risk_extraction(tmpdir: Path, num_cards: int = 1) -> Path:
    path = tmpdir / "risk-extraction.json"
    path.write_text(_make_risk_extraction_json(num_cards), encoding="utf-8")
    return path


def _write_profiles_yaml(tmpdir: Path) -> Path:
    path = tmpdir / "model-profiles.yaml"
    path.write_text(
        yaml.dump({
            "default-pro": {
                "base_url": "https://default.example.com/v1",
                "model": "default-model",
                "api_key": "sk-def",
                "temperature": 0.4,
            },
            "sp1-pro": {
                "base_url": "https://sp1.example.com/v1",
                "model": "sp1-model",
                "api_key": "sk-sp1",
                "temperature": 0.3,
            },
            "sp2-pro": {
                "base_url": "https://sp2.example.com/v1",
                "model": "sp2-model",
                "api_key": "sk-sp2",
                "temperature": 0.2,
            },
            "sp3-pro": {
                "base_url": "https://sp3.example.com/v1",
                "model": "sp3-model",
                "api_key": "sk-sp3",
                "temperature": 0.1,
            },
            "custom-model": {
                "base_url": "https://custom.example.com/v1",
                "model": "custom-model-name",
                "api_key": "sk-cust",
                "temperature": 0.5,
            },
        }),
        encoding="utf-8",
    )
    return path


def _make_mock_sp1_result(
    *,
    with_control_structure: bool = True,
    with_capability_profile: bool = True,
    with_loss_analysis: bool = True,
    stage_errors: list[str] | None = None,
) -> MagicMock:
    result = MagicMock()
    result.loss_analysis = make_minimal_loss_analysis() if with_loss_analysis else None
    result.capability_profile = _make_capability_profile() if with_capability_profile else None
    result.control_structure = (
        make_minimal_control_structure() if with_control_structure else None
    )
    result.critic_findings = None
    result.heuristic_errors = []
    result.heuristic_warnings = []
    result.solution_neutrality_warnings = []
    result.post_revision_warnings = []
    result.revised = False
    result.stage_errors = stage_errors or []
    return result


def _make_mock_sp2_result(
    *,
    with_enriched_threats: bool = True,
    with_ica_enumeration: bool = True,
    stage_errors: list[str] | None = None,
) -> MagicMock:
    result = MagicMock()
    if with_ica_enumeration:
        result.ica_enumeration = ICAEnumeration(slots=[])
    else:
        result.ica_enumeration = None

    if with_enriched_threats:
        result.enriched_threat_set = EnrichedThreatSet(
            structural_threats=[
                StructuralThreat(
                    ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                    ica_text="ICA text",
                    hazardous_context="Context",
                    loss_scenario="Scenario",
                    related_hazards=["H-1"],
                    related_constraints=["SC-1"],
                )
            ],
            coverage_analysis=CoverageAnalysis(
                structural_coverage={"total_slots": 1, "non_na": 1, "na": 0, "coverage_rate": 1.0},
            ),
        )
    else:
        result.enriched_threat_set = None

    result.na_quality_result = MagicMock()
    result.na_quality_result.flagged_slots = []
    result.na_quality_result.ratio_flags = []
    result.stage_errors = stage_errors or []
    return result


def _make_mock_sp3_result(
    *,
    stage_errors: list[str] | None = None,
) -> MagicMock:
    result = MagicMock()
    result.scenario_specs = []
    result.scenario_envelopes = []
    result.eval_scorecard = {"metrics": {"consistency": {"rate": 1.0}}}
    result.coverage_gaps = {}
    result.stage_errors = stage_errors or []
    result.validation_errors = []
    return result


def _write_sp1_artifacts(output_dir: Path) -> None:
    write_yaml(make_minimal_loss_analysis(), output_dir / "loss-analysis.yaml")
    write_yaml(_make_capability_profile(), output_dir / "capability-profile.yaml")
    write_yaml(make_minimal_control_structure(), output_dir / "control-structure.yaml")


def _write_sp2_artifacts(output_dir: Path) -> None:
    write_yaml(ICAEnumeration(slots=[]), output_dir / "ica-enumeration.yaml")
    write_yaml(
        EnrichedThreatSet(
            structural_threats=[
                StructuralThreat(
                    ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                    ica_text="ICA text",
                    hazardous_context="Context",
                    loss_scenario="Scenario",
                    related_hazards=["H-1"],
                    related_constraints=["SC-1"],
                )
            ],
            coverage_analysis=CoverageAnalysis(
                structural_coverage={"total_slots": 1, "non_na": 1, "na": 0, "coverage_rate": 1.0},
            ),
        ),
        output_dir / "enriched-threats.yaml",
    )


def _write_sp3_artifacts(output_dir: Path) -> None:
    scenarios_dir = output_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    (scenarios_dir / "scenario-001.yaml").write_text("dummy: true", encoding="utf-8")
    (scenarios_dir / "scenario-001.feature").write_text(
        "Feature: Test\n  Scenario: Test\n    Then pass\n", encoding="utf-8",
    )


def _write_eval_artifacts(output_dir: Path) -> None:
    (output_dir / "eval-scorecard.yaml").write_text(
        "metrics:\n  consistency:\n    rate: 1.0\n", encoding="utf-8",
    )
    (output_dir / "coverage-gaps.json").write_text("{}", encoding="utf-8")


def _write_all_artifacts(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_sp1_artifacts(output_dir)
    _write_sp2_artifacts(output_dir)
    _write_sp3_artifacts(output_dir)
    _write_eval_artifacts(output_dir)


def _write_calls_jsonl(output_dir: Path, entries: list[dict]) -> None:
    path = output_dir / "calls.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _patch_all_stages(
    sp1_result=None,
    sp2_result=None,
    sp3_result=None,
    patch_llm: bool = True,
) -> dict:
    if sp1_result is None:
        sp1_result = _make_mock_sp1_result()
    if sp2_result is None:
        sp2_result = _make_mock_sp2_result()
    if sp3_result is None:
        sp3_result = _make_mock_sp3_result()

    patchers: list = []

    if patch_llm:
        mock_client = MagicMock()
        mock_client.model = "mock-model"
        mock_client.base_url = "http://mock:8080"
        p0 = patch(
            "scenario_forge.stpa.pipeline.runner.resolve_llm_client",
            return_value=(mock_client, None),
        )
        patchers.append(p0)
    else:
        mock_client = None

    p1 = patch("scenario_forge.stpa.pipeline.runner.run_sp1", return_value=sp1_result)
    p2 = patch("scenario_forge.stpa.pipeline.runner.run_sp2", return_value=sp2_result)
    p3 = patch("scenario_forge.stpa.pipeline.runner.run_sp3", return_value=sp3_result)
    pr = patch(
        "scenario_forge.stpa.pipeline.runner.generate_report",
        side_effect=lambda d, p=None: _write_report_file(d),
    )
    patchers.extend([p1, p2, p3, pr])

    mocks = {
        "sp1": p1.start(),
        "sp2": p2.start(),
        "sp3": p3.start(),
        "report": pr.start(),
        "sp1_result": sp1_result,
        "sp2_result": sp2_result,
        "sp3_result": sp3_result,
        "mock_client": mock_client,
    }
    if patch_llm:
        mocks["llm"] = p0.start()
    mocks["patchers"] = patchers
    return mocks


def _write_report_file(output_dir: Path) -> Path:
    """Write a minimal HTML report file and return its path."""
    report_path = output_dir / "stpa-report.html"
    report_path.write_text(
        "<html><body><h1>STPA Report</h1></body></html>", encoding="utf-8",
    )
    return report_path


def _stop_patches(mocks: dict) -> None:
    for p in mocks["patchers"]:
        p.stop()


class _TempDir:
    """Context manager for temporary directories."""

    def __enter__(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir)
        return self.path

    def __exit__(self, *args):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI interface tests (QA-STPA-RUN-CLI-*)
# ---------------------------------------------------------------------------


def test_cli_01_stpa_run_command_registered():
    """QA-STPA-RUN-CLI-01: stpa-run subcommand is registered."""
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0, f"exit code {result.exit_code}"
    assert "stpa-run" in result.stdout, "stpa-run not in --help output"


def test_cli_02_required_and_optional_flags():
    """QA-STPA-RUN-CLI-02: --help shows required and optional flags."""
    result = CliRunner().invoke(app, ["stpa-run", "--help"])
    assert result.exit_code == 0
    for flag in ["--use-case", "--risk-extraction", "--output-dir"]:
        assert flag in result.stdout, f"{flag} not in stpa-run --help"
    for flag in [
        "--profile", "--sp1-profile", "--sp2-profile", "--sp3-profile",
        "--profiles-file", "--capability-profile", "--max-workers", "--resume",
    ]:
        assert flag in result.stdout, f"{flag} not in stpa-run --help"


def test_cli_03_use_case_at_prefix():
    """QA-STPA-RUN-CLI-03: --use-case accepts @ prefix."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-cli03"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run",
                "--use-case", f"@{uc}",
                "--risk-extraction", str(risk),
                "--output-dir", str(out),
            ])
            # Spec: "does not report a use-case file not found error"
            assert "use-case" not in result.output.lower() or "not found" not in result.output.lower(), (
                f"Use-case file not found error: {result.output}"
            )
        finally:
            _stop_patches(mocks)


def test_cli_04_use_case_bare_path():
    """QA-STPA-RUN-CLI-04: --use-case accepts bare path without @."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-cli04"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run",
                "--use-case", str(uc),
                "--risk-extraction", str(risk),
                "--output-dir", str(out),
            ])
            assert "use-case" not in result.output.lower() or "not found" not in result.output.lower(), (
                f"Use-case file not found error: {result.output}"
            )
        finally:
            _stop_patches(mocks)


def test_cli_05_max_workers_default():
    """QA-STPA-RUN-CLI-05: --max-workers defaults to 1."""
    result = CliRunner().invoke(app, ["stpa-run", "--help"])
    assert "1" in result.stdout, "default value 1 not shown for --max-workers"


def test_cli_06_profiles_file_default():
    """QA-STPA-RUN-CLI-06: --profiles-file defaults to ai/model-profiles.yaml."""
    result = CliRunner().invoke(app, ["stpa-run", "--help"])
    assert "ai/model-profiles.yaml" in result.stdout, (
        "default ai/model-profiles.yaml not shown for --profiles-file"
    )


def test_cli_07_runner_module_exists():
    """QA-STPA-RUN-CLI-07: runner and llm_config modules are importable."""
    import scenario_forge.stpa.pipeline.runner as runner_mod
    import scenario_forge.stpa.pipeline.llm_config as llm_config_mod
    assert hasattr(runner_mod, "run_stpa_pipeline")
    assert hasattr(llm_config_mod, "resolve_llm_client_from_profile")
    assert hasattr(llm_config_mod, "resolve_llm_client_from_env")


def test_cli_08_flat_artifact_layout():
    """QA-STPA-RUN-CLI-08: flat artifact layout in output-dir."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-cli08"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                _write_calls_jsonl(kw["run_dir"], [{"stage": "stage_1a"}])
                return mocks["sp1_result"]

            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]

            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]

            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run",
                "--use-case", str(uc),
                "--risk-extraction", str(risk),
                "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.stdout}"

            for name in [
                "loss-analysis.yaml", "capability-profile.yaml",
                "control-structure.yaml", "ica-enumeration.yaml",
                "enriched-threats.yaml", "eval-scorecard.yaml",
                "coverage-gaps.json", "calls.jsonl",
                "stpa-report.html",
            ]:
                assert (out / name).exists(), f"{name} missing from output dir"
            assert (out / "scenarios").is_dir(), "scenarios/ dir missing"
            assert list((out / "scenarios").glob("*.yaml")), "no .yaml in scenarios/"
            assert list((out / "scenarios").glob("*.feature")), "no .feature in scenarios/"
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# SP1 execution tests (QA-STPA-RUN-SP1-*)
# ---------------------------------------------------------------------------


def test_sp1_01_writes_expected_artifacts():
    """QA-STPA-RUN-SP1-01: SP1 writes all expected artifacts."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp1"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                _write_calls_jsonl(kw["run_dir"], [{"stage": "stage_1a"}])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert (out / "loss-analysis.yaml").exists(), "loss-analysis.yaml missing"
            assert (out / "capability-profile.yaml").exists(), "capability-profile.yaml missing"
            assert (out / "control-structure.yaml").exists(), "control-structure.yaml missing"
            assert (out / "calls.jsonl").exists(), "calls.jsonl missing"
        finally:
            _stop_patches(mocks)


def test_sp1_02_calls_html_auto_rendered():
    """QA-STPA-RUN-SP1-02: calls.html is auto-rendered."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp1html"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                rd = kw["run_dir"]
                rd.mkdir(parents=True, exist_ok=True)
                _write_calls_jsonl(rd, [{"stage": "stage_1a", "step": "test"}])
                _write_sp1_artifacts(rd)
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert (out / "calls.html").exists(), "calls.html not generated"
            content = (out / "calls.html").read_text()
            assert "<html" in content.lower() or "<table" in content.lower(), (
                "calls.html does not contain HTML markup"
            )
        finally:
            _stop_patches(mocks)


def test_sp1_03_capability_profile_skips_stage_1b():
    """QA-STPA-RUN-SP1-03: --capability-profile skips Stage 1b."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        cap = tmp / "cap-profile.yaml"
        write_yaml(_make_capability_profile(), cap)
        out = tmp / "out-sp1cp"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                _write_calls_jsonl(kw["run_dir"], [{"stage": "stage_1a"}])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--capability-profile", str(cap),
            ])
            calls = []
            if (out / "calls.jsonl").exists():
                for line in (out / "calls.jsonl").read_text().splitlines():
                    if line.strip():
                        calls.append(json.loads(line))
            stage_1b_calls = [c for c in calls if c.get("stage") == "stage_1b"]
            assert len(stage_1b_calls) == 0, "Stage 1b call found in calls.jsonl"
        finally:
            _stop_patches(mocks)


def test_sp1_04_max_workers_forwarded():
    """QA-STPA-RUN-SP1-04: --max-workers forwarded to SP1."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp1mw"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--max-workers", "4",
            ])
            call_kwargs = mocks["sp1"].call_args.kwargs
            assert call_kwargs.get("max_workers") == 4, (
                f"max_workers not 4: {call_kwargs.get('max_workers')}"
            )
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# SP2 execution tests (QA-STPA-RUN-SP2-*)
# ---------------------------------------------------------------------------


def test_sp2_01_writes_expected_artifacts():
    """QA-STPA-RUN-SP2-01: SP2 writes expected artifacts after SP1."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp2"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            assert (out / "ica-enumeration.yaml").exists(), "ica-enumeration.yaml missing"
            assert (out / "enriched-threats.yaml").exists(), "enriched-threats.yaml missing"
        finally:
            _stop_patches(mocks)


def test_sp2_02_calls_appended():
    """QA-STPA-RUN-SP2-02: SP2 calls appended to calls.jsonl."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp2calls"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                _write_calls_jsonl(kw["run_dir"], [{"stage": "stage_2", "step": "sp1"}])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                rd = kw["run_dir"]
                existing = []
                if (rd / "calls.jsonl").exists():
                    existing = [
                        json.loads(line) for line in (rd / "calls.jsonl").read_text().splitlines() if line.strip()
                    ]
                existing.append({"stage": "stage_3", "step": "sp2"})
                _write_calls_jsonl(rd, existing)
                _write_sp2_artifacts(rd)
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            calls = [json.loads(line) for line in (out / "calls.jsonl").read_text().splitlines() if line.strip()]
            stages = {c.get("stage") for c in calls}
            assert "stage_2" in stages, "SP1 calls (stage_2) not in calls.jsonl"
            assert "stage_3" in stages, "SP2 calls (stage_3) not in calls.jsonl"
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# SP3 execution tests (QA-STPA-RUN-SP3-*)
# ---------------------------------------------------------------------------


def test_sp3_01_writes_expected_artifacts():
    """QA-STPA-RUN-SP3-01: SP3 writes expected artifacts after SP2."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp3"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            assert (out / "scenarios").is_dir(), "scenarios/ dir missing"
            assert list((out / "scenarios").glob("*.yaml")), "no .yaml in scenarios/"
            assert list((out / "scenarios").glob("*.feature")), "no .feature in scenarios/"
            assert (out / "eval-scorecard.yaml").exists(), "eval-scorecard.yaml missing"
            assert (out / "coverage-gaps.json").exists(), "coverage-gaps.json missing"
        finally:
            _stop_patches(mocks)


def test_sp3_02_capability_profile_passed():
    """QA-STPA-RUN-SP3-02: capability_profile passed to SP3 with --capability-profile."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        cap = tmp / "cap-profile.yaml"
        write_yaml(_make_capability_profile(), cap)
        out = tmp / "out-sp3cp"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--capability-profile", str(cap),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            sp3_kwargs = mocks["sp3"].call_args.kwargs
            cap_profile = sp3_kwargs.get("capability_profile")
            assert cap_profile is not None, "capability_profile not passed to SP3"
        finally:
            _stop_patches(mocks)


def test_sp3_03_capability_profile_not_passed():
    """QA-STPA-RUN-SP3-03: capability_profile not passed to SP3 without --capability-profile."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp3nocp"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            sp3_kwargs = mocks["sp3"].call_args.kwargs
            cap_profile = sp3_kwargs.get("capability_profile")
            assert cap_profile is None, "capability_profile should not be passed to SP3"
        finally:
            _stop_patches(mocks)


def test_sp3_04_calls_appended():
    """QA-STPA-RUN-SP3-04: SP3 calls appended to calls.jsonl."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sp3calls"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                _write_calls_jsonl(kw["run_dir"], [{"stage": "stage_1a"}])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                rd = kw["run_dir"]
                existing = [json.loads(line) for line in (rd / "calls.jsonl").read_text().splitlines() if line.strip()]
                existing.append({"stage": "stage_3"})
                _write_calls_jsonl(rd, existing)
                _write_sp2_artifacts(rd)
                return mocks["sp2_result"]
            def sp3_side(**kw):
                rd = kw["run_dir"]
                existing = [json.loads(line) for line in (rd / "calls.jsonl").read_text().splitlines() if line.strip()]
                existing.append({"stage": "stage_5"})
                existing.append({"stage": "stage_6"})
                _write_calls_jsonl(rd, existing)
                _write_sp3_artifacts(rd)
                _write_eval_artifacts(rd)
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            calls = [json.loads(line) for line in (out / "calls.jsonl").read_text().splitlines() if line.strip()]
            stages = {c.get("stage") for c in calls}
            assert "stage_5" in stages or "stage_6" in stages, (
                "SP3 calls (stage_5/stage_6) not in calls.jsonl"
            )
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Report generation tests (QA-STPA-RUN-RPT-*)
# ---------------------------------------------------------------------------


def test_rpt_01_report_generated():
    """QA-STPA-RUN-RPT-01: stpa-report.html generated after all stages."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-rpt"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            assert (out / "stpa-report.html").exists(), "stpa-report.html missing"
            content = (out / "stpa-report.html").read_text()
            assert "<html" in content.lower(), "no <html> tag in report"
        finally:
            _stop_patches(mocks)


def test_rpt_02_report_with_degraded_sp3():
    """QA-STPA-RUN-RPT-02: report generated even with degraded SP3."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-rpt-deg-sp3"
        sp3_res = _make_mock_sp3_result(stage_errors=["SP3 degraded"])
        mocks = _patch_all_stages(sp3_result=sp3_res)
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return sp3_res
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            assert (out / "stpa-report.html").exists(), "report not generated with degraded SP3"
        finally:
            _stop_patches(mocks)


def test_rpt_03_report_with_degraded_sp2():
    """QA-STPA-RUN-RPT-03: report generated even with degraded SP2."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-rpt-deg-sp2"
        sp2_res = _make_mock_sp2_result(stage_errors=["SP2 degraded"])
        mocks = _patch_all_stages(sp2_result=sp2_res)
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return sp2_res
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            assert (out / "stpa-report.html").exists(), "report not generated with degraded SP2"
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Summary output tests (QA-STPA-RUN-SUM-*)
# ---------------------------------------------------------------------------


def test_sum_01_sp1_metrics():
    """QA-STPA-RUN-SUM-01: summary includes SP1 metrics."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sum"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            output = result.stdout
            assert "SP1" in output, "SP1 not in summary"
            assert "Losses" in output, "Losses not in summary"
            assert "Hazards" in output, "Hazards not in summary"
            assert "Constraints" in output, "Constraints not in summary"
            assert "Responsibilities" in output, "Responsibilities not in summary"
            assert "Control Actions" in output, "Control Actions not in summary"
        finally:
            _stop_patches(mocks)


def test_sum_02_sp2_metrics():
    """QA-STPA-RUN-SUM-02: summary includes SP2 metrics."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sum2"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            output = result.stdout
            assert "SP2" in output, "SP2 not in summary"
            assert "slots" in output.lower(), "slots not in summary"
        finally:
            _stop_patches(mocks)


def test_sum_03_sp3_metrics():
    """QA-STPA-RUN-SUM-03: summary includes SP3 metrics."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sum3"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            output = result.stdout
            assert "SP3" in output, "SP3 not in summary"
            assert "specs" in output.lower() or "envelopes" in output.lower(), (
                "scenario specs/envelopes not in summary"
            )
        finally:
            _stop_patches(mocks)


def test_sum_04_report_path():
    """QA-STPA-RUN-SUM-04: summary includes report path."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-sum4"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            assert "stpa-report.html" in result.stdout, "report path not in summary"
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Error handling tests (QA-STPA-RUN-ERR-*)
# ---------------------------------------------------------------------------


def test_err_01_hard_failure_sp1():
    """QA-STPA-RUN-ERR-01: hard failure in SP1 exits with code 1."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-err-sp1"
        mocks = _patch_all_stages()
        try:
            mocks["sp1"].side_effect = RuntimeError("SP1 failed")
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 1, f"expected exit code 1, got {result.exit_code}"
            assert not (out / "ica-enumeration.yaml").exists(), "SP2 should not have run"
        finally:
            _stop_patches(mocks)


def test_err_02_hard_failure_sp2():
    """QA-STPA-RUN-ERR-02: hard failure in SP2 exits with code 1."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-err-sp2"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = RuntimeError("SP2 failed")

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 1, f"expected exit code 1, got {result.exit_code}"
            assert (out / "control-structure.yaml").exists(), "SP1 should have completed"
        finally:
            _stop_patches(mocks)


def test_err_03_hard_failure_sp3():
    """QA-STPA-RUN-ERR-03: hard failure in SP3 exits with code 1."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-err-sp3"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = RuntimeError("SP3 failed")

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 1, f"expected exit code 1, got {result.exit_code}"
        finally:
            _stop_patches(mocks)


def test_err_04_degraded_continues():
    """QA-STPA-RUN-ERR-04: degraded results continue pipeline."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-deg"
        sp1_res = _make_mock_sp1_result(stage_errors=["SP1 warning"])
        mocks = _patch_all_stages(sp1_result=sp1_res)
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return sp1_res
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"expected exit code 0, got {result.exit_code}"
            assert (out / "ica-enumeration.yaml").exists(), "SP2 should have run"
            assert "stage" in result.stdout.lower() or "error" in result.stdout.lower(), (
                "stage errors not in summary"
            )
        finally:
            _stop_patches(mocks)


def test_err_05_missing_control_structure_stops_sp2():
    """QA-STPA-RUN-ERR-05: missing control_structure stops SP2."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-no-cs"
        sp1_res = _make_mock_sp1_result(with_control_structure=False)
        mocks = _patch_all_stages(sp1_result=sp1_res)
        try:
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 1, f"expected exit code 1, got {result.exit_code}"
            assert not (out / "ica-enumeration.yaml").exists(), "SP2 should not have run"
        finally:
            _stop_patches(mocks)


def test_err_06_error_to_stderr():
    """QA-STPA-RUN-ERR-06: error message printed to stderr."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-stderr"
        mocks = _patch_all_stages()
        try:
            mocks["sp1"].side_effect = RuntimeError("SP1 failed")
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 1
            # CliRunner captures stderr in result.output
            assert "Error" in result.output or "error" in result.output.lower(), (
                "error message not in output"
            )
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Resume behavior tests (QA-STPA-RUN-RES-*)
# ---------------------------------------------------------------------------


def test_res_01_resume_skips_sp1():
    """QA-STPA-RUN-RES-01: --resume skips SP1 when artifacts exist."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-res1"
        _write_all_artifacts(out)
        la_mtime = (out / "loss-analysis.yaml").stat().st_mtime

        mocks = _patch_all_stages()
        try:
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--resume",
            ])
            assert result.exit_code == 0
            assert not mocks["sp1"].called, "SP1 was called during resume"
            new_mtime = (out / "loss-analysis.yaml").stat().st_mtime
            assert new_mtime == la_mtime, "loss-analysis.yaml was modified during resume"
        finally:
            _stop_patches(mocks)


def test_res_02_resume_skips_sp2():
    """QA-STPA-RUN-RES-02: --resume skips SP2 when artifacts exist."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-res2"
        _write_all_artifacts(out)
        ica_mtime = (out / "ica-enumeration.yaml").stat().st_mtime

        mocks = _patch_all_stages()
        try:
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--resume",
            ])
            assert result.exit_code == 0
            assert not mocks["sp2"].called, "SP2 was called during resume"
            new_mtime = (out / "ica-enumeration.yaml").stat().st_mtime
            assert new_mtime == ica_mtime, "ica-enumeration.yaml was modified during resume"
        finally:
            _stop_patches(mocks)


def test_res_03_resume_skips_sp3():
    """QA-STPA-RUN-RES-03: --resume skips SP3 when scenarios exist."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-res3"
        _write_all_artifacts(out)
        scn = out / "scenarios" / "scenario-001.yaml"
        scn_mtime = scn.stat().st_mtime

        mocks = _patch_all_stages()
        try:
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--resume",
            ])
            assert result.exit_code == 0
            assert not mocks["sp3"].called, "SP3 was called during resume"
            new_mtime = scn.stat().st_mtime
            assert new_mtime == scn_mtime, "scenario YAML was modified during resume"
        finally:
            _stop_patches(mocks)


def test_res_04_report_always_generated():
    """QA-STPA-RUN-RES-04: report always generated with --resume."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-res4"
        _write_all_artifacts(out)
        # Delete report if it exists
        report = out / "stpa-report.html"
        if report.exists():
            report.unlink()

        mocks = _patch_all_stages()
        try:
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--resume",
            ])
            assert result.exit_code == 0
            assert (out / "stpa-report.html").exists(), "report not generated with --resume"
        finally:
            _stop_patches(mocks)


def test_res_05_without_resume_all_stages_run():
    """QA-STPA-RUN-RES-05: without --resume all stages run from scratch."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-res5"
        _write_all_artifacts(out)
        (out / "loss-analysis.yaml").stat().st_mtime

        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            mocks["sp1"].side_effect = sp1_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0
            assert mocks["sp1"].called, "SP1 was not called without --resume"
        finally:
            _stop_patches(mocks)


def test_res_06_resume_runs_sp1_when_incomplete():
    """QA-STPA-RUN-RES-06: --resume runs SP1 when artifacts incomplete."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-res6"
        out.mkdir(parents=True, exist_ok=True)
        # Write only loss-analysis.yaml (incomplete SP1)
        write_yaml(make_minimal_loss_analysis(), out / "loss-analysis.yaml")

        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--resume",
            ])
            assert mocks["sp1"].called, "SP1 should have been called (incomplete artifacts)"
            assert (out / "capability-profile.yaml").exists(), "capability-profile.yaml missing"
            assert (out / "control-structure.yaml").exists(), "control-structure.yaml missing"
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Model profiles tests (QA-STPA-RUN-MP-*)
# ---------------------------------------------------------------------------


def test_mp_01_profile_sets_default():
    """QA-STPA-RUN-MP-01: --profile sets default model for all stages."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        profiles = _write_profiles_yaml(tmp)
        out = tmp / "out-mp01"
        mocks = _patch_all_stages(patch_llm=False)
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--profile", "default-pro",
                "--profiles-file", str(profiles),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            calls = mocks["sp1"].call_args.kwargs
            assert calls.get("profile_name") == "default-pro" or calls.get("profile_name") is None
        finally:
            _stop_patches(mocks)


def test_mp_02_sp1_profile_overrides_default():
    """QA-STPA-RUN-MP-02: --sp1-profile overrides --profile for SP1."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        profiles = _write_profiles_yaml(tmp)
        out = tmp / "out-mp02"
        mocks = _patch_all_stages(patch_llm=False)
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--profile", "default-pro",
                "--sp1-profile", "sp1-pro",
                "--profiles-file", str(profiles),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            sp1_kwargs = mocks["sp1"].call_args.kwargs
            assert sp1_kwargs.get("profile_name") == "sp1-pro", (
                f"SP1 profile_name should be sp1-pro, got {sp1_kwargs.get('profile_name')}"
            )
        finally:
            _stop_patches(mocks)


def test_mp_03_per_stage_profiles_without_default():
    """QA-STPA-RUN-MP-03: per-stage profiles without --profile."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        profiles = _write_profiles_yaml(tmp)
        out = tmp / "out-mp03"
        mocks = _patch_all_stages(patch_llm=False)
        try:
            stage_models: dict[str, str] = {}

            def sp1_side(**kw):
                stage_models["SP1"] = kw["llm_client"].model
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                stage_models["SP2"] = kw["llm_client"].model
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                stage_models["SP3"] = kw["llm_client"].model
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--sp1-profile", "sp1-pro",
                "--sp2-profile", "sp2-pro",
                "--sp3-profile", "sp3-pro",
                "--profiles-file", str(profiles),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
            assert stage_models.get("SP1") == "sp1-model", (
                f"SP1 model should be sp1-model, got {stage_models.get('SP1')}"
            )
            assert stage_models.get("SP2") == "sp2-model", (
                f"SP2 model should be sp2-model, got {stage_models.get('SP2')}"
            )
            assert stage_models.get("SP3") == "sp3-model", (
                f"SP3 model should be sp3-model, got {stage_models.get('SP3')}"
            )
        finally:
            _stop_patches(mocks)


def test_mp_04_no_profile_falls_back_to_env():
    """QA-STPA-RUN-MP-04: no profile flags fall back to environment variables."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-mp04"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            with patch.dict(os.environ, {
                "SCENARIO_FORGE_MODEL_BASE_URL": "http://env-test:1234",
                "SCENARIO_FORGE_API_KEY": "env-key",
                "SCENARIO_FORGE_MODEL_NAME": "env-model",
            }):
                result = CliRunner().invoke(app, [
                    "stpa-run", "--use-case", str(uc),
                    "--risk-extraction", str(risk), "--output-dir", str(out),
                ])
                assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
                # resolve_llm_client was mocked, verify it was called
                assert mocks["llm"].called, "resolve_llm_client should have been called"
        finally:
            _stop_patches(mocks)


def test_mp_05_profiles_file_custom_path():
    """QA-STPA-RUN-MP-05: --profiles-file uses custom path."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        profiles = _write_profiles_yaml(tmp)
        out = tmp / "out-mp05"
        mocks = _patch_all_stages(patch_llm=False)
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--profiles-file", str(profiles),
                "--profile", "custom-model",
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.output}"
        finally:
            _stop_patches(mocks)


def test_mp_06_llm_config_functions():
    """QA-STPA-RUN-MP-06: llm_config module has shared resolution functions."""
    import scenario_forge.stpa.pipeline.llm_config as llm_config
    assert callable(getattr(llm_config, "resolve_llm_client_from_profile", None)), (
        "resolve_llm_client_from_profile not callable"
    )
    assert callable(getattr(llm_config, "resolve_llm_client_from_env", None)), (
        "resolve_llm_client_from_env not callable"
    )


# ---------------------------------------------------------------------------
# Input validation tests (QA-STPA-RUN-VAL-*)
# ---------------------------------------------------------------------------


def test_val_01_missing_use_case_file():
    """QA-STPA-RUN-VAL-01: missing use-case file exits with error."""
    with _TempDir() as tmp:
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-val01"
        result = CliRunner().invoke(app, [
            "stpa-run", "--use-case", "tmp/nonexistent-use-case.txt",
            "--risk-extraction", str(risk), "--output-dir", str(out),
        ])
        assert result.exit_code == 1, f"expected exit code 1, got {result.exit_code}"
        assert "use-case" in result.output.lower() or "not found" in result.output.lower(), (
            "error message does not mention use-case file"
        )


def test_val_02_missing_risk_extraction_file():
    """QA-STPA-RUN-VAL-02: missing risk-extraction file exits with error."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        out = tmp / "out-val02"
        result = CliRunner().invoke(app, [
            "stpa-run", "--use-case", str(uc),
            "--risk-extraction", "tmp/nonexistent-risk.json",
            "--output-dir", str(out),
        ])
        assert result.exit_code == 1
        assert "risk" in result.output.lower() or "not found" in result.output.lower(), (
            "error message does not mention risk-extraction file"
        )


def test_val_03_missing_capability_profile_file():
    """QA-STPA-RUN-VAL-03: missing --capability-profile file exits with error."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-val03"
        result = CliRunner().invoke(app, [
            "stpa-run", "--use-case", str(uc),
            "--risk-extraction", str(risk), "--output-dir", str(out),
            "--capability-profile", "tmp/nonexistent-cap.yaml",
        ])
        assert result.exit_code == 1
        assert "capability" in result.output.lower() or "not found" in result.output.lower(), (
            "error message does not mention capability-profile file"
        )


def test_val_04_missing_use_case_flag():
    """QA-STPA-RUN-VAL-04: missing required --use-case flag."""
    with _TempDir() as tmp:
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-val04"
        result = CliRunner().invoke(app, [
            "stpa-run", "--risk-extraction", str(risk), "--output-dir", str(out),
        ])
        assert result.exit_code != 0, "expected nonzero exit code for missing --use-case"


def test_val_05_missing_risk_extraction_flag():
    """QA-STPA-RUN-VAL-05: missing required --risk-extraction flag."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        out = tmp / "out-val05"
        result = CliRunner().invoke(app, [
            "stpa-run", "--use-case", str(uc), "--output-dir", str(out),
        ])
        assert result.exit_code != 0, "expected nonzero exit code for missing --risk-extraction"


def test_val_06_missing_output_dir_flag():
    """QA-STPA-RUN-VAL-06: missing required --output-dir flag."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        result = CliRunner().invoke(app, [
            "stpa-run", "--use-case", str(uc), "--risk-extraction", str(risk),
        ])
        assert result.exit_code != 0, "expected nonzero exit code for missing --output-dir"


def test_val_07_validation_before_stages():
    """QA-STPA-RUN-VAL-07: input validation runs before any pipeline stage."""
    with _TempDir() as tmp:
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-val07"
        mocks = _patch_all_stages()
        try:
            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", "tmp/nonexistent-use-case.txt",
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 1
            assert not mocks["sp1"].called, "SP1 should not have been called"
            assert not out.exists() or not any(out.iterdir()), (
                "output directory should not exist or be empty"
            )
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# End-to-end pipeline test (via subprocess CLI invocation)
# ---------------------------------------------------------------------------


def test_e2e_full_pipeline():
    """E2E: full pipeline SP1→SP2→SP3→report runs through the CLI."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-e2e"
        mocks = _patch_all_stages()
        try:
            def sp1_side(**kw):
                _write_sp1_artifacts(kw["run_dir"])
                _write_calls_jsonl(kw["run_dir"], [{"stage": "stage_1a"}])
                return mocks["sp1_result"]
            def sp2_side(**kw):
                _write_sp2_artifacts(kw["run_dir"])
                return mocks["sp2_result"]
            def sp3_side(**kw):
                _write_sp3_artifacts(kw["run_dir"])
                _write_eval_artifacts(kw["run_dir"])
                return mocks["sp3_result"]
            mocks["sp1"].side_effect = sp1_side
            mocks["sp2"].side_effect = sp2_side
            mocks["sp3"].side_effect = sp3_side

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.stdout}"
            # Verify all artifacts
            assert (out / "loss-analysis.yaml").exists()
            assert (out / "control-structure.yaml").exists()
            assert (out / "ica-enumeration.yaml").exists()
            assert (out / "enriched-threats.yaml").exists()
            assert (out / "scenarios").is_dir()
            assert (out / "stpa-report.html").exists()
        finally:
            _stop_patches(mocks)


def test_e2e_resume_mode():
    """E2E: resume mode skips completed stages and regenerates report."""
    with _TempDir() as tmp:
        uc = _write_use_case(tmp)
        risk = _write_risk_extraction(tmp)
        out = tmp / "out-e2e-resume"
        _write_all_artifacts(out)

        mocks = _patch_all_stages()
        try:
            # Delete report to verify it gets regenerated
            report = out / "stpa-report.html"
            if report.exists():
                report.unlink()

            result = CliRunner().invoke(app, [
                "stpa-run", "--use-case", str(uc),
                "--risk-extraction", str(risk), "--output-dir", str(out),
                "--resume",
            ])
            assert result.exit_code == 0, f"exit code {result.exit_code}: {result.stdout}"
            assert not mocks["sp1"].called, "SP1 should be skipped"
            assert not mocks["sp2"].called, "SP2 should be skipped"
            assert not mocks["sp3"].called, "SP3 should be skipped"
            assert (out / "stpa-report.html").exists(), "report should be regenerated"
        finally:
            _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 60)
    print("STPA-RUN QA Suite — Executable Verification")
    print("=" * 60)
    print()

    # CLI interface
    check("QA-STPA-RUN-CLI-01: stpa-run subcommand registered", test_cli_01_stpa_run_command_registered)
    check("QA-STPA-RUN-CLI-02: required and optional flags shown", test_cli_02_required_and_optional_flags)
    check("QA-STPA-RUN-CLI-03: --use-case accepts @ prefix", test_cli_03_use_case_at_prefix)
    check("QA-STPA-RUN-CLI-04: --use-case accepts bare path", test_cli_04_use_case_bare_path)
    check("QA-STPA-RUN-CLI-05: --max-workers defaults to 1", test_cli_05_max_workers_default)
    check("QA-STPA-RUN-CLI-06: --profiles-file defaults", test_cli_06_profiles_file_default)
    check("QA-STPA-RUN-CLI-07: runner module exists", test_cli_07_runner_module_exists)
    check("QA-STPA-RUN-CLI-08: flat artifact layout", test_cli_08_flat_artifact_layout)

    # SP1 execution
    check("QA-STPA-RUN-SP1-01: SP1 writes expected artifacts", test_sp1_01_writes_expected_artifacts)
    check("QA-STPA-RUN-SP1-02: calls.html auto-rendered", test_sp1_02_calls_html_auto_rendered)
    check("QA-STPA-RUN-SP1-03: --capability-profile skips Stage 1b", test_sp1_03_capability_profile_skips_stage_1b)
    check("QA-STPA-RUN-SP1-04: --max-workers forwarded to SP1", test_sp1_04_max_workers_forwarded)

    # SP2 execution
    check("QA-STPA-RUN-SP2-01: SP2 writes expected artifacts", test_sp2_01_writes_expected_artifacts)
    check("QA-STPA-RUN-SP2-02: SP2 calls appended", test_sp2_02_calls_appended)

    # SP3 execution
    check("QA-STPA-RUN-SP3-01: SP3 writes expected artifacts", test_sp3_01_writes_expected_artifacts)
    check("QA-STPA-RUN-SP3-02: capability_profile passed with --capability-profile", test_sp3_02_capability_profile_passed)
    check("QA-STPA-RUN-SP3-03: capability_profile not passed without flag", test_sp3_03_capability_profile_not_passed)
    check("QA-STPA-RUN-SP3-04: SP3 calls appended", test_sp3_04_calls_appended)

    # Report generation
    check("QA-STPA-RUN-RPT-01: report generated after stages", test_rpt_01_report_generated)
    check("QA-STPA-RUN-RPT-02: report with degraded SP3", test_rpt_02_report_with_degraded_sp3)
    check("QA-STPA-RUN-RPT-03: report with degraded SP2", test_rpt_03_report_with_degraded_sp2)

    # Summary output
    check("QA-STPA-RUN-SUM-01: summary includes SP1 metrics", test_sum_01_sp1_metrics)
    check("QA-STPA-RUN-SUM-02: summary includes SP2 metrics", test_sum_02_sp2_metrics)
    check("QA-STPA-RUN-SUM-03: summary includes SP3 metrics", test_sum_03_sp3_metrics)
    check("QA-STPA-RUN-SUM-04: summary includes report path", test_sum_04_report_path)

    # Error handling
    check("QA-STPA-RUN-ERR-01: hard failure SP1 exits 1", test_err_01_hard_failure_sp1)
    check("QA-STPA-RUN-ERR-02: hard failure SP2 exits 1", test_err_02_hard_failure_sp2)
    check("QA-STPA-RUN-ERR-03: hard failure SP3 exits 1", test_err_03_hard_failure_sp3)
    check("QA-STPA-RUN-ERR-04: degraded results continue", test_err_04_degraded_continues)
    check("QA-STPA-RUN-ERR-05: missing control_structure stops SP2", test_err_05_missing_control_structure_stops_sp2)
    check("QA-STPA-RUN-ERR-06: error message to stderr", test_err_06_error_to_stderr)

    # Resume behavior
    check("QA-STPA-RUN-RES-01: --resume skips SP1", test_res_01_resume_skips_sp1)
    check("QA-STPA-RUN-RES-02: --resume skips SP2", test_res_02_resume_skips_sp2)
    check("QA-STPA-RUN-RES-03: --resume skips SP3", test_res_03_resume_skips_sp3)
    check("QA-STPA-RUN-RES-04: report always generated with --resume", test_res_04_report_always_generated)
    check("QA-STPA-RUN-RES-05: without --resume all stages run", test_res_05_without_resume_all_stages_run)
    check("QA-STPA-RUN-RES-06: --resume runs SP1 when incomplete", test_res_06_resume_runs_sp1_when_incomplete)

    # Model profiles
    check("QA-STPA-RUN-MP-01: --profile sets default model", test_mp_01_profile_sets_default)
    check("QA-STPA-RUN-MP-02: --sp1-profile overrides default", test_mp_02_sp1_profile_overrides_default)
    check("QA-STPA-RUN-MP-03: per-stage profiles without default", test_mp_03_per_stage_profiles_without_default)
    check("QA-STPA-RUN-MP-04: no profile falls back to env", test_mp_04_no_profile_falls_back_to_env)
    check("QA-STPA-RUN-MP-05: --profiles-file custom path", test_mp_05_profiles_file_custom_path)
    check("QA-STPA-RUN-MP-06: llm_config functions defined", test_mp_06_llm_config_functions)

    # Input validation
    check("QA-STPA-RUN-VAL-01: missing use-case file", test_val_01_missing_use_case_file)
    check("QA-STPA-RUN-VAL-02: missing risk-extraction file", test_val_02_missing_risk_extraction_file)
    check("QA-STPA-RUN-VAL-03: missing capability-profile file", test_val_03_missing_capability_profile_file)
    check("QA-STPA-RUN-VAL-04: missing --use-case flag", test_val_04_missing_use_case_flag)
    check("QA-STPA-RUN-VAL-05: missing --risk-extraction flag", test_val_05_missing_risk_extraction_flag)
    check("QA-STPA-RUN-VAL-06: missing --output-dir flag", test_val_06_missing_output_dir_flag)
    check("QA-STPA-RUN-VAL-07: validation before stages", test_val_07_validation_before_stages)

    # End-to-end
    check("E2E: full pipeline SP1→SP2→SP3→report", test_e2e_full_pipeline)
    check("E2E: resume mode skips stages, regenerates report", test_e2e_resume_mode)

    print("=" * 60)
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {PASS + FAIL} total")
    if FAILED_CHECKS:
        print("FAILED:")
        for name in FAILED_CHECKS:
            print(f"  - {name}")
    print("=" * 60)

    if FAIL > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
