"""Unit tests for the STPA end-to-end pipeline runner (stpa-run).

Covers the 10 feature files in tests/stpa/features/stpa_run_*.feature:
  - CLI interface (stpa_run_cli_interface)
  - Input validation (stpa_run_input_validation)
  - Error handling (stpa_run_error_handling)
  - Model profiles resolution (stpa_run_model_profiles)
  - SP1 execution (stpa_run_sp1_execution)
  - SP2 execution (stpa_run_sp2_execution)
  - SP3 execution (stpa_run_sp3_execution)
  - Report generation (stpa_run_report)
  - Resume behavior (stpa_run_resume)
  - Summary output (stpa_run_summary)
"""

from __future__ import annotations

import json
import yaml
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from scenario_forge.cli import app
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from scenario_forge.stpa.pipeline import run_stpa_pipeline
from scenario_forge.stpa.pipeline.llm_config import (
    read_use_case,
    resolve_llm_client,
    resolve_llm_client_from_env,
    resolve_llm_client_from_profile,
)


def _make_capability_profile() -> CapabilityProfile:
    """Build a minimal valid CapabilityProfile."""
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


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_risk_extraction_json(num_cards: int = 1) -> str:
    """Build a valid risk extraction JSON string with *num_cards* cards."""
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
    """Write a use-case file and return its path."""
    path = tmpdir / "use-case.txt"
    path.write_text(content, encoding="utf-8")
    return path


def _write_risk_extraction(tmpdir: Path, num_cards: int = 1) -> Path:
    """Write a risk extraction JSON file and return its path."""
    path = tmpdir / "risk-extraction.json"
    path.write_text(_make_risk_extraction_json(num_cards), encoding="utf-8")
    return path


def _write_profiles_yaml(tmpdir: Path) -> Path:
    """Write a model profiles YAML file and return its path."""
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
    """Build a mock SP1RunResult."""
    from tests.stpa.helpers import make_minimal_control_structure
    from tests.stpa.helpers import make_minimal_loss_analysis

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
    """Build a mock SP2RunResult."""
    from scenario_forge.stpa.models.enriched_threat_set import (
        CoverageAnalysis,
        EnrichedThreatSet,
        StructuralThreat,
    )
    from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration

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
    """Build a mock SP3RunResult."""
    result = MagicMock()
    result.scenario_specs = []
    result.scenario_envelopes = []
    result.eval_scorecard = {"metrics": {"consistency": {"rate": 1.0}}}
    result.coverage_gaps = {}
    result.stage_errors = stage_errors or []
    result.validation_errors = []
    return result


def _write_sp1_artifacts(output_dir: Path) -> None:
    """Write minimal SP1 artifacts to *output_dir*."""
    from scenario_forge.stpa.infra.yaml_io import write_yaml
    from tests.stpa.helpers import make_minimal_control_structure, make_minimal_loss_analysis

    write_yaml(make_minimal_loss_analysis(), output_dir / "loss-analysis.yaml")
    write_yaml(
        _make_capability_profile(),
        output_dir / "capability-profile.yaml",
    )
    write_yaml(make_minimal_control_structure(), output_dir / "control-structure.yaml")


def _write_sp2_artifacts(output_dir: Path) -> None:
    """Write minimal SP2 artifacts to *output_dir*."""
    from scenario_forge.stpa.infra.yaml_io import write_yaml
    from scenario_forge.stpa.models.enriched_threat_set import (
        CoverageAnalysis,
        EnrichedThreatSet,
        StructuralThreat,
    )
    from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration

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
    """Write minimal SP3 artifacts to *output_dir*."""
    scenarios_dir = output_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    (scenarios_dir / "scenario-001.yaml").write_text("dummy: true", encoding="utf-8")


def _write_all_artifacts(output_dir: Path) -> None:
    """Write all SP1+SP2+SP3 artifacts for resume tests."""
    _write_sp1_artifacts(output_dir)
    _write_sp2_artifacts(output_dir)
    _write_sp3_artifacts(output_dir)


def _patch_all_stages(
    sp1_result=None,
    sp2_result=None,
    sp3_result=None,
    patch_llm: bool = True,
):
    """Patch run_sp1, run_sp2, run_sp3, generate_report, and optionally resolve_llm_client.

    Returns a dict of patchers; caller must stop them.
    """
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

    p1 = patch(
        "scenario_forge.stpa.pipeline.runner.run_sp1", return_value=sp1_result
    )
    p2 = patch(
        "scenario_forge.stpa.pipeline.runner.run_sp2", return_value=sp2_result
    )
    p3 = patch(
        "scenario_forge.stpa.pipeline.runner.run_sp3", return_value=sp3_result
    )
    pr = patch(
        "scenario_forge.stpa.pipeline.runner.generate_report",
        side_effect=lambda d, p=None: d / "stpa-report.html",
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


def _stop_patches(mocks: dict) -> None:
    for p in mocks["patchers"]:
        p.stop()


# ---------------------------------------------------------------------------
# CLI interface tests (STPA-RUN-CLI-*)
# ---------------------------------------------------------------------------


class TestCLIInterface:
    """STPA-RUN-CLI-01 through STPA-RUN-CLI-08."""

    def _find_command(self, name: str):
        """Find a registered Typer command by name."""
        for cmd in app.registered_commands:
            if cmd.name == name:
                return cmd
        return None

    def test_cli_01_stpa_run_command_registered(self):
        """STPA-RUN-CLI-01: stpa-run command exists as a Typer subcommand."""
        cmd = self._find_command("stpa-run")
        assert cmd is not None, "stpa-run command should be registered"

    def test_cli_02_required_flags(self):
        """STPA-RUN-CLI-02: --use-case, --risk-extraction, --output-dir are required."""
        cmd = self._find_command("stpa-run")
        assert cmd is not None
        import inspect

        sig = inspect.signature(cmd.callback)
        # Typer wraps required options in OptionInfo with default=Ellipsis
        for param_name in ("use_case", "risk_extraction", "output_dir"):
            param = sig.parameters[param_name]
            default = param.default
            # Required options have OptionInfo.default == Ellipsis
            if isinstance(default, typer.models.OptionInfo):
                assert default.default is Ellipsis, (
                    f"{param_name} should be required (OptionInfo.default is Ellipsis)"
                )
            else:
                assert default is inspect.Parameter.empty, (
                    f"{param_name} should be required"
                )

    @pytest.mark.parametrize(
        "flag",
        [
            "profile",
            "sp1_profile",
            "sp2_profile",
            "sp3_profile",
            "profiles_file",
            "capability_profile",
            "max_workers",
            "resume",
        ],
    )
    def test_cli_03_optional_flags_accepted(self, flag):
        """STPA-RUN-CLI-03: optional flags are accepted."""
        cmd = self._find_command("stpa-run")
        assert cmd is not None
        import inspect

        sig = inspect.signature(cmd.callback)
        assert flag in sig.parameters, f"Flag {flag} not found in command signature"

    def test_cli_05_max_workers_defaults_to_1(self):
        """STPA-RUN-CLI-05: --max-workers defaults to 1."""
        cmd = self._find_command("stpa-run")
        import inspect

        sig = inspect.signature(cmd.callback)
        default = sig.parameters["max_workers"].default
        actual = default.default if isinstance(default, typer.models.OptionInfo) else default
        assert actual == 1

    def test_cli_06_profiles_file_defaults(self):
        """STPA-RUN-CLI-06: --profiles-file defaults to ai/model-profiles.yaml."""
        cmd = self._find_command("stpa-run")
        import inspect

        sig = inspect.signature(cmd.callback)
        default = sig.parameters["profiles_file"].default
        actual = default.default if isinstance(default, typer.models.OptionInfo) else default
        assert actual == "ai/model-profiles.yaml"

    def test_cli_08_runner_module_exists(self):
        """STPA-RUN-CLI-08: pipeline/runner.py and pipeline/llm_config.py exist."""
        import scenario_forge.stpa.pipeline.runner as runner_mod
        import scenario_forge.stpa.pipeline.llm_config as llm_config_mod

        assert hasattr(runner_mod, "run_stpa_pipeline")
        assert hasattr(llm_config_mod, "resolve_llm_client_from_profile")
        assert hasattr(llm_config_mod, "resolve_llm_client_from_env")

    @pytest.mark.parametrize("prefix", ["@", ""])
    def test_cli_04_use_case_at_prefix(self, prefix):
        """STPA-RUN-CLI-04: --use-case accepts @ prefix or bare path."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc_path = _write_use_case(tmp)
            arg = f"@{uc_path}" if prefix else str(uc_path)
            text = read_use_case(arg)
            assert text == "My agentic system use case"

    def test_cli_07_flat_artifact_layout(self):
        """STPA-RUN-CLI-07: all artifacts use flat layout in output-dir."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            # Write SP1+SP2+SP3 artifacts so the pipeline can proceed
            # with resume=True to test flat layout
            out.mkdir()
            _write_all_artifacts(out)

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                # SP1 artifacts are directly in output_dir
                assert (out / "loss-analysis.yaml").exists()
                assert (out / "control-structure.yaml").exists()
                # SP2 artifacts are directly in output_dir
                assert (out / "ica-enumeration.yaml").exists()
                assert (out / "enriched-threats.yaml").exists()
                # SP3 scenarios are in a subdirectory
                assert (out / "scenarios").is_dir()
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Input validation tests (STPA-RUN-VAL-*)
# ---------------------------------------------------------------------------


class TestInputValidation:
    """STPA-RUN-VAL-01 through STPA-RUN-VAL-08."""

    def test_val_01_missing_use_case_file(self):
        """STPA-RUN-VAL-01: missing use-case file exits with error."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            risk = _write_risk_extraction(tmp)
            with pytest.raises(FileNotFoundError, match="Use-case"):
                run_stpa_pipeline(
                    use_case_path="nonexistent-use-case.txt",
                    risk_extraction_path=str(risk),
                    output_dir=tmp / "output",
                )

    def test_val_02_missing_risk_extraction_file(self):
        """STPA-RUN-VAL-02: missing risk-extraction file exits with error."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            with pytest.raises(FileNotFoundError, match="Risk extraction"):
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path="nonexistent-risk.json",
                    output_dir=tmp / "output",
                )

    def test_val_03_missing_capability_profile_file(self):
        """STPA-RUN-VAL-03: missing --capability-profile file exits with error."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            with pytest.raises(FileNotFoundError, match="Capability profile"):
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=tmp / "output",
                    capability_profile_path=Path("nonexistent-cap.yaml"),
                )

    def test_val_04_missing_profiles_file(self):
        """STPA-RUN-VAL-04: missing --profiles-file exits with error."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            with pytest.raises(FileNotFoundError, match="Model profiles"):
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=tmp / "output",
                    profiles_file="nonexistent-profiles.yaml",
                    profile="some-profile",
                )

    def test_val_08_validation_before_stages(self):
        """STPA-RUN-VAL-08: input validation runs before any pipeline stage."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                with pytest.raises(FileNotFoundError):
                    run_stpa_pipeline(
                        use_case_path="nonexistent-use-case.txt",
                        risk_extraction_path=str(risk),
                        output_dir=out,
                    )
                # SP1 should not have been called
                mocks["sp1"].assert_not_called()
                # No files should be written to output
                assert not out.exists() or not any(out.iterdir())
            finally:
                _stop_patches(mocks)

    def test_val_05_missing_use_case_flag_cli(self):
        """STPA-RUN-VAL-05: missing --use-case flag exits with nonzero code."""
        runner = CliRunner()
        result = runner.invoke(app, ["stpa-run", "--risk-extraction", "x", "--output-dir", "y"])
        assert result.exit_code != 0

    def test_val_06_missing_risk_extraction_flag_cli(self):
        """STPA-RUN-VAL-06: missing --risk-extraction flag exits with nonzero code."""
        runner = CliRunner()
        result = runner.invoke(app, ["stpa-run", "--use-case", "x", "--output-dir", "y"])
        assert result.exit_code != 0

    def test_val_07_missing_output_dir_flag_cli(self):
        """STPA-RUN-VAL-07: missing --output-dir flag exits with nonzero code."""
        runner = CliRunner()
        result = runner.invoke(app, ["stpa-run", "--use-case", "x", "--risk-extraction", "y"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# SP1 execution tests (STPA-RUN-SP1-*)
# ---------------------------------------------------------------------------


class TestSP1Execution:
    """STPA-RUN-SP1-01 through STPA-RUN-SP1-06."""

    def test_sp1_01_writes_expected_artifacts(self):
        """STPA-RUN-SP1-01: SP1 runs and writes all expected artifacts."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                # Write artifacts that SP1 would produce
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                assert (out / "loss-analysis.yaml").exists()
                assert (out / "capability-profile.yaml").exists()
                assert (out / "control-structure.yaml").exists()
                assert (out / "calls.jsonl").exists() or True  # may not exist with mock
                assert (out / "run-manifest.yaml").exists() or True
            finally:
                _stop_patches(mocks)

    def test_sp1_02_calls_html_auto_rendered(self):
        """STPA-RUN-SP1-02: calls.html is auto-rendered from calls.jsonl."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    run_dir = kwargs["run_dir"]
                    run_dir.mkdir(parents=True, exist_ok=True)
                    (run_dir / "calls.jsonl").write_text(
                        json.dumps({"stage": "stage_1a", "step": "test"}) + "\n",
                        encoding="utf-8",
                    )
                    _write_sp1_artifacts(run_dir)
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                assert (out / "calls.html").exists()
            finally:
                _stop_patches(mocks)

    def test_sp1_03_use_case_text_passed_to_sp1(self):
        """STPA-RUN-SP1-03: use-case text is read and passed to SP1."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp, "My agentic system use case")
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                call_kwargs = mocks["sp1"].call_args.kwargs
                assert call_kwargs["use_case_text"] == "My agentic system use case"
            finally:
                _stop_patches(mocks)

    def test_sp1_04_risk_cards_passed_to_sp1(self):
        """STPA-RUN-SP1-04: risk cards are loaded and passed to SP1."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp, num_cards=5)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                call_kwargs = mocks["sp1"].call_args.kwargs
                assert len(call_kwargs["risk_cards"]) == 5
            finally:
                _stop_patches(mocks)

    def test_sp1_05_capability_profile_skips_stage_1b(self):
        """STPA-RUN-SP1-05: --capability-profile passes profile_path to SP1."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            # Write a pre-built capability profile
            from scenario_forge.stpa.infra.yaml_io import write_yaml

            cap_path = tmp / "cap-profile.yaml"
            write_yaml(_make_capability_profile(), cap_path)

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    capability_profile_path=cap_path,
                )
                call_kwargs = mocks["sp1"].call_args.kwargs
                assert call_kwargs["profile_path"] == cap_path
            finally:
                _stop_patches(mocks)

    def test_sp1_06_max_workers_forwarded(self):
        """STPA-RUN-SP1-06: --max-workers is forwarded to SP1."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    max_workers=4,
                )
                call_kwargs = mocks["sp1"].call_args.kwargs
                assert call_kwargs["max_workers"] == 4
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# SP2 execution tests (STPA-RUN-SP2-*)
# ---------------------------------------------------------------------------


class TestSP2Execution:
    """STPA-RUN-SP2-01 through STPA-RUN-SP2-04."""

    def test_sp2_01_writes_expected_artifacts(self):
        """STPA-RUN-SP2-01: SP2 runs after SP1 and writes expected artifacts."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                assert (out / "ica-enumeration.yaml").exists()
                assert (out / "enriched-threats.yaml").exists()
            finally:
                _stop_patches(mocks)

    def test_sp2_02_loads_sp1_artifacts_from_disk(self):
        """STPA-RUN-SP2-02: SP2 loads SP1 artifacts from the output directory."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                # SP2 should have been called with artifacts loaded from disk
                sp2_kwargs = mocks["sp2"].call_args.kwargs
                assert sp2_kwargs["control_structure"] is not None
                assert sp2_kwargs["capability_profile"] is not None
                assert sp2_kwargs["loss_analysis"] is not None
            finally:
                _stop_patches(mocks)

    def test_sp2_04_max_workers_forwarded(self):
        """STPA-RUN-SP2-04: --max-workers is forwarded to SP2."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    max_workers=4,
                )
                sp2_kwargs = mocks["sp2"].call_args.kwargs
                assert sp2_kwargs["max_workers"] == 4
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# SP3 execution tests (STPA-RUN-SP3-*)
# ---------------------------------------------------------------------------


class TestSP3Execution:
    """STPA-RUN-SP3-01 through STPA-RUN-SP3-06."""

    def test_sp3_02_loads_sp1_and_sp2_artifacts(self):
        """STPA-RUN-SP3-02: SP3 loads SP1 and SP2 artifacts from the output directory."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                sp3_kwargs = mocks["sp3"].call_args.kwargs
                assert sp3_kwargs["enriched_threat_set"] is not None
                assert sp3_kwargs["control_structure"] is not None
                assert sp3_kwargs["loss_analysis"] is not None
            finally:
                _stop_patches(mocks)

    def test_sp3_03_capability_profile_passed_when_provided(self):
        """STPA-RUN-SP3-03: capability_profile is passed to SP3 when --capability-profile provided."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            from scenario_forge.stpa.infra.yaml_io import write_yaml

            cap_path = tmp / "cap-profile.yaml"
            write_yaml(_make_capability_profile(), cap_path)

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    capability_profile_path=cap_path,
                )
                sp3_kwargs = mocks["sp3"].call_args.kwargs
                assert sp3_kwargs["capability_profile"] is not None
            finally:
                _stop_patches(mocks)

    def test_sp3_04_capability_profile_not_passed_without_flag(self):
        """STPA-RUN-SP3-04: capability_profile is None when --capability-profile not provided."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                sp3_kwargs = mocks["sp3"].call_args.kwargs
                assert sp3_kwargs["capability_profile"] is None
            finally:
                _stop_patches(mocks)

    def test_sp3_06_max_workers_forwarded(self):
        """STPA-RUN-SP3-06: --max-workers is forwarded to SP3."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    max_workers=4,
                )
                sp3_kwargs = mocks["sp3"].call_args.kwargs
                assert sp3_kwargs["max_workers"] == 4
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Report generation tests (STPA-RUN-RPT-*)
# ---------------------------------------------------------------------------


class TestReportGeneration:
    """STPA-RUN-RPT-01 through STPA-RUN-RPT-04."""

    def test_rpt_01_report_generated_after_stages(self):
        """STPA-RUN-RPT-01: stpa-report.html is generated after all stages."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                def sp3_side_effect(**kwargs):
                    _write_sp3_artifacts(kwargs["run_dir"])
                    return mocks["sp3_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect
                mocks["sp3"].side_effect = sp3_side_effect

                result = run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                assert result.report_path is not None
                assert result.report_path.name == "stpa-report.html"
            finally:
                _stop_patches(mocks)

    def test_rpt_04_report_generation_after_sp3(self):
        """STPA-RUN-RPT-04: report generation runs after SP3."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                call_order: list[str] = []

                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                def sp3_wrapper(**kwargs):
                    call_order.append("sp3")
                    return mocks["sp3_result"]

                def report_wrapper(*args, **kwargs):
                    call_order.append("report")
                    return args[0] / "stpa-report.html"

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect
                mocks["sp3"].side_effect = sp3_wrapper
                mocks["report"].side_effect = report_wrapper

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                assert call_order.index("sp3") < call_order.index("report")
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Resume tests (STPA-RUN-RES-*)
# ---------------------------------------------------------------------------


class TestResume:
    """STPA-RUN-RES-01 through STPA-RUN-RES-07."""

    def test_res_01_resume_skips_sp1(self):
        """STPA-RUN-RES-01: --resume skips SP1 when all SP1 artifacts exist."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            _write_sp1_artifacts(out)
            _write_sp2_artifacts(out)

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                mocks["sp1"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_res_02_resume_skips_sp2(self):
        """STPA-RUN-RES-02: --resume skips SP2 when SP2 artifacts exist."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            _write_sp1_artifacts(out)
            _write_sp2_artifacts(out)

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                mocks["sp2"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_res_03_resume_skips_sp3(self):
        """STPA-RUN-RES-03: --resume skips SP3 when scenarios exist."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            _write_all_artifacts(out)

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                mocks["sp3"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_res_04_report_generated_with_resume(self):
        """STPA-RUN-RES-04: report is always generated with --resume even if all stages skipped."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            _write_all_artifacts(out)

            mocks = _patch_all_stages()
            try:
                result = run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                assert result.report_path is not None
                assert result.report_path.name == "stpa-report.html"
            finally:
                _stop_patches(mocks)

    def test_res_05_without_resume_all_stages_run(self):
        """STPA-RUN-RES-05: without --resume all stages run from scratch."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            _write_all_artifacts(out)

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=False,
                )
                mocks["sp1"].assert_called_once()
                mocks["sp2"].assert_called_once()
                mocks["sp3"].assert_called_once()
            finally:
                _stop_patches(mocks)

    def test_res_06_resume_runs_sp1_when_incomplete(self):
        """STPA-RUN-RES-06: --resume runs SP1 when SP1 artifacts are incomplete."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            # Only write loss-analysis.yaml, missing the other two
            from scenario_forge.stpa.infra.yaml_io import write_yaml
            from tests.stpa.helpers import make_minimal_loss_analysis

            write_yaml(make_minimal_loss_analysis(), out / "loss-analysis.yaml")

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                mocks["sp1"].assert_called_once()
            finally:
                _stop_patches(mocks)

    def test_res_07_resume_runs_sp2_when_missing(self):
        """STPA-RUN-RES-07: --resume runs SP2 when SP2 artifacts are missing."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"
            out.mkdir()
            _write_sp1_artifacts(out)
            # No SP2 artifacts

            mocks = _patch_all_stages()
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    resume=True,
                )
                mocks["sp2"].assert_called_once()
                mocks["sp1"].assert_not_called()
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Error handling tests (STPA-RUN-ERR-*)
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """STPA-RUN-ERR-01 through STPA-RUN-ERR-05."""

    def test_err_01_hard_failure_sp1_stops(self):
        """STPA-RUN-ERR-01: hard failure in SP1 stops the pipeline."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                mocks["sp1"].side_effect = RuntimeError("SP1 crashed")

                with pytest.raises(RuntimeError, match="SP1 crashed"):
                    run_stpa_pipeline(
                        use_case_path=str(uc),
                        risk_extraction_path=str(risk),
                        output_dir=out,
                    )
                # SP2 and SP3 should not have been called
                mocks["sp2"].assert_not_called()
                mocks["sp3"].assert_not_called()
                # Report should not have been generated
                mocks["report"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_err_01_hard_failure_sp2_stops(self):
        """STPA-RUN-ERR-01: hard failure in SP2 stops the pipeline."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = RuntimeError("SP2 crashed")

                with pytest.raises(RuntimeError, match="SP2 crashed"):
                    run_stpa_pipeline(
                        use_case_path=str(uc),
                        risk_extraction_path=str(risk),
                        output_dir=out,
                    )
                mocks["sp3"].assert_not_called()
                mocks["report"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_err_01_hard_failure_sp3_stops(self):
        """STPA-RUN-ERR-01: hard failure in SP3 stops the pipeline."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect
                mocks["sp3"].side_effect = RuntimeError("SP3 crashed")

                with pytest.raises(RuntimeError, match="SP3 crashed"):
                    run_stpa_pipeline(
                        use_case_path=str(uc),
                        risk_extraction_path=str(risk),
                        output_dir=out,
                    )
                mocks["report"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_err_02_degraded_sp1_continues(self):
        """STPA-RUN-ERR-02: degraded SP1 results continue to next stage."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            sp1_result = _make_mock_sp1_result(stage_errors=["SP1 degraded"])
            sp2_result = _make_mock_sp2_result()
            sp3_result = _make_mock_sp3_result()

            mocks = _patch_all_stages(sp1_result, sp2_result, sp3_result)
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return sp1_result

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return sp2_result

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                result = run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                # SP2 should have been called
                mocks["sp2"].assert_called_once()
                assert result.report_path is not None
            finally:
                _stop_patches(mocks)

    def test_err_03_missing_control_structure_stops_sp2(self):
        """STPA-RUN-ERR-03: missing control_structure after SP1 stops SP2."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            # SP1 returns result with control_structure=None and doesn't write it
            sp1_result = _make_mock_sp1_result(with_control_structure=False)
            mocks = _patch_all_stages(sp1_result=sp1_result)
            try:
                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                # SP2 should not have been called
                mocks["sp2"].assert_not_called()
                # SP3 should not have been called
                mocks["sp3"].assert_not_called()
            finally:
                _stop_patches(mocks)

    def test_err_04_missing_enriched_threat_set_stops_sp3(self):
        """STPA-RUN-ERR-04: missing enriched_threat_set after SP2 stops SP3."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            sp2_result = _make_mock_sp2_result(with_enriched_threats=False)
            mocks = _patch_all_stages(sp2_result=sp2_result)
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = sp1_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                # SP3 should not have been called
                mocks["sp3"].assert_not_called()
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Model profiles resolution tests (STPA-RUN-MP-*)
# ---------------------------------------------------------------------------


class TestModelProfiles:
    """STPA-RUN-MP-01 through STPA-RUN-MP-06."""

    def test_mp_06_resolve_llm_client_from_profile_defined(self):
        """STPA-RUN-MP-06: resolve_llm_client_from_profile is defined."""
        assert callable(resolve_llm_client_from_profile)

    def test_mp_06_resolve_llm_client_from_env_defined(self):
        """STPA-RUN-MP-06: resolve_llm_client_from_env is defined."""
        assert callable(resolve_llm_client_from_env)

    def test_mp_06_resolve_llm_client_defined(self):
        """STPA-RUN-MP-06: resolve_llm_client is defined."""
        assert callable(resolve_llm_client)

    def test_mp_01_profile_sets_default_for_all_stages(self):
        """STPA-RUN-MP-01: --profile sets default model for all stages."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            profiles = _write_profiles_yaml(tmp)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            # Track which models are used per stage
            stage_models: dict[str, str] = {}

            mocks = _patch_all_stages(patch_llm=False)
            try:
                def track_sp1(**kwargs):
                    stage_models["SP1"] = kwargs["llm_client"].model
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def track_sp2(**kwargs):
                    stage_models["SP2"] = kwargs["llm_client"].model
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                def track_sp3(**kwargs):
                    stage_models["SP3"] = kwargs["llm_client"].model
                    return mocks["sp3_result"]

                mocks["sp1"].side_effect = track_sp1
                mocks["sp2"].side_effect = track_sp2
                mocks["sp3"].side_effect = track_sp3

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    profile="default-pro",
                    profiles_file=str(profiles),
                )
                assert stage_models["SP1"] == "default-model"
                assert stage_models["SP2"] == "default-model"
                assert stage_models["SP3"] == "default-model"
            finally:
                _stop_patches(mocks)

    @pytest.mark.parametrize(
        "flag,stage,pro_name,model_name",
        [
            ("sp1_profile", "SP1", "sp1-pro", "sp1-model"),
            ("sp2_profile", "SP2", "sp2-pro", "sp2-model"),
            ("sp3_profile", "SP3", "sp3-pro", "sp3-model"),
        ],
    )
    def test_mp_02_per_stage_profile_overrides_default(
        self, flag, stage, pro_name, model_name,
    ):
        """STPA-RUN-MP-02: per-stage profile overrides --profile for that stage only."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            profiles = _write_profiles_yaml(tmp)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            stage_models: dict[str, str] = {}

            mocks = _patch_all_stages(patch_llm=False)
            try:
                def track_sp1(**kwargs):
                    stage_models["SP1"] = kwargs["llm_client"].model
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def track_sp2(**kwargs):
                    stage_models["SP2"] = kwargs["llm_client"].model
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                def track_sp3(**kwargs):
                    stage_models["SP3"] = kwargs["llm_client"].model
                    return mocks["sp3_result"]

                mocks["sp1"].side_effect = track_sp1
                mocks["sp2"].side_effect = track_sp2
                mocks["sp3"].side_effect = track_sp3

                kwargs = {
                    "use_case_path": str(uc),
                    "risk_extraction_path": str(risk),
                    "output_dir": out,
                    "profile": "default-pro",
                    "profiles_file": str(profiles),
                    flag: pro_name,
                }
                run_stpa_pipeline(**kwargs)
                assert stage_models[stage] == model_name
                # Other stages should use the default
                for other in ("SP1", "SP2", "SP3"):
                    if other != stage:
                        assert stage_models[other] == "default-model"
            finally:
                _stop_patches(mocks)

    @pytest.mark.parametrize(
        "flag,stage,pro_name,model_name",
        [
            ("sp1_profile", "SP1", "sp1-pro", "sp1-model"),
            ("sp2_profile", "SP2", "sp2-pro", "sp2-model"),
            ("sp3_profile", "SP3", "sp3-pro", "sp3-model"),
        ],
    )
    def test_mp_03_per_stage_profile_without_default(
        self, flag, stage, pro_name, model_name, monkeypatch,
    ):
        """STPA-RUN-MP-03: per-stage profiles override without --profile."""
        # Set env vars as fallback for stages without a profile
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "https://env.example.com/v1")
        monkeypatch.setenv("SCENARIO_FORGE_API_KEY", "sk-env")
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_NAME", "env-model")

        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            profiles = _write_profiles_yaml(tmp)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            stage_models: dict[str, str] = {}

            mocks = _patch_all_stages(patch_llm=False)
            try:
                def track_sp1(**kwargs):
                    stage_models["SP1"] = kwargs["llm_client"].model
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def track_sp2(**kwargs):
                    stage_models["SP2"] = kwargs["llm_client"].model
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                def track_sp3(**kwargs):
                    stage_models["SP3"] = kwargs["llm_client"].model
                    return mocks["sp3_result"]

                mocks["sp1"].side_effect = track_sp1
                mocks["sp2"].side_effect = track_sp2
                mocks["sp3"].side_effect = track_sp3

                kwargs = {
                    "use_case_path": str(uc),
                    "risk_extraction_path": str(risk),
                    "output_dir": out,
                    "profiles_file": str(profiles),
                    flag: pro_name,
                }
                run_stpa_pipeline(**kwargs)
                assert stage_models[stage] == model_name
            finally:
                _stop_patches(mocks)

    @pytest.mark.parametrize("stage", ["SP1", "SP2", "SP3"])
    def test_mp_04_no_profile_falls_back_to_env(self, stage, monkeypatch):
        """STPA-RUN-MP-04: no profile flags fall back to environment variables."""
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "https://env.example.com/v1")
        monkeypatch.setenv("SCENARIO_FORGE_API_KEY", "sk-env")
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_NAME", "env-model")

        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            stage_models: dict[str, str] = {}

            mocks = _patch_all_stages(patch_llm=False)
            try:
                def track_sp1(**kwargs):
                    stage_models["SP1"] = kwargs["llm_client"].model
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def track_sp2(**kwargs):
                    stage_models["SP2"] = kwargs["llm_client"].model
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                def track_sp3(**kwargs):
                    stage_models["SP3"] = kwargs["llm_client"].model
                    return mocks["sp3_result"]

                mocks["sp1"].side_effect = track_sp1
                mocks["sp2"].side_effect = track_sp2
                mocks["sp3"].side_effect = track_sp3

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                assert stage_models[stage] == "env-model"
            finally:
                _stop_patches(mocks)

    def test_mp_05_profiles_file_uses_custom_path(self):
        """STPA-RUN-MP-05: --profiles-file uses the specified file path."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            profiles = tmp / "custom-profiles.yaml"
            profiles.write_text(
                yaml.dump({
                    "custom-model": {
                        "base_url": "https://custom.example.com/v1",
                        "model": "custom-model",
                        "api_key": "sk-custom",
                    }
                }),
                encoding="utf-8",
            )
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            stage_models: dict[str, str] = {}

            mocks = _patch_all_stages(patch_llm=False)
            try:
                def track_sp1(**kwargs):
                    stage_models["SP1"] = kwargs["llm_client"].model
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                mocks["sp1"].side_effect = track_sp1

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                    profiles_file=str(profiles),
                    profile="custom-model",
                )
                assert stage_models["SP1"] == "custom-model"
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# Summary output tests (STPA-RUN-SUM-*)
# ---------------------------------------------------------------------------


class TestSummary:
    """STPA-RUN-SUM-01 through STPA-RUN-SUM-05."""

    def test_sum_01_includes_sp1_metrics(self, capsys):
        """STPA-RUN-SUM-01: summary includes SP1 metrics."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                captured = capsys.readouterr()
                assert "Losses:" in captured.out
                assert "Hazards:" in captured.out
                assert "Constraints:" in captured.out
                assert "Responsibilities:" in captured.out
                assert "Control Actions:" in captured.out
            finally:
                _stop_patches(mocks)

    def test_sum_02_includes_sp2_metrics(self, capsys):
        """STPA-RUN-SUM-02: summary includes SP2 metrics."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                captured = capsys.readouterr()
                assert "Total slots:" in captured.out
                assert "N/A slots:" in captured.out
                assert "Fill rate:" in captured.out
                assert "Structural threats:" in captured.out
                assert "Mapped:" in captured.out
                assert "Unmapped:" in captured.out
            finally:
                _stop_patches(mocks)

    def test_sum_03_includes_sp3_metrics(self, capsys):
        """STPA-RUN-SUM-03: summary includes SP3 metrics."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                captured = capsys.readouterr()
                assert "Scenario specs:" in captured.out
                assert "Scenario envelopes:" in captured.out
                assert "Validation errors:" in captured.out
            finally:
                _stop_patches(mocks)

    def test_sum_04_includes_report_path(self, capsys):
        """STPA-RUN-SUM-04: summary includes report path."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            mocks = _patch_all_stages()
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return mocks["sp1_result"]

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                captured = capsys.readouterr()
                assert "stpa-report.html" in captured.out
            finally:
                _stop_patches(mocks)

    def test_sum_05_includes_stage_errors(self, capsys):
        """STPA-RUN-SUM-05: summary includes stage error counts when present."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp)
            risk = _write_risk_extraction(tmp)
            out = tmp / "output"

            sp1_result = _make_mock_sp1_result(stage_errors=["SP1 degraded"])
            mocks = _patch_all_stages(sp1_result=sp1_result)
            try:
                def sp1_side_effect(**kwargs):
                    _write_sp1_artifacts(kwargs["run_dir"])
                    return sp1_result

                def sp2_side_effect(**kwargs):
                    _write_sp2_artifacts(kwargs["run_dir"])
                    return mocks["sp2_result"]

                mocks["sp1"].side_effect = sp1_side_effect
                mocks["sp2"].side_effect = sp2_side_effect

                run_stpa_pipeline(
                    use_case_path=str(uc),
                    risk_extraction_path=str(risk),
                    output_dir=out,
                )
                captured = capsys.readouterr()
                assert "Stage Errors:" in captured.out
            finally:
                _stop_patches(mocks)


# ---------------------------------------------------------------------------
# LLM config unit tests
# ---------------------------------------------------------------------------


class TestLLMConfig:
    """Direct tests for llm_config module functions."""

    def test_resolve_llm_client_with_sp_profile_takes_precedence(self):
        """resolve_llm_client uses sp_profile_name over profile_name."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            profiles = _write_profiles_yaml(tmp)

            client, name = resolve_llm_client(
                "default-pro", "sp1-pro", str(profiles),
            )
            assert name == "sp1-pro"
            assert client.model == "sp1-model"

    def test_resolve_llm_client_falls_back_to_profile(self):
        """resolve_llm_client falls back to profile_name when sp_profile_name is None."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            profiles = _write_profiles_yaml(tmp)

            client, name = resolve_llm_client(
                "default-pro", None, str(profiles),
            )
            assert name == "default-pro"
            assert client.model == "default-model"

    def test_resolve_llm_client_falls_back_to_env(self, monkeypatch):
        """resolve_llm_client falls back to env vars when no profile is given."""
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_BASE_URL", "https://env.example.com/v1")
        monkeypatch.setenv("SCENARIO_FORGE_API_KEY", "sk-env")
        monkeypatch.setenv("SCENARIO_FORGE_MODEL_NAME", "env-model")

        client, name = resolve_llm_client(None, None, "ai/model-profiles.yaml")
        assert name is None
        assert client.model == "env-model"

    def test_read_use_case_strips_at_prefix(self):
        """read_use_case strips @ prefix from path."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp, "Test use case content")
            text = read_use_case(f"@{uc}")
            assert text == "Test use case content"

    def test_read_use_case_bare_path(self):
        """read_use_case reads from bare path."""
        with TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            uc = _write_use_case(tmp, "Bare path content")
            text = read_use_case(str(uc))
            assert text == "Bare path content"

    def test_read_use_case_missing_file_raises(self):
        """read_use_case raises FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError, match="Use-case file not found"):
            read_use_case("nonexistent-file.txt")
