"""End-to-end QA suite for the Stage 1 split-and-reorder feature.

This QA suite verifies the combined Stage 1 restructure (beads tgs3 + 82t5)
through the user interface: the `scenario-forge stpa-run` CLI subcommand.
It inspects output artifacts on disk (YAML files, JSONL call logs, run
manifest) and source prompt templates — never internal Python APIs.

Two execution modes:

1. **Static checks** (no LLM needed): inspect prompt templates on disk
   and Pydantic model field declarations. These run immediately and
   verify the structural changes (template replacement, model cleanup).

2. **Pipeline checks** (require an LLM endpoint): run the full
   `scenario-forge stpa-run` pipeline and inspect output artifacts.
   These require SCENARIO_FORGE_MODEL_BASE_URL and SCENARIO_FORGE_API_KEY
   environment variables (or equivalent).

Usage::

    # Static checks only (fast, no LLM)
    uv run python acceptance/qa/stage1-split-reorder/qa_suite.py --static

    # Full pipeline checks (requires LLM endpoint)
    uv run python acceptance/qa/stage1-split-reorder/qa_suite.py \\
        --use-case <path> --risk-extraction <path> \\
        [--capability-profile <path>]

    # All checks (static + pipeline)
    uv run python acceptance/qa/stage1-split-reorder/qa_suite.py \\
        --all --use-case <path> --risk-extraction <path>

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROMPTS_DIR = (
    next(
        p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
    )
    / "src"
    / "scenario_forge"
    / "stpa"
    / "system_model"
    / "prompts"
)

VALID_KC_SUBCODES = frozenset(
    {
        "KC1.1",
        "KC1.2",
        "KC1.3",
        "KC1.4",
        "KC2.1",
        "KC2.2",
        "KC2.3",
        "KC3.1",
        "KC3.2",
        "KC3.3",
        "KC3.4",
        "KC4.1",
        "KC4.2",
        "KC4.3",
        "KC4.4",
        "KC4.5",
        "KC4.6",
        "KC5.1",
        "KC5.2",
        "KC5.3",
        "KC6.1.1",
        "KC6.1.2",
        "KC6.2.1",
        "KC6.2.2",
        "KC6.3.1",
        "KC6.3.2",
        "KC6.3.3",
        "KC6.4",
        "KC6.5",
        "KC6.6",
        "KC6.7",
    }
)
KCX_PREFIX = "KCX-"

_KC4_PERSISTENT = frozenset({"KC4.3", "KC4.4", "KC4.5", "KC4.6"})
_KC_MULTI_AGENT = frozenset({"KC2.3", "KCX-MAGENT"})


# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------


class CheckResult:
    """Result of a single QA check."""

    def __init__(self, name: str, passed: bool, detail: str = ""):
        self.name = name
        self.passed = passed
        self.detail = detail

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        s = f"  [{status}] {self.name}"
        if self.detail:
            s += f"\n         {self.detail}"
        return s


class QARunner:
    """Collects and reports QA check results."""

    def __init__(self):
        self.results: list[CheckResult] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.results.append(CheckResult(name, condition, detail))

    def summary(self) -> int:
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        failed = total - passed
        print()
        print("=" * 60)
        print(f"QA SUMMARY: {passed}/{total} passed, {failed} failed")
        print("=" * 60)
        for r in self.results:
            print(r)
        if failed > 0:
            print(f"\n{failed} CHECK(S) FAILED")
            return 1
        print("\nALL CHECKS PASSED")
        return 0


# ---------------------------------------------------------------------------
# Static checks (no LLM required)
# ---------------------------------------------------------------------------


def run_static_checks(runner: QARunner) -> None:
    """Run checks that inspect prompt templates and model declarations on disk."""

    # --- stage1a-split: old templates removed ---
    runner.check(
        "stage1a-split: old stage1a_system.j2 is absent",
        not (PROMPTS_DIR / "stage1a_system.j2").exists(),
    )
    runner.check(
        "stage1a-split: old stage1a_user.j2 is absent",
        not (PROMPTS_DIR / "stage1a_user.j2").exists(),
    )

    # --- stage1a-split: new templates present ---
    for tmpl in (
        "stage1a_risk_system.j2",
        "stage1a_risk_user.j2",
        "stage1a_gap_system.j2",
        "stage1a_gap_user.j2",
    ):
        runner.check(
            f"stage1a-split: {tmpl} is present",
            (PROMPTS_DIR / tmpl).exists(),
        )

    # --- stage1b-revision: KC taxonomy in system prompt ---
    stage1b_system = PROMPTS_DIR / "stage1b_system.j2"
    if stage1b_system.exists():
        content = stage1b_system.read_text(encoding="utf-8")
        for marker in (
            "KC1 — Language Models",
            "KC6 — Operational Environment",
            "KCX — Extended Capabilities",
        ):
            runner.check(
                f"stage1b-revision: stage1b_system.j2 contains '{marker}'",
                marker in content,
            )
        # --- stage1b-revision: no STPA terminology ---
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not contain 'STPA'",
            "STPA" not in content,
        )
        # --- stage1b-revision: no zones_active in system prompt ---
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not request 'zones_active'",
            "zones_active" not in content,
        )
        # --- stage1b-revision: no entry-point category checklist ---
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not contain 'User input surfaces'",
            "User input surfaces" not in content,
        )
        runner.check(
            "stage1b-revision: stage1b_system.j2 does not contain 'Entry point category checklist'",
            "Entry point category checklist" not in content,
        )
    else:
        runner.check(
            "stage1b-revision: stage1b_system.j2 exists",
            False,
            "File not found",
        )

    # --- stage1b-revision: user prompt has no loss-analysis context ---
    stage1b_user = PROMPTS_DIR / "stage1b_user.j2"
    if stage1b_user.exists():
        content = stage1b_user.read_text(encoding="utf-8")
        for marker in ("loss_analysis", "all_losses", "security_constraints"):
            runner.check(
                f"stage1b-revision: stage1b_user.j2 does not contain '{marker}'",
                marker not in content,
            )
    else:
        runner.check(
            "stage1b-revision: stage1b_user.j2 exists",
            False,
            "File not found",
        )

    # --- stage1b-revision: Stage1Profile model has no boolean fields ---
    # We inspect the source file for field declarations rather than
    # importing the model, to stay at the "file on disk" level.
    profile_model_path = (
        next(
            p
            for p in Path(__file__).resolve().parents
            if (p / "pyproject.toml").is_file()
        )
        / "src"
        / "scenario_forge"
        / "models"
        / "capability_profile.py"
    )
    if profile_model_path.exists():
        src = profile_model_path.read_text(encoding="utf-8")
        # Extract the Stage1Profile class body
        match = re.search(
            r"class Stage1Profile\(BaseModel\):(.*?)(?=\nclass |\Z)",
            src,
            re.DOTALL,
        )
        if match:
            class_body = match.group(1)
            for field in ("has_persistent_memory", "multi_agent", "hitl"):
                # Look for field declarations like:
                #   has_persistent_memory: bool = Field(
                # but NOT in to_capability_profile (which uses exclude=...)
                # or in comments.
                decl_pattern = rf"^\s*{field}\s*:\s*bool\s*=\s*Field"
                found = bool(re.search(decl_pattern, class_body, re.MULTILINE))
                runner.check(
                    f"stage1b-revision: Stage1Profile does not declare '{field}'",
                    not found,
                    f"Found declaration: {field}" if found else "",
                )
        else:
            runner.check(
                "stage1b-revision: Stage1Profile class found in source",
                False,
                "Could not locate class definition",
            )
    else:
        runner.check(
            "stage1b-revision: capability_profile.py exists",
            False,
            "File not found",
        )


# ---------------------------------------------------------------------------
# Pipeline checks (require LLM endpoint)
# ---------------------------------------------------------------------------


def _run_stpa_pipeline(
    use_case: str,
    risk_extraction: Path,
    output_dir: Path,
    capability_profile: Path | None = None,
) -> subprocess.CompletedProcess:
    """Run `scenario-forge stpa-run` and return the completed process."""
    cmd = [
        "uv",
        "run",
        "scenario-forge",
        "stpa-run",
        "--use-case",
        use_case,
        "--risk-extraction",
        str(risk_extraction),
        "--output-dir",
        str(output_dir),
    ]
    if capability_profile is not None:
        cmd.extend(["--capability-profile", str(capability_profile)])
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file, returning None if missing."""
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_calls_jsonl(path: Path) -> list[dict]:
    """Load calls.jsonl, returning a list of entry dicts."""
    if not path.exists():
        return []
    entries = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _is_valid_kc_subcode(code: str) -> bool:
    """Check if a KC sub-code is valid (OWASP or KCX extension)."""
    if code.startswith(KCX_PREFIX):
        return True
    return code in VALID_KC_SUBCODES


def _check_id_sequence(ids: list[str], prefix: str) -> bool:
    """Check that IDs like L-1, L-2, ... are sequential with no duplicates."""
    if not ids:
        return True
    seen = set()
    expected = 1
    for id_str in ids:
        if id_str in seen:
            return False
        seen.add(id_str)
        # Parse the number after the prefix
        match = re.match(rf"^{prefix}(\d+)$", id_str)
        if not match:
            return False
        num = int(match.group(1))
        if num != expected:
            return False
        expected += 1
    return True


def run_pipeline_checks(
    runner: QARunner,
    use_case: str,
    risk_extraction: Path,
    capability_profile: Path | None = None,
) -> None:
    """Run the full pipeline and inspect output artifacts."""

    with tempfile.TemporaryDirectory(prefix="stage1-qa-") as tmpdir:
        output_dir = Path(tmpdir) / "output"

        proc = _run_stpa_pipeline(
            use_case,
            risk_extraction,
            output_dir,
            capability_profile,
        )

        runner.check(
            "pipeline: stpa-run exits with code 0",
            proc.returncode == 0,
            f"exit code {proc.returncode}, stderr: {proc.stderr[:500]}",
        )

        if proc.returncode != 0:
            runner.check(
                "pipeline: stpa-run produced output artifacts",
                False,
                "Pipeline did not complete — skipping remaining checks",
            )
            return

        # --- Load artifacts ---
        loss_analysis = _load_yaml(output_dir / "loss-analysis.yaml")
        cap_profile = _load_yaml(output_dir / "capability-profile.yaml")
        control_structure = _load_yaml(output_dir / "control-structure.yaml")
        run_manifest = _load_yaml(output_dir / "run-manifest.yaml")
        calls = _load_calls_jsonl(output_dir / "calls.jsonl")

        # --- stage1a-split: loss-analysis.yaml exists ---
        runner.check(
            "stage1a-split: loss-analysis.yaml exists",
            loss_analysis is not None,
        )

        # --- stage1a-split: risk_card_losses with provenance risk_card ---
        if loss_analysis:
            risk_losses = loss_analysis.get("risk_card_losses", [])
            uc_losses = loss_analysis.get("use_case_losses", [])

            has_risk_card_loss = any(
                loss.get("provenance") == "risk_card" for loss in risk_losses
            )
            runner.check(
                "stage1a-split: at least one loss with provenance risk_card",
                has_risk_card_loss or len(risk_losses) == 0,
                f"risk_card_losses count: {len(risk_losses)}",
            )

            all_risk_have_source = all(
                loss.get("source_risk_cards") for loss in risk_losses
            )
            runner.check(
                "stage1a-split: every risk_card loss has non-empty source_risk_cards",
                all_risk_have_source,
            )

            # --- stage1a-split: use_case_losses with provenance use_case ---
            has_use_case_loss = any(
                loss.get("provenance") in ("use_case", "critic_derived")
                for loss in uc_losses
            )
            runner.check(
                "stage1a-split: at least one loss with provenance use_case",
                has_use_case_loss or len(uc_losses) == 0,
                f"use_case_losses count: {len(uc_losses)}",
            )

            all_uc_empty_source = all(
                not loss.get("source_risk_cards") for loss in uc_losses
            )
            runner.check(
                "stage1a-split: every use_case loss has empty source_risk_cards",
                all_uc_empty_source,
            )

            # --- stage1a-split: ID sequence continuity ---
            all_losses = risk_losses + uc_losses
            loss_ids = [loss.get("loss_id", "") for loss in all_losses]
            hazard_ids = [
                h.get("hazard_id", "") for h in loss_analysis.get("hazards", [])
            ]
            sc_ids = [
                sc.get("constraint_id", "")
                for sc in loss_analysis.get("security_constraints", [])
            ]

            runner.check(
                "stage1a-split: loss IDs are sequential with no duplicates",
                _check_id_sequence(loss_ids, "L-"),
                f"IDs: {loss_ids}",
            )
            runner.check(
                "stage1a-split: hazard IDs are sequential with no duplicates",
                _check_id_sequence(hazard_ids, "H-"),
                f"IDs: {hazard_ids}",
            )
            runner.check(
                "stage1a-split: security constraint IDs are sequential with no duplicates",
                _check_id_sequence(sc_ids, "SC-"),
                f"IDs: {sc_ids}",
            )

            # --- stage1a-split: cross-references valid ---
            loss_id_set = set(loss_ids)
            hazard_refs_valid = all(
                all(r in loss_id_set for r in h.get("related_losses", []))
                for h in loss_analysis.get("hazards", [])
            )
            runner.check(
                "stage1a-split: every hazard references valid loss_id(s)",
                hazard_refs_valid,
            )

            hazard_id_set = set(hazard_ids)
            sc_refs_valid = all(
                all(r in hazard_id_set for r in sc.get("related_hazards", []))
                for sc in loss_analysis.get("security_constraints", [])
            )
            runner.check(
                "stage1a-split: every security constraint references valid hazard_id(s)",
                sc_refs_valid,
            )

        # --- stage1a-split: two call-log entries for stage_1a ---
        risk_calls = [
            c
            for c in calls
            if c.get("stage") == "stage_1a" and c.get("step") == "risk_derivation"
        ]
        gap_calls = [
            c
            for c in calls
            if c.get("stage") == "stage_1a" and c.get("step") == "gap_analysis"
        ]

        runner.check(
            "stage1a-split: calls.jsonl has stage_1a/risk_derivation entry",
            len(risk_calls) >= 1,
            f"found {len(risk_calls)} entries",
        )
        runner.check(
            "stage1a-split: calls.jsonl has stage_1a/gap_analysis entry",
            len(gap_calls) >= 1,
            f"found {len(gap_calls)} entries",
        )

        # --- stage1a-split: manifest call count ---
        if run_manifest:
            stage_1a_count = (
                run_manifest.get("stage_summary", {})
                .get("stage_1a", {})
                .get("call_count", 0)
            )
            runner.check(
                "stage1a-split: run-manifest stage_1a call_count is 2",
                stage_1a_count == 2,
                f"got {stage_1a_count}",
            )

        # --- stage1b-revision: capability-profile.yaml exists ---
        runner.check(
            "stage1b-revision: capability-profile.yaml exists",
            cap_profile is not None,
        )

        if cap_profile:
            # --- stage1b-revision: kc_subcodes present and valid ---
            kc_subcodes = cap_profile.get("kc_subcodes", [])
            runner.check(
                "stage1b-revision: kc_subcodes is non-empty",
                len(kc_subcodes) > 0,
                f"codes: {kc_subcodes}",
            )
            all_valid = all(_is_valid_kc_subcode(c) for c in kc_subcodes)
            runner.check(
                "stage1b-revision: all kc_subcodes are valid",
                all_valid,
            )

            # --- stage1b-revision: zones computed ---
            zones = cap_profile.get("zones_active", [])
            runner.check(
                "stage1b-revision: zones_active contains 'input' and 'reasoning'",
                "input" in zones and "reasoning" in zones,
                f"zones: {zones}",
            )

            # --- stage1b-revision: computed boolean flags ---
            kc_set = set(kc_subcodes)
            expected_persistent = bool(kc_set & _KC4_PERSISTENT) or "KCX-PMEM" in kc_set
            expected_multi_agent = bool(kc_set & _KC_MULTI_AGENT)
            expected_hitl = "KCX-HITL" in kc_set

            runner.check(
                "stage1b-revision: has_persistent_memory consistent with kc_subcodes",
                cap_profile.get("has_persistent_memory") == expected_persistent,
                f"got {cap_profile.get('has_persistent_memory')}, expected {expected_persistent}",
            )
            runner.check(
                "stage1b-revision: multi_agent consistent with kc_subcodes",
                cap_profile.get("multi_agent") == expected_multi_agent,
                f"got {cap_profile.get('multi_agent')}, expected {expected_multi_agent}",
            )
            runner.check(
                "stage1b-revision: hitl consistent with kc_subcodes",
                cap_profile.get("hitl") == expected_hitl,
                f"got {cap_profile.get('hitl')}, expected {expected_hitl}",
            )

            # --- stage1b-revision: entry points present ---
            entry_points = cap_profile.get("entry_points", [])
            runner.check(
                "stage1b-revision: entry_points is non-empty",
                len(entry_points) > 0,
            )
            all_ep_have_name_dir = all(
                ep.get("name") and ep.get("direction") for ep in entry_points
            )
            runner.check(
                "stage1b-revision: every entry point has name and direction",
                all_ep_have_name_dir,
            )

            # --- stage1b-revision: tool inventory when tool_execution active ---
            if "tool_execution" in zones:
                tool_inv = cap_profile.get("tool_inventory", [])
                runner.check(
                    "stage1b-revision: tool_inventory non-empty when tool_execution active",
                    len(tool_inv) > 0,
                    f"tool_inventory count: {len(tool_inv)}",
                )

        # --- stage1-ordering: 1b before 1a in call log ---
        stage_1b_calls = [c for c in calls if c.get("stage") == "stage_1b"]
        stage_1a_calls = [c for c in calls if c.get("stage") == "stage_1a"]

        if stage_1b_calls and stage_1a_calls:
            first_1b_idx = calls.index(stage_1b_calls[0])
            first_1a_idx = calls.index(stage_1a_calls[0])
            runner.check(
                "stage1-ordering: stage_1b call appears before first stage_1a call",
                first_1b_idx < first_1a_idx,
                f"1b at index {first_1b_idx}, 1a at index {first_1a_idx}",
            )
        else:
            skip_reason = []
            if not stage_1b_calls:
                skip_reason.append("no stage_1b calls")
            if not stage_1a_calls:
                skip_reason.append("no stage_1a calls")
            runner.check(
                "stage1-ordering: stage_1b call appears before first stage_1a call",
                False,
                f"Cannot verify ordering: {', '.join(skip_reason)}",
            )

        # --- stage1-ordering: risk_derivation before gap_analysis ---
        if risk_calls and gap_calls:
            risk_idx = calls.index(risk_calls[0])
            gap_idx = calls.index(gap_calls[0])
            runner.check(
                "stage1-ordering: risk_derivation appears before gap_analysis",
                risk_idx < gap_idx,
                f"risk at index {risk_idx}, gap at index {gap_idx}",
            )
        else:
            runner.check(
                "stage1-ordering: risk_derivation appears before gap_analysis",
                False,
                "Missing risk_derivation or gap_analysis call entries",
            )

        # --- stage1-ordering: all artifacts produced ---
        runner.check(
            "stage1-ordering: capability-profile.yaml produced",
            cap_profile is not None,
        )
        runner.check(
            "stage1-ordering: loss-analysis.yaml produced",
            loss_analysis is not None,
        )
        runner.check(
            "stage1-ordering: control-structure.yaml produced",
            control_structure is not None,
        )

        # --- stage1-ordering: gap analysis receives capability profile ---
        if gap_calls:
            gap_user_prompt = gap_calls[0].get("user_prompt_text", "")
            runner.check(
                "stage1-ordering: gap_analysis user_prompt_text contains 'kc_subcodes'",
                "kc_subcodes" in gap_user_prompt,
            )
        else:
            runner.check(
                "stage1-ordering: gap_analysis user_prompt_text contains 'kc_subcodes'",
                False,
                "No gap_analysis call entry found",
            )

        # --- stage1-ordering: 1b call does not receive loss analysis ---
        if stage_1b_calls:
            b_user_prompt = stage_1b_calls[0].get("user_prompt_text", "")
            runner.check(
                "stage1-ordering: stage_1b user_prompt_text does not contain 'loss_analysis'",
                "loss_analysis" not in b_user_prompt,
            )
            runner.check(
                "stage1-ordering: stage_1b user_prompt_text does not contain 'risk_card_losses'",
                "risk_card_losses" not in b_user_prompt,
            )
        else:
            runner.check(
                "stage1-ordering: stage_1b call does not receive loss analysis",
                False,
                "No stage_1b call entry found",
            )


def run_profile_skip_checks(
    runner: QARunner,
    use_case: str,
    risk_extraction: Path,
    capability_profile: Path,
) -> None:
    """Run the pipeline with --capability-profile and verify 1a still runs."""

    with tempfile.TemporaryDirectory(prefix="stage1-qa-skip-") as tmpdir:
        output_dir = Path(tmpdir) / "output"

        proc = _run_stpa_pipeline(
            use_case,
            risk_extraction,
            output_dir,
            capability_profile,
        )

        runner.check(
            "profile-skip: stpa-run with --capability-profile exits with code 0",
            proc.returncode == 0,
            f"exit code {proc.returncode}, stderr: {proc.stderr[:500]}",
        )

        if proc.returncode != 0:
            runner.check(
                "profile-skip: output artifacts produced",
                False,
                "Pipeline did not complete",
            )
            return

        calls = _load_calls_jsonl(output_dir / "calls.jsonl")

        risk_calls = [
            c
            for c in calls
            if c.get("stage") == "stage_1a" and c.get("step") == "risk_derivation"
        ]
        gap_calls = [
            c
            for c in calls
            if c.get("stage") == "stage_1a" and c.get("step") == "gap_analysis"
        ]
        b_calls = [c for c in calls if c.get("stage") == "stage_1b"]

        runner.check(
            "profile-skip: stage_1a/risk_derivation call present",
            len(risk_calls) >= 1,
        )
        runner.check(
            "profile-skip: stage_1a/gap_analysis call present",
            len(gap_calls) >= 1,
        )
        runner.check(
            "profile-skip: stage_1b call absent",
            len(b_calls) == 0,
            f"found {len(b_calls)} stage_1b calls",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end QA suite for Stage 1 split-and-reorder."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--static",
        action="store_true",
        help="Run static checks only (no LLM needed).",
    )
    mode.add_argument(
        "--pipeline",
        action="store_true",
        help="Run pipeline checks (requires LLM endpoint and input files).",
    )
    mode.add_argument(
        "--all",
        action="store_true",
        help="Run both static and pipeline checks.",
    )
    parser.add_argument(
        "--use-case",
        type=str,
        default=None,
        help="Path to use-case text file for pipeline checks.",
    )
    parser.add_argument(
        "--risk-extraction",
        type=Path,
        default=None,
        help="Path to risk extraction JSON file for pipeline checks.",
    )
    parser.add_argument(
        "--capability-profile",
        type=Path,
        default=None,
        help="Pre-built capability profile for the profile-skip scenario.",
    )
    args = parser.parse_args()

    runner = QARunner()

    do_static = args.static or args.all
    do_pipeline = args.pipeline or args.all

    if do_static:
        print("=== Static checks (no LLM required) ===")
        run_static_checks(runner)

    if do_pipeline:
        if not args.use_case or not args.risk_extraction:
            print(
                "ERROR: --use-case and --risk-extraction required for pipeline checks"
            )
            return 1
        print("\n=== Pipeline checks (requires LLM endpoint) ===")
        run_pipeline_checks(
            runner,
            args.use_case,
            args.risk_extraction,
            args.capability_profile,
        )

    if do_pipeline and args.capability_profile:
        print("\n=== Profile-skip checks ===")
        run_profile_skip_checks(
            runner,
            args.use_case,
            args.risk_extraction,
            args.capability_profile,
        )

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
