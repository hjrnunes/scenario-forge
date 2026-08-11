"""End-to-end QA suite for the acceptance staleness refresh (beads er9q + in8d).

This QA suite verifies that the acceptance specification corpus is consistent
with the shipped Stage 1 and Stage 2 implementations. It operates entirely at
the user interface — the filesystem artifacts a user or QA agent can inspect
(feature files, parser IR, generated entry points, prompt templates) and the
`scenario-forge stpa-run` CLI. It never imports the project's Python API.

The refresh has three observable outcomes:

1. **No stale symbol survives.** No feature file, no parser IR, and no prompt
   template still names a symbol, template, or call-log step that the Stage 1
   split-reorder or the Stage 2 restructure deleted.
2. **Every replacement is present.** The renamed templates, renamed call-log
   steps, and new internal models are all named by at least one feature.
3. **Every feature has current generated artifacts.** Each feature file has a
   parser IR, each IR has a generated entry point, and no IR contains text
   that its feature file no longer contains (the staleness that caused the
   original 25 failures).

Two execution modes:

1. **Static checks** (no LLM needed): inspect feature files, IR, generated
   entry points, and prompt templates on disk.
2. **Pipeline checks** (require an LLM endpoint): run the full
   `scenario-forge stpa-run` pipeline and confirm the refreshed call-log step
   names and manifest call counts are what the features assert. These require
   SCENARIO_FORGE_MODEL_BASE_URL and SCENARIO_FORGE_API_KEY (or equivalent).

Usage::

    # Static checks only (fast, no LLM)
    uv run python tmp/acceptance/qa/acceptance-refresh/qa_suite.py --static

    # Full pipeline checks (requires LLM endpoint)
    uv run python tmp/acceptance/qa/acceptance-refresh/qa_suite.py \\
        --pipeline --use-case <path> --risk-extraction <path>

    # All checks
    uv run python tmp/acceptance/qa/acceptance-refresh/qa_suite.py \\
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
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[4]

PROMPTS_DIR = (
    _PROJECT_ROOT / "src" / "scenario_forge" / "stpa" / "system_model" / "prompts"
)
LEGACY_FEATURES_DIR = _PROJECT_ROOT / "tests" / "stpa" / "features"
REFRESH_FEATURES_DIR = (
    _PROJECT_ROOT / "tmp" / "acceptance" / "features" / "acceptance-refresh"
)
IR_DIR = _PROJECT_ROOT / "tmp" / "acceptance" / "ir"
GENERATED_DIR = _PROJECT_ROOT / "tmp" / "acceptance" / "generated"


# ---------------------------------------------------------------------------
# Stale / replacement vocabulary
#
# A stale symbol is one that the Stage 1 split-reorder (beads tgs3+82t5) or the
# Stage 2 restructure (bead w5tp) deleted. Any acceptance artifact that still
# names one is asserting behavior the system no longer has.
# ---------------------------------------------------------------------------

# Templates deleted by the two restructures.
STALE_TEMPLATES = [
    "stage1a_system.j2",
    "stage1a_user.j2",
    "stage2_call2_system.j2",
    "stage2_call2_user.j2",
]

# Templates that replaced them.
REPLACEMENT_TEMPLATES = [
    "stage1a_risk_system.j2",
    "stage1a_risk_user.j2",
    "stage1a_gap_system.j2",
    "stage1a_gap_user.j2",
    "stage2_call2a_system.j2",
    "stage2_call2a_user.j2",
    "stage2_call2b_system.j2",
    "stage2_call2b_user.j2",
]

# Templates untouched by either restructure — present before and after.
STABLE_TEMPLATES = [
    "stage1b_system.j2",
    "stage1b_user.j2",
    "stage2_call1_system.j2",
    "stage2_call1_user.j2",
    "stage2_call3_system.j2",
    "stage2_call3_user.j2",
    "critic_system.j2",
    "critic_user.j2",
    "revision_system.j2",
    "revision_user.j2",
]

# Removed classes and functions.
STALE_SYMBOLS = [
    "ConnectionSet",
    "connection_assignments",
    "merge_connection_set",
    "_merge_with_fallback",
]

# Classes and functions that replaced them.
REPLACEMENT_SYMBOLS = [
    "CoordinationAnalysis",
    "ControlElementSet",
    "coordination_links",
    "integrity_findings",
]

# Call-log step names deleted by the restructures.
STALE_STEPS = [
    "loss_analysis",
    "call_2_responsibilities",
    "call_3_connections",
]

# Call-log step names that replaced them.
REPLACEMENT_STEPS = [
    "risk_derivation",
    "gap_analysis",
    "capability_profile",
    "call_1_requirements",
    "call_2a_responsibilities",
    "call_2b_control_elements",
    "call_3_coordination",
]

# Stage 2 fallback steps that replaced the single merge_connection_set step.
FALLBACK_STEPS = [
    "assemble_control_structure",
    "add_coordination_links",
]

# Prompt content deleted by the Stage 1b rewrite. The five-category
# entry-point checklist and the security-constraint caveat are gone; entry
# points are now derived from the KC taxonomy.
STALE_PROMPT_CONTENT = [
    "User input surfaces",
    "RAG/retrieval data sources",
    "Tool execution results",
    "External data feeds",
    "Admin/config interfaces",
    "Security constraints describe what SHOULD exist",
    "Do not infer tools from security constraints",
    "## Schneider zones",
    "## Emphasis",
]

# Features retired by this refresh because their mechanism was deleted.
RETIRED_FEATURES = [
    "sp1_entry_point_checklist",
    "sp1_security_constraints_contamination",
    "sp1_connection_set_merge",
    "sp1_merge_fallback_degradation",
]

# Features added by this refresh to replace them.
REPLACEMENT_FEATURES = [
    "stage1b-entry-point-guidance",
    "stage1b-grounding",
    "stage2-coordination-analysis",
    "stage2-assembly-fallback",
]

EXPECTED_STAGE2_CALL_COUNT = 4
EXPECTED_STAGE1A_CALL_COUNT = 2


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

    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.results.append(CheckResult(name, bool(condition), detail))

    def summary(self) -> int:
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        failed = total - passed
        print()
        print("=" * 68)
        print(f"QA SUMMARY: {passed}/{total} passed, {failed} failed")
        print("=" * 68)
        for r in self.results:
            print(r)
        if failed > 0:
            print(f"\n{failed} CHECK(S) FAILED")
            return 1
        print("\nALL CHECKS PASSED")
        return 0


# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------

def _strip_manifest_comments(text: str) -> str:
    """Drop leading '#' comment lines from a feature file.

    Mutation stamps and mutation manifests are stored as '#' comments and
    embed historical feature text, including symbol names that the feature
    body no longer asserts. Scanning them would report false staleness.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


FEATURE_ROOTS = [
    LEGACY_FEATURES_DIR,
    _PROJECT_ROOT / "tmp" / "acceptance" / "features",
]

# Negation markers that make an assertion a *negative* one. A retired symbol
# named inside a negative assertion is correct — that assertion is what keeps
# the symbol from coming back.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|absent|retired|removed|omits|excludes)\b",
    re.IGNORECASE,
)


def _feature_files() -> list[Path]:
    """All feature files in the acceptance corpus, across every feature root."""
    files: list[Path] = []
    for root in FEATURE_ROOTS:
        if root.is_dir():
            files += sorted(root.rglob("*.feature"))
    return sorted(set(files))


def _feature_bodies() -> dict[Path, str]:
    """Feature file bodies with mutation-manifest comments stripped."""
    return {p: _strip_manifest_comments(p.read_text(encoding="utf-8")) for p in _feature_files()}


def _ir_files() -> list[Path]:
    """Executable parser IR files.

    Excludes '*_dry.json', which are DRY-checker reports rather than IR the
    acceptance runtime executes.
    """
    return sorted(p for p in IR_DIR.rglob("*.json") if not p.stem.endswith("_dry"))


def _ir_assertions(ir: dict) -> list[tuple[str, bool]]:
    """Flatten an IR to (text, is_negative) pairs.

    Each step contributes its own text, and each example value is paired with
    the polarity of the step that consumes it. A retired symbol supplied as an
    example value to 'the prompts directory does not contain <x>' is therefore
    correctly recognized as a negative assertion rather than staleness.
    """
    pairs: list[tuple[str, bool]] = []
    for section in ("background", "scenarios"):
        node = ir.get(section)
        if node is None:
            continue
        scenarios = node if isinstance(node, list) else [node]
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            name = str(scenario.get("name", ""))
            steps = [str(s.get("text", "")) for s in scenario.get("steps", []) or []]
            pairs.append((name, bool(_NEGATION_RE.search(name))))
            for step in steps:
                pairs.append((step, bool(_NEGATION_RE.search(step))))
            # An example value is only as affirmative as the steps that
            # actually consume its placeholder. Judging it against every step
            # in the scenario would mis-read a value used solely by a negative
            # assertion whenever some unrelated step is affirmative.
            for example in scenario.get("examples", []) or []:
                if not isinstance(example, dict):
                    continue
                for key, value in example.items():
                    consumers = [s for s in steps if f"<{key}>" in s]
                    negative = bool(consumers) and all(
                        _NEGATION_RE.search(s) for s in consumers
                    )
                    pairs.append((str(value), negative))
    return pairs


def _scenario_blocks(body: str) -> list[str]:
    """Split a feature body into per-scenario blocks.

    Example-table rows carry no negation word of their own, so they must be
    judged against the scenario that contains them. The Feature narrative is
    excluded: it is documentation, and it legitimately names retired symbols
    when explaining what replaced them.
    """
    parts = re.split(r"\n(?=\s*(?:Scenario|Scenario Outline|Background)\b)", body)
    return [p for p in parts[1:] if p.strip()]


def _whole_word(needle: str, haystack: str) -> bool:
    """Match *needle* only at identifier boundaries.

    Prevents 'loss_analysis' from matching inside 'derive_loss_analysis' and
    prevents 'call_2_responsibilities' from matching 'call_2a_responsibilities'.
    """
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])", haystack) is not None


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------

def check_templates_on_disk(runner: QARunner) -> None:
    """Prompt templates: stale ones deleted, replacements and stable ones present."""
    for tmpl in STALE_TEMPLATES:
        runner.check(
            f"template: retired {tmpl} is absent from the prompts directory",
            not (PROMPTS_DIR / tmpl).exists(),
        )
    for tmpl in REPLACEMENT_TEMPLATES + STABLE_TEMPLATES:
        runner.check(
            f"template: {tmpl} is present in the prompts directory",
            (PROMPTS_DIR / tmpl).exists(),
        )


def check_prompt_content(runner: QARunner) -> None:
    """Prompt content deleted by the Stage 1b rewrite has not returned."""
    all_prompts = {
        p.name: p.read_text(encoding="utf-8") for p in sorted(PROMPTS_DIR.glob("*.j2"))
    }
    for fragment in STALE_PROMPT_CONTENT:
        offenders = [name for name, body in all_prompts.items() if fragment in body]
        runner.check(
            f"prompt content: retired text {fragment!r} is absent from every template",
            not offenders,
            f"present in: {offenders}" if offenders else "",
        )

    # The KC-driven entry-point guidance that replaced the checklist.
    stage1b = all_prompts.get("stage1b_system.j2", "")
    for fragment in (
        "## Entry Points",
        "KC6.3.3 (RAG) implies an indirect entry point",
        "A component can appear in both tool_inventory and entry_points",
        "Do not invent tools based on what a system like this might have",
    ):
        runner.check(
            f"prompt content: stage1b_system.j2 states {fragment!r}",
            fragment in stage1b,
        )

    # Stage 1b no longer receives any loss-analysis context, which is what
    # made security-constraint contamination possible in the first place.
    stage1b_user = all_prompts.get("stage1b_user.j2", "")
    for fragment in ("Security Constraints", "Loss Analysis", "loss_analysis", "all_losses"):
        runner.check(
            f"prompt content: stage1b_user.j2 carries no {fragment!r} context",
            fragment not in stage1b_user,
        )


def check_features_free_of_stale_symbols(runner: QARunner) -> None:
    """No feature file asserts a deleted template, symbol, or step name."""
    bodies = _feature_bodies()
    runner.check(
        "corpus: feature files were discovered",
        len(bodies) > 0,
        f"searched {LEGACY_FEATURES_DIR} and {REFRESH_FEATURES_DIR}",
    )

    # A retired symbol is allowed inside a negative assertion — that is the
    # assertion that keeps it from coming back. Only affirmative uses are
    # staleness, and polarity is a property of the whole scenario block
    # because example rows carry no negation word of their own.
    stale_needles = STALE_TEMPLATES + STALE_SYMBOLS + [
        "call_2_responsibilities",
        "call_3_connections",
    ]
    for needle in stale_needles:
        offenders = []
        for path, body in bodies.items():
            for block in _scenario_blocks(body):
                if not _whole_word(needle, block):
                    continue
                if _NEGATION_RE.search(block):
                    continue
                first = block.strip().splitlines()[0][:60]
                offenders.append(f"{path.name} :: {first}")
        runner.check(
            f"features: retired symbol {needle!r} is only ever asserted absent",
            not offenders,
            "; ".join(offenders[:4]) if offenders else "",
        )


def check_features_name_replacements(runner: QARunner) -> None:
    """Every replacement template, symbol, and step is asserted somewhere."""
    corpus = "\n".join(_feature_bodies().values())
    for needle in REPLACEMENT_TEMPLATES + REPLACEMENT_SYMBOLS + REPLACEMENT_STEPS + FALLBACK_STEPS:
        runner.check(
            f"features: some feature asserts replacement {needle!r}",
            _whole_word(needle, corpus),
        )


def check_retired_and_replacement_features(runner: QARunner) -> None:
    """Retired features are gone; replacement features exist with IR."""
    for name in RETIRED_FEATURES:
        runner.check(
            f"retirement: feature {name}.feature is removed",
            not (LEGACY_FEATURES_DIR / f"{name}.feature").exists(),
        )
        runner.check(
            f"retirement: IR {name}.json is removed",
            not (IR_DIR / f"{name}.json").exists(),
        )
        runner.check(
            f"retirement: entry point {name}_acceptance_test.py is removed",
            not (GENERATED_DIR / f"{name}_acceptance_test.py").exists(),
        )

    for name in REPLACEMENT_FEATURES:
        runner.check(
            f"replacement: feature {name}.feature exists",
            (REFRESH_FEATURES_DIR / f"{name}.feature").exists(),
        )
        ir_candidates = list(IR_DIR.rglob(f"{name}.json"))
        runner.check(
            f"replacement: IR for {name} exists",
            bool(ir_candidates),
        )
        entry_candidates = list(GENERATED_DIR.glob(f"*{name.replace('-', '_')}*_acceptance_test.py"))
        entry_candidates += list(GENERATED_DIR.glob(f"*{name}*_acceptance_test.py"))
        runner.check(
            f"replacement: generated entry point for {name} exists",
            bool(entry_candidates),
        )


def check_ir_free_of_stale_symbols(runner: QARunner) -> None:
    """No parser IR carries a deleted template, symbol, or step name.

    This is the specific defect that produced most of the original failures:
    a feature file was updated in place but its IR was never regenerated, so
    the executed IR still asserted the pre-restructure behavior.
    """
    ir_files = _ir_files()
    runner.check(
        "corpus: parser IR files were discovered",
        len(ir_files) > 0,
        f"searched {IR_DIR}",
    )

    parsed: list[tuple[Path, list[tuple[str, bool]]]] = []
    for path in ir_files:
        try:
            parsed.append((path, _ir_assertions(json.loads(path.read_text(encoding="utf-8")))))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

    needles = STALE_TEMPLATES + STALE_SYMBOLS + [
        "call_2_responsibilities",
        "call_3_connections",
    ]
    for needle in needles:
        offenders = []
        for path, pairs in parsed:
            for text, negative in pairs:
                if negative or not _whole_word(needle, text):
                    continue
                offenders.append(f"{path.name} :: {text[:60]}")
                break
        runner.check(
            f"IR: retired symbol {needle!r} is only ever asserted absent",
            not offenders,
            "; ".join(offenders[:4]) if offenders else "",
        )


def check_ir_matches_features(runner: QARunner) -> None:
    """Each IR's scenario names are present in a feature file of the same name.

    Catches the IR-behind-feature drift directly: if a scenario name appears
    in the IR but in no feature file, the IR was generated from an older
    revision of that feature.
    """
    feature_corpus = "\n".join(_feature_bodies().values())
    for path in _ir_files():
        try:
            ir = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        missing = [
            s.get("name", "")
            for s in ir.get("scenarios", []) or []
            if s.get("name") and s["name"] not in feature_corpus
        ]
        runner.check(
            f"IR: every scenario in {path.name} is present in a feature file",
            not missing,
            f"orphan scenarios: {missing[:3]}" if missing else "",
        )


def check_entry_points_resolve(runner: QARunner) -> None:
    """Every generated entry point points at an IR file that exists."""
    entry_points = sorted(GENERATED_DIR.glob("*_acceptance_test.py"))
    runner.check(
        "corpus: generated entry points were discovered",
        len(entry_points) > 0,
        f"searched {GENERATED_DIR}",
    )
    for path in entry_points:
        body = path.read_text(encoding="utf-8")
        refs = re.findall(r'Path\(r"([^"]+\.json)"\)', body)
        missing = [r for r in refs if not Path(r).exists()]
        runner.check(
            f"entry point: {path.name} references an existing IR file",
            bool(refs) and not missing,
            f"missing IR: {missing}" if missing else ("no IR reference found" if not refs else ""),
        )


def check_entry_points_cover_ir(runner: QARunner) -> None:
    """Every IR file is executed by exactly one generated entry point."""
    referenced: dict[str, int] = {}
    for path in GENERATED_DIR.glob("*_acceptance_test.py"):
        body = path.read_text(encoding="utf-8")
        for ref in set(re.findall(r'Path\(r"([^"]+\.json)"\)', body)):
            referenced[Path(ref).resolve().as_posix()] = referenced.get(
                Path(ref).resolve().as_posix(), 0
            ) + 1

    for ir_path in _ir_files():
        key = ir_path.resolve().as_posix()
        runner.check(
            f"coverage: IR {ir_path.name} is executed by a generated entry point",
            referenced.get(key, 0) >= 1,
        )


def run_static_checks(runner: QARunner) -> None:
    """Run every check that needs only the filesystem."""
    check_templates_on_disk(runner)
    check_prompt_content(runner)
    check_features_free_of_stale_symbols(runner)
    check_features_name_replacements(runner)
    check_retired_and_replacement_features(runner)
    check_ir_free_of_stale_symbols(runner)
    check_ir_matches_features(runner)
    check_entry_points_resolve(runner)
    check_entry_points_cover_ir(runner)


# ---------------------------------------------------------------------------
# Pipeline checks
# ---------------------------------------------------------------------------

def run_pipeline_checks(
    runner: QARunner,
    use_case: str,
    risk_extraction: Path,
    capability_profile: Path | None,
) -> None:
    """Run `scenario-forge stpa-run` and verify the refreshed call-log vocabulary."""
    with tempfile.TemporaryDirectory(prefix="qa_acceptance_refresh_") as tmpdir:
        out_dir = Path(tmpdir) / "run"
        cmd = [
            "uv", "run", "scenario-forge", "stpa-run",
            "--use-case", str(use_case),
            "--risk-extraction", str(risk_extraction),
            "--output-dir", str(out_dir),
        ]
        if capability_profile is not None:
            cmd += ["--profile", str(capability_profile)]

        proc = subprocess.run(
            cmd, cwd=_PROJECT_ROOT, capture_output=True, text=True, timeout=3600,
        )
        runner.check(
            "pipeline: stpa-run exits with code 0",
            proc.returncode == 0,
            (proc.stderr or proc.stdout)[-600:] if proc.returncode != 0 else "",
        )

        calls_path = out_dir / "calls.jsonl"
        if not calls_path.exists():
            runner.check("pipeline: calls.jsonl exists", False, f"not found at {calls_path}")
            return
        runner.check("pipeline: calls.jsonl exists", True)

        entries = [
            json.loads(line)
            for line in calls_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        logged = {(e.get("stage"), e.get("step")) for e in entries}
        logged_steps = {step for _stage, step in logged}

        # Replacement steps present.
        for step in REPLACEMENT_STEPS:
            runner.check(
                f"pipeline: call log contains step {step!r}",
                step in logged_steps,
                f"logged steps: {sorted(logged_steps)}" if step not in logged_steps else "",
            )

        # Retired steps absent.
        for step in STALE_STEPS + ["merge_connection_set"]:
            runner.check(
                f"pipeline: call log does not contain retired step {step!r}",
                step not in logged_steps,
            )

        # Stage 2 call ordering, as stage2-assembly.feature asserts.
        order = [e.get("step") for e in entries if e.get("stage") == "stage_2"]
        expected_order = [
            "call_1_requirements",
            "call_2a_responsibilities",
            "call_2b_control_elements",
            "call_3_coordination",
        ]
        positions = [order.index(s) for s in expected_order if s in order]
        runner.check(
            "pipeline: Stage 2 calls are logged in order 1, 2a, 2b, 3",
            len(positions) == len(expected_order) and positions == sorted(positions),
            f"stage_2 order: {order}",
        )

        # Manifest call counts.
        manifest_path = out_dir / "run-manifest.yaml"
        if manifest_path.exists():
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
            stage_summary = manifest.get("stage_summary", {}) or {}
            runner.check(
                f"pipeline: manifest records {EXPECTED_STAGE2_CALL_COUNT} Stage 2 calls",
                (stage_summary.get("stage_2", {}) or {}).get("call_count")
                == EXPECTED_STAGE2_CALL_COUNT,
                f"stage_summary.stage_2: {stage_summary.get('stage_2')}",
            )
            runner.check(
                f"pipeline: manifest records {EXPECTED_STAGE1A_CALL_COUNT} Stage 1a calls",
                (stage_summary.get("stage_1a", {}) or {}).get("call_count")
                == EXPECTED_STAGE1A_CALL_COUNT,
                f"stage_summary.stage_1a: {stage_summary.get('stage_1a')}",
            )
        else:
            runner.check("pipeline: run-manifest.yaml exists", False)

        # Control structure carries the replacement coordination model.
        cs_path = out_dir / "control-structure.yaml"
        if cs_path.exists():
            cs = yaml.safe_load(cs_path.read_text(encoding="utf-8")) or {}
            runner.check(
                "pipeline: control-structure.yaml has a coordination_links list",
                isinstance(cs.get("coordination_links"), list),
            )
            runner.check(
                "pipeline: control-structure.yaml has no connection_assignments",
                "connection_assignments" not in cs,
            )
        else:
            runner.check("pipeline: control-structure.yaml exists", False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end QA suite for the acceptance staleness refresh.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--static", action="store_true",
        help="Run static checks only (no LLM needed).",
    )
    mode.add_argument(
        "--pipeline", action="store_true",
        help="Run pipeline checks (requires LLM endpoint and input files).",
    )
    mode.add_argument(
        "--all", action="store_true",
        help="Run both static and pipeline checks.",
    )
    parser.add_argument(
        "--use-case", type=str, default=None,
        help="Path to use-case text file for pipeline checks.",
    )
    parser.add_argument(
        "--risk-extraction", type=Path, default=None,
        help="Path to risk extraction JSON file for pipeline checks.",
    )
    parser.add_argument(
        "--capability-profile", type=Path, default=None,
        help="Pre-built capability profile YAML (optional).",
    )
    args = parser.parse_args()

    runner = QARunner()

    if args.static or args.all:
        print("=== Static checks (no LLM required) ===")
        run_static_checks(runner)

    if args.pipeline or args.all:
        if not args.use_case or not args.risk_extraction:
            print("ERROR: --use-case and --risk-extraction required for pipeline checks")
            return 1
        print("\n=== Pipeline checks (requires LLM endpoint) ===")
        run_pipeline_checks(
            runner, args.use_case, args.risk_extraction, args.capability_profile,
        )

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
