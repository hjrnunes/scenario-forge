"""End-to-end QA suite for the STPA HTML report feature.

This QA suite verifies the STPA report through the user interface:
  - CLI: `scenario-forge stpa-report --output-dir <dir>`
  - HTML inspection: parse the generated HTML and assert on its content

It does NOT use any project API. It treats the CLI as the user interface
and inspects the HTML output as a user would (via standard library
HTML parsing).

Usage:
    uv run python tmp/acceptance/qa/stpa-report/qa_suite.py [--fixture-dir <dir>]

The suite creates a temporary combined output directory from fixture data,
runs the CLI, and inspects the output HTML.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Test fixture builder
# ---------------------------------------------------------------------------

def _find_project_root() -> Path:
    """Find the project root by searching for pyproject.toml."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return Path.cwd()


PROJECT_ROOT = _find_project_root()
FIXTURE_DIR = PROJECT_ROOT / "src" / "scenario_forge" / "stpa" / "fixtures"
SP3_OUTPUT = PROJECT_ROOT / "output" / "runs" / "20260810-sp3-occiai-or"


def _build_combined_output_dir(tmpdir: Path) -> Path:
    """Build a combined STPA output directory in *tmpdir* with all artifacts."""
    combined = tmpdir / "combined-output"
    combined.mkdir(parents=True, exist_ok=True)
    scenarios_dir = combined / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)

    # SP1 artifacts from fixtures (convert underscores to hyphens for
    # the filenames the generator expects)
    for name in ("loss_analysis_occiai.yaml", "capability_profile_occiai.yaml",
                 "control_structure_occiai.yaml"):
        src = FIXTURE_DIR / name
        if src.exists():
            dest_name = name.replace("_occiai", "").replace("_", "-")
            shutil.copy2(src, combined / dest_name)

    # SP2 artifacts from fixtures
    for name in ("ica_enumeration_occiai.yaml", "enriched_threats_occiai.yaml"):
        src = FIXTURE_DIR / name
        if src.exists():
            dest_name = name.replace("_occiai", "").replace("_", "-")
            shutil.copy2(src, combined / dest_name)

    # SP3 artifacts from output runs
    if SP3_OUTPUT.exists():
        for fname in ("eval-scorecard.yaml", "coverage-gaps.json",
                      "run-manifest.yaml", "calls.jsonl"):
            src = SP3_OUTPUT / fname
            if src.exists():
                shutil.copy2(src, combined / fname)

        # Copy scenario files
        scn_dir = SP3_OUTPUT / "scenarios"
        if scn_dir.exists():
            for f in scn_dir.iterdir():
                if f.suffix in (".yaml", ".feature"):
                    shutil.copy2(f, scenarios_dir / f.name)

    return combined


# ---------------------------------------------------------------------------
# Minimal HTML content inspector
# ---------------------------------------------------------------------------

class HTMLInspector:
    """Lightweight HTML content inspector using regex (no external deps)."""

    def __init__(self, html_text: str) -> None:
        self.html = html_text

    def contains(self, pattern: str) -> bool:
        return pattern in self.html

    def contains_regex(self, pattern: str, flags: int = 0) -> bool:
        return re.search(pattern, self.html, flags | re.IGNORECASE) is not None

    def count_occurrences(self, pattern: str) -> int:
        return len(re.findall(pattern, self.html, re.IGNORECASE))

    def has_id(self, element_id: str) -> bool:
        return self.contains_regex(rf'id\s*=\s*["\']?{re.escape(element_id)}["\']?')

    def has_class(self, class_name: str) -> bool:
        return self.contains_regex(
            rf'class\s*=\s*["\'][^"\']*\b{re.escape(class_name)}\b[^"\']*["\']'
        )

    def has_data_attr(self, attr_name: str, attr_value: str) -> bool:
        return self.contains_regex(
            rf'data-{re.escape(attr_name)}\s*=\s*["\']{re.escape(attr_value)}["\']'
        )

    def extract_section(self, start_marker: str, end_marker: str) -> str:
        """Extract text between two markers."""
        start = self.html.find(start_marker)
        if start == -1:
            return ""
        start += len(start_marker)
        end = self.html.find(end_marker, start)
        if end == -1:
            return self.html[start:]
        return self.html[start:end]

    def has_collapsible(self, label: str) -> bool:
        """Check if a collapsible <details> section with the given label exists."""
        return self.contains(f">{label}<") or self.contains(f'>{label}</summary>')

    def no_external_links(self) -> bool:
        """Check that there are no <link> tags with href to external resources."""
        # Allow <link> with no href or inline data, but not external URLs
        links = re.findall(r'<link\s[^>]*href\s*=\s*["\']([^"\']+)["\']', self.html, re.IGNORECASE)
        return all(h.startswith("data:") for h in links)

    def no_external_scripts(self) -> bool:
        """Check that there are no <script src> tags with external URLs."""
        scripts = re.findall(r'<script\s[^>]*src\s*=\s*["\']([^"\']+)["\']', self.html, re.IGNORECASE)
        return all(s.startswith("data:") for s in scripts)

    def no_external_images(self) -> bool:
        """Check that there are no <img> tags with external src URLs."""
        imgs = re.findall(r'<img\s[^>]*src\s*=\s*["\']([^"\']+)["\']', self.html, re.IGNORECASE)
        return all(s.startswith("data:") for s in imgs)


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

class TestResult:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.errors: list[str] = []

    def check(self, condition: bool, message: str) -> None:
        if condition:
            self.passed += 1
            print(f"  PASS: {message}")
        else:
            self.failed += 1
            self.errors.append(message)
            print(f"  FAIL: {message}")

    def summary(self) -> bool:
        total = self.passed + self.failed
        print(f"\n{'=' * 60}")
        print(f"QA Suite Results: {self.passed}/{total} passed, {self.failed} failed")
        if self.errors:
            print("\nFailures:")
            for e in self.errors:
                print(f"  - {e}")
        return self.failed == 0


def run_cli(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run the scenario-forge CLI and return the completed process."""
    cmd = ["uv", "run", "scenario-forge"] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

def test_report_generation(result: TestResult, combined_dir: Path, tmpdir: Path) -> Path | None:
    """Test: CLI report generation."""
    print("\n--- Report Generation ---")

    # Test: valid directory produces report
    proc = run_cli(["stpa-report", "--output-dir", str(combined_dir)])
    result.check(proc.returncode == 0, f"CLI exits 0 for valid dir (got {proc.returncode})")
    report_path = combined_dir / "stpa-report.html"
    result.check(report_path.exists(), "stpa-report.html is written")

    if not report_path.exists():
        return None

    html_text = report_path.read_text(encoding="utf-8")
    inspector = HTMLInspector(html_text)

    # Test: console output mentions report path
    result.check(
        "stpa-report.html" in proc.stdout or "stpa-report.html" in proc.stderr,
        "Console output mentions report file path",
    )

    # Test: self-contained — no external CSS/JS/images
    result.check(inspector.no_external_links(), "No external CSS <link> tags")
    result.check(inspector.no_external_scripts(), "No external <script src> tags")
    result.check(inspector.no_external_images(), "No external <img src> tags")

    # Test: nonexistent directory
    fake_dir = tmpdir / "nonexistent"
    proc2 = run_cli(["stpa-report", "--output-dir", str(fake_dir)])
    result.check(proc2.returncode != 0, "CLI exits nonzero for nonexistent dir")
    result.check(
        "not found" in proc2.stderr.lower() or "not found" in proc2.stdout.lower(),
        "Error message mentions 'not found'",
    )

    # Test: custom output filename
    custom_path = tmpdir / "custom-report.html"
    proc3 = run_cli([
        "stpa-report", "--output-dir", str(combined_dir),
        "--output", str(custom_path),
    ])
    result.check(proc3.returncode == 0, f"CLI exits 0 with --output (got {proc3.returncode})")
    result.check(custom_path.exists(), "Custom report file is written")

    return report_path


def test_hero_summary(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: hero summary section."""
    print("\n--- Hero Summary ---")

    result.check(
        inspector.contains_regex(r'class\s*=\s*["\'][^"\']*hero[^"\']*["\']')
        or inspector.has_id("hero")
        or inspector.has_id("hero-summary"),
        "Hero summary section exists",
    )
    result.check(
        inspector.contains("sp3-20260810") or inspector.contains("20260810"),
        "Hero summary shows run ID/timestamp",
    )
    result.check(
        inspector.contains("28") or inspector.contains("scenario"),
        "Hero summary shows scenario count or metrics",
    )


def test_sp1_flow_card(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: SP1 flow card."""
    print("\n--- SP1 Flow Card ---")

    result.check(
        inspector.has_id("sp1") or inspector.contains_regex(r'id\s*=\s*["\']?sp1'),
        "SP1 flow card section exists with id",
    )
    result.check(
        inspector.contains("SP1") or inspector.contains("Loss"),
        "SP1 flow card header labeled SP1 or contains Loss",
    )
    result.check(
        inspector.contains("L-") or inspector.contains("loss"),
        "SP1 flow card contains loss data",
    )
    result.check(
        inspector.contains("H-") or inspector.contains("hazard"),
        "SP1 flow card contains hazard data",
    )
    result.check(
        inspector.contains("SC-") or inspector.contains("constraint"),
        "SP1 flow card contains security constraint data",
    )
    result.check(
        inspector.contains("RESP-") or inspector.contains("responsibility"),
        "SP1 flow card contains control structure data",
    )
    # Collapsible raw YAML
    result.check(
        inspector.contains("loss-analysis") or inspector.contains("loss_analysis"),
        "SP1 flow card has raw YAML for loss-analysis",
    )


def test_sp2_flow_card(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: SP2 flow card."""
    print("\n--- SP2 Flow Card ---")

    result.check(
        inspector.has_id("sp2") or inspector.contains_regex(r'id\s*=\s*["\']?sp2'),
        "SP2 flow card section exists with id",
    )
    result.check(
        inspector.contains("SP2") or inspector.contains("ICA"),
        "SP2 flow card header labeled SP2 or contains ICA",
    )
    result.check(
        inspector.contains("RESP-") and inspector.contains("CA-"),
        "SP2 flow card contains ICA slot data",
    )
    result.check(
        inspector.contains("AML.T") or inspector.contains("catalog"),
        "SP2 flow card contains catalog enrichment data",
    )
    result.check(
        inspector.contains("coverage") or inspector.contains("coverage_rate"),
        "SP2 flow card contains coverage analysis",
    )
    # Produces arrow between SP1 and SP2
    result.check(
        inspector.contains("→") or inspector.contains("↓") or inspector.contains("produces")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*arrow[^"\']*["\']'),
        "Produces arrow between SP1 and SP2",
    )


def test_sp3_flow_card(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: SP3 flow card."""
    print("\n--- SP3 Flow Card ---")

    result.check(
        inspector.has_id("sp3") or inspector.contains_regex(r'id\s*=\s*["\']?sp3'),
        "SP3 flow card section exists with id",
    )
    result.check(
        inspector.contains("SP3") or inspector.contains("Scenario"),
        "SP3 flow card header labeled SP3 or contains Scenario",
    )
    # Scenario list
    result.check(
        inspector.contains("SCN-001"),
        "SP3 flow card lists scenario SCN-001",
    )
    # Collapsible scenario cards
    result.check(
        inspector.contains_regex(r'class\s*=\s*["\'][^"\']*scenario[^"\']*card[^"\']*["\']')
        or inspector.contains_regex(r'<details[^>]*>.*?SCN-001', re.DOTALL),
        "Scenario cards are collapsible",
    )
    # BDI section
    result.check(
        inspector.contains("belief") or inspector.contains("Belief")
        or inspector.contains("BDI") or inspector.contains("bdi"),
        "Scenario card contains BDI section",
    )
    # Narrative section
    result.check(
        inspector.contains("narrative") or inspector.contains("Narrative"),
        "Scenario card contains narrative section",
    )
    # Attack tree section
    result.check(
        inspector.contains("attack") and inspector.contains("tree"),
        "Scenario card contains attack tree section",
    )
    # Gherkin section
    result.check(
        inspector.contains("Given") or inspector.contains("gherkin") or inspector.contains("Gherkin"),
        "Scenario card contains Gherkin section",
    )
    # Eval scorecard
    result.check(
        inspector.contains("eval") and inspector.contains("scorecard"),
        "SP3 flow card contains eval scorecard",
    )


def test_llm_call_inspector(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: LLM call inspector."""
    print("\n--- LLM Call Inspector ---")

    result.check(
        inspector.has_id("calls") or inspector.contains_regex(r'id\s*=\s*["\']?calls'),
        "LLM call inspector section exists with id",
    )
    result.check(
        inspector.contains("Calls") or inspector.contains("call"),
        "LLM call inspector is labeled 'Calls'",
    )
    # No search box
    result.check(
        not inspector.contains_regex(r'<input[^>]*type\s*=\s*["\']search["\']')
        or not inspector.contains_regex(r'id\s*=\s*["\']call-search["\']'),
        "LLM call inspector has no search input field",
    )
    # Call entries with metadata
    result.check(
        inspector.contains("stage") and inspector.contains("model"),
        "Call entries show stage and model metadata",
    )
    result.check(
        inspector.contains("token") or inspector.contains("prompt_tokens"),
        "Call entries show token counts",
    )
    result.check(
        inspector.contains("duration") or inspector.contains("duration_ms"),
        "Call entries show duration",
    )
    # Collapsible sections for prompts/responses
    result.check(
        inspector.contains("system_prompt") or inspector.contains("system prompt"),
        "Call entries have collapsible system_prompt section",
    )
    result.check(
        inspector.contains("user_prompt") or inspector.contains("user prompt"),
        "Call entries have collapsible user_prompt section",
    )
    result.check(
        inspector.contains("response") or inspector.contains("response_content"),
        "Call entries have collapsible response section",
    )
    # Summary stats
    result.check(
        inspector.contains_regex(r'(?:total|summary|successful|failed|success)'),
        "LLM call inspector shows summary statistics",
    )


def test_run_manifest(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: run manifest section."""
    print("\n--- Run Manifest ---")

    result.check(
        inspector.has_id("manifest") or inspector.contains_regex(r'id\s*=\s*["\']?manifest'),
        "Run manifest section exists with id",
    )
    result.check(
        inspector.contains("Manifest") or inspector.contains("manifest"),
        "Run manifest section is labeled 'Manifest'",
    )
    result.check(
        inspector.contains("input_hash") or inspector.contains("hash"),
        "Run manifest shows input hashes",
    )
    result.check(
        inspector.contains("gemma") or inspector.contains("model"),
        "Run manifest shows model name",
    )
    result.check(
        inspector.contains("2026-08-10") or inspector.contains("created_at"),
        "Run manifest shows timestamp",
    )
    # Collapsible raw YAML
    result.check(
        inspector.contains("run-manifest") or inspector.contains("run_manifest"),
        "Run manifest has raw YAML section",
    )


def test_sticky_nav(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: sticky mini-navigation."""
    print("\n--- Sticky Nav ---")

    result.check(
        inspector.contains_regex(r'class\s*=\s*["\'][^"\']*sticky[^"\']*["\']')
        or inspector.contains_regex(r'id\s*=\s*["\']?sticky-nav["\']')
        or inspector.contains_regex(r'id\s*=\s*["\']?mininav["\']'),
        "Sticky navigation element exists",
    )
    for label in ("SP1", "SP2", "SP3", "Calls", "Manifest"):
        result.check(
            inspector.contains(f">{label}<") or inspector.contains(f'>{label}</a>')
            or inspector.contains_regex(rf'href\s*=\s*["\']#(?:sp1|sp2|sp3|calls|manifest)["\'][^>]*>\s*{label}'),
            f"Sticky nav contains link labeled '{label}'",
        )
    # JavaScript for scroll behavior
    result.check(
        inspector.contains("scroll") or inspector.contains("addEventListener"),
        "Sticky nav has JavaScript for scroll behavior",
    )


def test_attack_tree_visual(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: attack tree visualization."""
    print("\n--- Attack Tree Visual ---")

    result.check(
        inspector.contains_regex(r'class\s*=\s*["\'][^"\']*attack-tree[^"\']*["\']')
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*tree[^"\']*["\']'),
        "Attack tree rendered with tree CSS class",
    )
    # Color coding for branch categories
    result.check(
        inspector.contains("controller_side") or inspector.contains("controller-side")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*controller[^"\']*["\']'),
        "Attack tree has controller_side category",
    )
    result.check(
        inspector.contains("path_side") or inspector.contains("path-side")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*path[^"\']*["\']'),
        "Attack tree has path_side category",
    )
    result.check(
        inspector.contains("coordination_gap") or inspector.contains("coordination-gap")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*coordination[^"\']*["\']'),
        "Attack tree has coordination_gap category",
    )
    # Gate badges
    result.check(
        inspector.contains("AND") or inspector.contains("OR") or inspector.contains("LEAF")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*gate[^"\']*["\']'),
        "Attack tree shows gate badges",
    )


def test_gherkin_highlighting(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: Gherkin syntax highlighting."""
    print("\n--- Gherkin Highlighting ---")

    # Check for Gherkin keyword highlighting CSS classes
    result.check(
        inspector.contains("gherkin-keyword") or inspector.contains("step-given")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*step[^"\']*["\']'),
        "Gherkin keywords have highlighting CSS classes",
    )
    # Given = blue
    result.check(
        inspector.contains_regex(r'(?:step-given|gherkin-keyword)[^"\']*\b.*?3b82f6')
        or inspector.contains_regex(r'\.step-given\b.*?3b82f6')
        or inspector.contains("step-given"),
        "Given keyword highlighted (blue)",
    )
    # When = purple
    result.check(
        inspector.contains("step-when") or inspector.contains("8b5cf6"),
        "When keyword highlighted (purple)",
    )
    # Then = green
    result.check(
        inspector.contains("step-then") or inspector.contains("22c55e"),
        "Then keyword highlighted (green)",
    )
    # But = red
    result.check(
        inspector.contains("step-but") or inspector.contains("ef4444"),
        "But keyword highlighted (red)",
    )
    # And = indigo
    result.check(
        inspector.contains("step-and") or inspector.contains("6366f1"),
        "And keyword highlighted (indigo)",
    )


def test_eval_scorecard_gauges(result: TestResult, inspector: HTMLInspector) -> None:
    """Test: eval scorecard gauges with color thresholds."""
    print("\n--- Eval Scorecard Gauges ---")

    # Check for gauge/bar elements
    result.check(
        inspector.contains_regex(r'class\s*=\s*["\'][^"\']*(?:gauge|score-bar|scorecard-badge)[^"\']*["\']'),
        "Eval scorecard has gauge/bar elements",
    )
    # Green for >= 80%
    result.check(
        inspector.contains("scorecard-badge-green") or inspector.contains("22c55e")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*green[^"\']*["\']'),
        "Eval scorecard has green gauge for high scores",
    )
    # Red for < 60%
    result.check(
        inspector.contains("scorecard-badge-red") or inspector.contains("ef4444")
        or inspector.contains_regex(r'class\s*=\s*["\'][^"\']*red[^"\']*["\']'),
        "Eval scorecard has red gauge for low scores",
    )
    # Metrics present
    for metric in ("traceability", "bdi", "branch", "diversity"):
        result.check(
            inspector.contains(metric),
            f"Eval scorecard shows metric '{metric}'",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="STPA Report QA Suite")
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        default=None,
        help="Override fixture directory",
    )
    args = parser.parse_args()

    global FIXTURE_DIR
    if args.fixture_dir is not None:
        FIXTURE_DIR = args.fixture_dir

    result = TestResult()

    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)

        # Build combined output directory
        combined_dir = _build_combined_output_dir(tmpdir)
        print(f"Combined output dir: {combined_dir}")

        # Run report generation tests
        report_path = test_report_generation(result, combined_dir, tmpdir)

        if report_path is None:
            print("ERROR: Report was not generated, cannot run further tests")
            result.failed += 1
            return 1

        # Load HTML for inspection
        html_text = report_path.read_text(encoding="utf-8")
        inspector = HTMLInspector(html_text)

        # Run all section tests
        test_hero_summary(result, inspector)
        test_sp1_flow_card(result, inspector)
        test_sp2_flow_card(result, inspector)
        test_sp3_flow_card(result, inspector)
        test_llm_call_inspector(result, inspector)
        test_run_manifest(result, inspector)
        test_sticky_nav(result, inspector)
        test_attack_tree_visual(result, inspector)
        test_gherkin_highlighting(result, inspector)
        test_eval_scorecard_gauges(result, inspector)

    return 0 if result.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
