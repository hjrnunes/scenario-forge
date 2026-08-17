"""End-to-end QA for output entry-point ingress-zone normalization.

Exercises the public ``scenario-forge generate`` CLI and inspects its YAML
artifacts with PyYAML. No Scenario Forge Python API is imported.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
QA_ROOT = ROOT / "tmp" / "qa-output-ingress-zone"

EXPECTED = {
    "Audit Logs": ("output", None),
    "Notifications": ("output", None),
    "User Prompt": ("input", "reasoning"),
    "Admin Console": ("bidirectional", "input"),
}

PROFILE = """\
zones_active:
  - input
  - reasoning
entry_points:
  - name: Audit Logs
    direction: output
    ingress_zone: reasoning
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


def run_cli(
    profile: Path,
    out_dir: Path,
    use_case: Path,
    risks: Path,
    mapping: Path,
) -> subprocess.CompletedProcess[str]:
    """Run the generate command through its public CLI."""
    return subprocess.run(
        [
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
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def generated_profile(out_dir: Path) -> Path:
    """Find the sole generated capability profile below an output collection."""
    matches = sorted(out_dir.rglob("capability-profile.yaml"))
    if len(matches) != 1:
        raise AssertionError(
            f"Expected one generated capability profile below {out_dir}, got {matches}"
        )
    return matches[0]


def observed_values(path: Path) -> dict[str, tuple[str, str | None]]:
    """Read entry-point directions and zones using a general YAML reader."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {
        item["name"]: (item["direction"], item.get("ingress_zone"))
        for item in data["entry_points"]
    }


def require_cli_success(label: str, proc: subprocess.CompletedProcess[str]) -> None:
    """Assert the observable success contract for one CLI invocation."""
    detail = f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    if proc.returncode != 0:
        raise AssertionError(f"{label} exited {proc.returncode}\n{detail}")
    if "Pipeline complete." not in proc.stdout:
        raise AssertionError(f"{label} omitted completion message\n{detail}")
    error_text = proc.stderr.lower()
    if "validationerror" in error_text or "cannot have an ingress zone" in error_text:
        raise AssertionError(
            f"{label} reported entry-point validation failure\n{detail}"
        )


def main() -> int:
    QA_ROOT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=QA_ROOT))
    use_case = work / "use-case.txt"
    risks = work / "risk-extraction.json"
    mapping = work / "mappings.sssom.tsv"
    source_profile = work / "capability-profile.yaml"

    use_case.write_text(
        "An AI assistant emits audit records and accepts user prompts.\n",
        encoding="utf-8",
    )
    risks.write_text("[]\n", encoding="utf-8")
    mapping.write_text("", encoding="utf-8")
    source_profile.write_text(PROFILE, encoding="utf-8")

    first_out = work / "output-1"
    first = run_cli(source_profile, first_out, use_case, risks, mapping)
    require_cli_success("QA-OIZ-01", first)
    normalized = generated_profile(first_out)
    first_values = observed_values(normalized)
    if first_values != EXPECTED:
        raise AssertionError(
            f"QA-OIZ-01 generated unexpected entry points: {first_values}"
        )

    second_out = work / "output-2"
    second = run_cli(normalized, second_out, use_case, risks, mapping)
    require_cli_success("QA-OIZ-02", second)
    second_values = observed_values(generated_profile(second_out))
    if second_values != EXPECTED:
        raise AssertionError(
            f"QA-OIZ-02 generated unexpected entry points: {second_values}"
        )

    print("PASS QA-OIZ-01: contradictory output ingress zone was normalized")
    print("PASS QA-OIZ-02: normalized profile reuse was idempotent")
    print(f"Artifacts: {work.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
