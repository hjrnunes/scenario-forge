"""CLI entry point for scenario-forge."""

from __future__ import annotations

from pathlib import Path

import json

import typer
import yaml

app = typer.Typer(
    name="scenario-forge",
    help="LLM-driven red-teaming scenario generator for LLM and agentic AI systems.",
)

_VERSION = "0.1.0"


def _resolve_use_case(value: str) -> str:
    """If value starts with @, read from the referenced file; otherwise return as-is."""
    if value.startswith("@"):
        file_path = Path(value[1:])
        if not file_path.exists():
            typer.echo(f"Error: use-case file not found: {file_path}", err=True)
            raise typer.Exit(code=1)
        return file_path.read_text(encoding="utf-8").strip()
    return value


def _validate_file(path: Path, label: str) -> None:
    if not path.exists():
        typer.echo(f"Error: {label} not found: {path}", err=True)
        raise typer.Exit(code=1)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """scenario-forge: generate red-teaming scenarios for AI systems."""
    if ctx.invoked_subcommand is None:
        typer.echo(f"scenario-forge v{_VERSION} — use --help for commands")


@app.command()
def generate(
    use_case: str = typer.Option(
        ...,
        help="Use-case description (or @file.txt to read from file).",
    ),
    risk_extraction: Path = typer.Option(
        ...,
        help="Path to policy-mapper risk-extraction.json.",
    ),
    sssom: Path = typer.Option(
        ...,
        help="Path to SSSOM TSV mapping file.",
    ),
    output_dir: Path = typer.Option(
        "output",
        help="Output directory for pipeline artifacts.",
    ),
    cross_taxonomy: Path | None = typer.Option(
        None,
        help="Path to cross-taxonomy-mappings.yaml (defaults to bundled).",
    ),
    threats_path: Path | None = typer.Option(
        None,
        help="Path to OWASP agentic threats YAML (defaults to bundled).",
    ),
    base_url: str | None = typer.Option(
        None,
        help="LLM endpoint base URL (overrides SCENARIO_FORGE_MODEL_BASE_URL).",
    ),
    api_key: str | None = typer.Option(
        None,
        help="LLM API key (overrides SCENARIO_FORGE_API_KEY).",
    ),
    model: str | None = typer.Option(
        None,
        help="LLM model name (overrides SCENARIO_FORGE_MODEL_NAME).",
    ),
) -> None:
    """Run the full scenario generation pipeline (stages 1-4)."""
    typer.echo(f"\nscenario-forge v{_VERSION} — generate\n{'=' * 40}")

    use_case_text = _resolve_use_case(use_case)
    _validate_file(risk_extraction, "risk-extraction file")
    _validate_file(sssom, "SSSOM file")
    if cross_taxonomy is not None:
        _validate_file(cross_taxonomy, "cross-taxonomy file")
    if threats_path is not None:
        _validate_file(threats_path, "agentic threats file")

    try:
        from scenario_forge.pipeline.runner import run_pipeline

        result = run_pipeline(
            use_case=use_case_text,
            risk_extraction_path=risk_extraction,
            sssom_path=sssom,
            output_dir=output_dir,
            cross_taxonomy_path=cross_taxonomy,
            threats_path=threats_path,
            base_url=base_url,
            api_key=api_key,
            model=model,
        )

        typer.echo("\nPipeline complete.")
        typer.echo(f"  Scenarios generated: {len(result.scenarios)}/{len(result.seeds)}")
        typer.echo(f"  Governance-only:     {result.governance_only_count}")
        typer.echo(f"  Output directory:    {output_dir}")

    except Exception as exc:
        typer.echo(f"\nError: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command()
def report(
    output_dir: Path = typer.Option(
        "output",
        help="Output directory containing pipeline artifacts.",
    ),
) -> None:
    """Generate an HTML report from pipeline output."""
    typer.echo(f"\nscenario-forge v{_VERSION} — report\n{'=' * 40}")

    if not output_dir.exists():
        typer.echo(f"Error: output directory not found: {output_dir}", err=True)
        raise typer.Exit(code=1)

    try:
        from scenario_forge.report.generator import generate_report

        report_path = generate_report(output_dir)
        typer.echo(f"\nReport written to {report_path}")

    except Exception as exc:
        typer.echo(f"\nError: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command()
def profile(
    use_case: str = typer.Option(
        ...,
        help="Use-case description (or @file.txt to read from file).",
    ),
    output: Path | None = typer.Option(
        None,
        help="Write profile YAML to this file (default: stdout).",
    ),
    base_url: str | None = typer.Option(
        None,
        help="LLM endpoint base URL (overrides SCENARIO_FORGE_MODEL_BASE_URL).",
    ),
    api_key: str | None = typer.Option(
        None,
        help="LLM API key (overrides SCENARIO_FORGE_API_KEY).",
    ),
    model: str | None = typer.Option(
        None,
        help="LLM model name (overrides SCENARIO_FORGE_MODEL_NAME).",
    ),
) -> None:
    """Infer a capability profile from a use-case description (stage 1 only)."""
    typer.echo(f"\nscenario-forge v{_VERSION} — profile\n{'=' * 40}")

    use_case_text = _resolve_use_case(use_case)

    try:
        from scenario_forge.pipeline.runner import run_profile_only

        cap_profile, llm_result = run_profile_only(
            use_case=use_case_text,
            base_url=base_url,
            api_key=api_key,
            model=model,
        )

        profile_yaml = yaml.dump(
            cap_profile.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(profile_yaml, encoding="utf-8")
            typer.echo(f"\nProfile written to {output}")
        else:
            typer.echo("")
            typer.echo(profile_yaml)

        typer.echo(
            f"  LLM tokens: {llm_result.prompt_tokens} prompt"
            f" + {llm_result.completion_tokens} completion"
            f" ({llm_result.duration_ms}ms)"
        )

    except Exception as exc:
        typer.echo(f"\nError: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command(name="eval")
def eval_cmd(
    output_dir: Path = typer.Option(
        ...,
        help="Output directory containing pipeline artifacts.",
    ),
    format: str = typer.Option(
        "yaml",
        help="Output format: yaml or json.",
    ),
) -> None:
    """Evaluate generated scenario quality (Tier 1: deterministic metrics)."""
    typer.echo(f"\nscenario-forge v{_VERSION} — eval\n{'=' * 40}")

    if not output_dir.exists():
        typer.echo(f"Error: output directory not found: {output_dir}", err=True)
        raise typer.Exit(code=1)

    try:
        from scenario_forge.eval.runner import run_evaluation

        scorecard = run_evaluation(output_dir)

        if format.lower() == "json":
            output_text = json.dumps(scorecard, indent=2, default=str)
            output_filename = "eval-scorecard.json"
        else:
            output_text = yaml.dump(
                scorecard,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
            output_filename = "eval-scorecard.yaml"

        typer.echo("")
        typer.echo(output_text)

        # Write scorecard to output directory
        scorecard_path = output_dir / output_filename
        scorecard_path.write_text(output_text, encoding="utf-8")
        typer.echo(f"Scorecard written to {scorecard_path}")

    except Exception as exc:
        typer.echo(f"\nError: {exc}", err=True)
        raise typer.Exit(code=1)
