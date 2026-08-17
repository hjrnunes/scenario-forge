#!/usr/bin/env python3
"""SP1 runner script — invokes the STPA SP1 pipeline against a real LLM endpoint.

Supports two modes for LLM client configuration:
  1. --profile <name>  : load parameters from ai/model-profiles.yaml (or --profiles-file)
  2. Environment fallback: SCENARIO_FORGE_MODEL_BASE_URL, SCENARIO_FORGE_API_KEY,
     SCENARIO_FORGE_MODEL_NAME (backwards compatible)

After the pipeline run, automatically renders calls.jsonl to calls.html.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from scenario_forge.data.loaders import load_risk_extraction
from scenario_forge.stpa.infra.calls_html import render_calls_html
from scenario_forge.stpa.pipeline.llm_config import (
    DEFAULT_PROFILES_FILE,
    read_use_case,
    resolve_llm_client_from_env,
    resolve_llm_client_from_profile,
)
from scenario_forge.stpa.system_model.run import run_sp1

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SP1 runner script for the STPA pipeline"
    )
    parser.add_argument(
        "--use-case",
        required=True,
        help="Path to use-case text file (@ prefix optional)",
    )
    parser.add_argument(
        "--risk-extraction",
        required=True,
        help="Path to risk extraction JSON file",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Output directory for artifacts",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Named model profile to load from the profiles file",
    )
    parser.add_argument(
        "--profiles-file",
        default=DEFAULT_PROFILES_FILE,
        help=f"Path to model profiles YAML file (default: {DEFAULT_PROFILES_FILE})",
    )
    parser.add_argument(
        "--capability-profile",
        default=None,
        help="Path to a pre-built capability-profile.yaml (skips Stage 1b)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="Maximum parallel workers for LLM calls (default: 1 = sequential)",
    )

    args = parser.parse_args()

    try:
        use_case_text = read_use_case(args.use_case)
        risk_cards = load_risk_extraction(args.risk_extraction)
        output_dir = Path(args.output_dir)

        logger.info("Loaded %d risk cards", len(risk_cards))
        logger.info("Output directory: %s", output_dir)

        profile_name = None
        if args.profile:
            llm_client, profile_name = resolve_llm_client_from_profile(
                args.profiles_file, args.profile
            )
        else:
            llm_client = resolve_llm_client_from_env()

        profile_path = (
            Path(args.capability_profile) if args.capability_profile else None
        )

        logger.info("Starting SP1 pipeline...")
        result = run_sp1(
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=output_dir,
            profile_path=profile_path,
            profile_name=profile_name,
            max_workers=args.max_workers,
        )

        # Render calls.jsonl to calls.html
        calls_jsonl = output_dir / "calls.jsonl"
        if calls_jsonl.exists():
            calls_html_path = output_dir / "calls.html"
            render_calls_html(calls_jsonl, calls_html_path)
            logger.info("Rendered calls.html to %s", calls_html_path)

        # Print summary
        print("\n" + "=" * 60)
        print("SP1 RUN SUMMARY")
        print("=" * 60)

        if result.loss_analysis is not None:
            all_losses = (
                result.loss_analysis.risk_card_losses
                + result.loss_analysis.use_case_losses
            )
            print(f"Losses: {len(all_losses)}")
            print(f"Hazards: {len(result.loss_analysis.hazards)}")
            print(f"Constraints: {len(result.loss_analysis.security_constraints)}")
        else:
            print("Loss Analysis: DEGRADED — not produced")

        if result.control_structure is not None:
            total_ca = sum(
                len(r.control_actions)
                for r in result.control_structure.responsibilities
            )
            print(f"Responsibilities: {len(result.control_structure.responsibilities)}")
            print(f"Control Actions: {total_ca}")
        else:
            print("Control Structure: DEGRADED — not produced")

        print(f"Heuristic Errors: {len(result.heuristic_errors)}")
        print(f"Heuristic Warnings: {len(result.heuristic_warnings)}")
        if result.critic_findings:
            print(f"Critic Findings: {len(result.critic_findings.gaps)} gaps")
        print(f"Revision Occurred: {result.revised}")
        if result.stage_errors:
            print(f"Stage Errors: {len(result.stage_errors)}")
            for err in result.stage_errors:
                print(f"  - {err}")
        print("=" * 60)

        logger.info("SP1 pipeline completed successfully")
        return 0

    except Exception as e:
        logger.exception("SP1 pipeline failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
