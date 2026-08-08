#!/usr/bin/env python3
"""Minimal SP1 runner script for lab-sp1-first-run.

Invokes the SP1 pipeline against a real LLM endpoint.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from scenario_forge.data.loaders import load_risk_extraction
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.system_model.run import run_sp1

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def resolve_llm_client() -> LLMClient:
    """Create an LLMClient from environment variables.
    
    Checks for SCENARIO_FORGE_* vars first, falls back to FG_* vars.
    """
    base_url = os.environ.get("SCENARIO_FORGE_MODEL_BASE_URL") or os.environ.get(
        "FG_BASE_URL"
    )
    model = os.environ.get("SCENARIO_FORGE_MODEL_NAME") or os.environ.get(
        "FG_MODEL_NAME", "gemma-4-26b-a4b-it"
    )
    api_key = os.environ.get("SCENARIO_FORGE_API_KEY", "unused")

    logger.info(f"Creating LLMClient: base_url={base_url}, model={model}")
    return LLMClient(base_url=base_url, model=model, api_key=api_key)


def read_use_case(path: str) -> str:
    """Read use-case text from file, stripping @ prefix if present."""
    # Strip @ prefix if present
    if path.startswith("@"):
        path = path[1:]

    use_case_path = Path(path)
    if not use_case_path.exists():
        raise FileNotFoundError(f"Use-case file not found: {path}")

    logger.info(f"Reading use-case from {path}")
    return use_case_path.read_text(encoding="utf-8")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Minimal SP1 runner for lab-sp1-first-run"
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

    args = parser.parse_args()

    try:
        # Read inputs
        use_case_text = read_use_case(args.use_case)
        risk_cards = load_risk_extraction(args.risk_extraction)
        output_dir = Path(args.output_dir)

        logger.info(f"Loaded {len(risk_cards)} risk cards")
        logger.info(f"Output directory: {output_dir}")

        # Create LLM client
        llm_client = resolve_llm_client()

        # Run SP1 pipeline
        logger.info("Starting SP1 pipeline...")
        result = run_sp1(
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=output_dir,
        )

        # Count control actions across all responsibilities
        total_control_actions = sum(
            len(resp.control_actions) for resp in result.control_structure.responsibilities
        )

        # Print summary
        print("\n" + "=" * 60)
        print("SP1 RUN SUMMARY")
        print("=" * 60)
        all_losses = (
            result.loss_analysis.risk_card_losses + result.loss_analysis.use_case_losses
        )
        print(f"Losses: {len(all_losses)}")
        print(f"Hazards: {len(result.loss_analysis.hazards)}")
        print(f"Constraints: {len(result.loss_analysis.security_constraints)}")
        print(f"Responsibilities: {len(result.control_structure.responsibilities)}")
        print(f"Control Actions: {total_control_actions}")
        print(f"Heuristic Errors: {len(result.heuristic_errors)}")
        print(f"Heuristic Warnings: {len(result.heuristic_warnings)}")
        if result.critic_findings:
            print(f"Critic Findings: {len(result.critic_findings.gaps)} gaps")
        print(f"Revision Occurred: {result.revised}")
        print("=" * 60)

        logger.info("SP1 pipeline completed successfully")
        return 0

    except Exception as e:
        logger.exception(f"SP1 pipeline failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
