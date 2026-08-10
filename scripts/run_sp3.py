#!/usr/bin/env python3
"""SP3 runner script — invokes the STPA SP3 scenario production pipeline.

Consumes SP1/SP2 artifacts (control structure, loss analysis, enriched
threat set) and runs Stage 5 (BDI generation), Stage 6 (narrative,
attack tree, Gherkin), and Stage 7 (validators, eval metrics, coverage
gaps).

Supports two modes for LLM client configuration:
  1. --profile <name>  : load parameters from ai/model-profiles.yaml
  2. Environment fallback: SCENARIO_FORGE_MODEL_BASE_URL, etc.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.model_profiles import load_profile
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.scenario_prod.run import run_sp3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

DEFAULT_PROFILES_FILE = "ai/model-profiles.yaml"


def resolve_llm_client_from_profile(
    profiles_file: str, profile_name: str
) -> tuple[LLMClient, str]:
    """Create an LLMClient from a named model profile."""
    profile = load_profile(profiles_file, profile_name)
    logger.info(
        "Loaded profile '%s' from %s: model=%s, base_url=%s",
        profile_name,
        profiles_file,
        profile.get("model"),
        profile.get("base_url"),
    )
    client = LLMClient(
        base_url=profile.get("base_url"),
        api_key=profile.get("api_key"),
        model=profile.get("model"),
        max_completion_tokens=profile.get("max_completion_tokens"),
        temperature=profile.get("temperature"),
        top_p=profile.get("top_p"),
        top_k=profile.get("top_k"),
        extra_headers=profile.get("headers"),
    )
    return client, profile_name


def resolve_llm_client_from_env() -> LLMClient:
    """Create an LLMClient from environment variables."""
    base_url = os.environ.get("SCENARIO_FORGE_MODEL_BASE_URL")
    model = os.environ.get("SCENARIO_FORGE_MODEL_NAME", "gemma-4-26b-a4b-it")
    api_key = os.environ.get("SCENARIO_FORGE_API_KEY", "unused")
    logger.info("Creating LLMClient from env: base_url=%s, model=%s", base_url, model)
    return LLMClient(base_url=base_url, model=model, api_key=api_key)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SP3 runner script for the STPA scenario production pipeline"
    )
    parser.add_argument(
        "--enriched-threats",
        required=True,
        help="Path to enriched-threats.yaml (SP2 output)",
    )
    parser.add_argument(
        "--control-structure",
        required=True,
        help="Path to control-structure.yaml (SP1 output)",
    )
    parser.add_argument(
        "--loss-analysis",
        required=True,
        help="Path to loss-analysis.yaml (SP1 output)",
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
        "--max-workers",
        type=int,
        default=1,
        help="Maximum parallel workers for LLM calls (default: 1 = sequential)",
    )

    args = parser.parse_args()

    try:
        ets_path = Path(args.enriched_threats)
        cs_path = Path(args.control_structure)
        la_path = Path(args.loss_analysis)
        output_dir = Path(args.output_dir)

        enriched_threat_set = read_yaml(ets_path, EnrichedThreatSet)
        control_structure = read_yaml(cs_path, ControlStructure)
        loss_analysis = read_yaml(la_path, LossAnalysis)

        logger.info("Loaded SP1/SP2 artifacts")
        logger.info("  Control structure: %d responsibilities", len(control_structure.responsibilities))
        logger.info("  Enriched threats: %d structural threats", len(enriched_threat_set.structural_threats))
        logger.info("  Loss analysis: %d hazards", len(loss_analysis.hazards))
        logger.info("Output directory: %s", output_dir)

        if args.profile:
            llm_client, _ = resolve_llm_client_from_profile(
                args.profiles_file, args.profile
            )
        else:
            llm_client = resolve_llm_client_from_env()

        logger.info("Starting SP3 pipeline...")
        result = run_sp3(
            llm_client=llm_client,
            enriched_threat_set=enriched_threat_set,
            control_structure=control_structure,
            loss_analysis=loss_analysis,
            run_dir=output_dir,
            max_workers=args.max_workers,
        )

        # Print summary
        print("\n" + "=" * 60)
        print("SP3 RUN SUMMARY")
        print("=" * 60)
        print(f"Scenario specs: {len(result.scenario_specs)}")
        print(f"Scenario envelopes: {len(result.scenario_envelopes)}")
        if result.stage_errors:
            print(f"Stage Errors: {len(result.stage_errors)}")
            for err in result.stage_errors:
                print(f"  - {err}")
        if result.validation_errors:
            print(f"Validation Errors: {len(result.validation_errors)}")
        print("=" * 60)

        logger.info("SP3 pipeline completed successfully")
        return 0

    except Exception as e:
        logger.exception("SP3 pipeline failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
