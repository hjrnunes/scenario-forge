#!/usr/bin/env python3
"""SP2 runner script — invokes the STPA SP2 threat enumeration pipeline.

Consumes SP1 artifacts (control structure, capability profile, loss
analysis) and runs Stage 3 (ICA enumeration) and Stage 4 (catalog
enrichment).

Supports two modes for LLM client configuration:
  1. --profile <name>  : load parameters from ai/model-profiles.yaml
  2. Environment fallback: SCENARIO_FORGE_MODEL_BASE_URL, etc.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.pipeline.llm_config import (
    DEFAULT_PROFILES_FILE,
    resolve_llm_client_from_env,
    resolve_llm_client_from_profile,
)
from scenario_forge.stpa.threat_enum.run import run_sp2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SP2 runner script for the STPA threat enumeration pipeline"
    )
    parser.add_argument(
        "--control-structure",
        required=True,
        help="Path to control-structure.yaml (SP1 output)",
    )
    parser.add_argument(
        "--capability-profile",
        required=True,
        help="Path to capability-profile.yaml (SP1 output)",
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
        cs_path = Path(args.control_structure)
        cp_path = Path(args.capability_profile)
        la_path = Path(args.loss_analysis)
        output_dir = Path(args.output_dir)

        control_structure = read_yaml(cs_path, ControlStructure)
        capability_profile = read_yaml(cp_path, CapabilityProfile)
        loss_analysis = read_yaml(la_path, LossAnalysis)

        logger.info("Loaded SP1 artifacts")
        logger.info("  Control structure: %d responsibilities", len(control_structure.responsibilities))
        logger.info("  Capability profile: %d zones", len(capability_profile.zones_active))
        logger.info("  Loss analysis: %d hazards", len(loss_analysis.hazards))
        logger.info("Output directory: %s", output_dir)

        if args.profile:
            llm_client, _ = resolve_llm_client_from_profile(
                args.profiles_file, args.profile
            )
        else:
            llm_client = resolve_llm_client_from_env()

        logger.info("Starting SP2 pipeline...")
        result = run_sp2(
            llm_client=llm_client,
            control_structure=control_structure,
            capability_profile=capability_profile,
            loss_analysis=loss_analysis,
            run_dir=output_dir,
            max_workers=args.max_workers,
        )

        # Print summary
        print("\n" + "=" * 60)
        print("SP2 RUN SUMMARY")
        print("=" * 60)

        if result.ica_enumeration is not None:
            total = len(result.ica_enumeration.slots)
            na = sum(1 for s in result.ica_enumeration.slots if s.is_na)
            print(f"Total slots: {total}")
            print(f"N/A slots: {na}")
            print(f"Fill rate: {(total - na) / total:.1%}" if total else "Fill rate: N/A")
        else:
            print("ICA Enumeration: FAILED")

        if result.enriched_threat_set is not None:
            print(f"Structural threats: {len(result.enriched_threat_set.structural_threats)}")
            mapped = sum(1 for t in result.enriched_threat_set.structural_threats if t.catalog_mappings)
            print(f"  Mapped: {mapped}")
            print(f"  Unmapped: {len(result.enriched_threat_set.structural_threats) - mapped}")
        else:
            print("Enriched Threat Set: FAILED")

        if result.na_quality_result is not None:
            print(f"N/A quality flags: {len(result.na_quality_result.flagged_slots)} structural, {len(result.na_quality_result.ratio_flags)} ratio")

        if result.stage_errors:
            print(f"Stage Errors: {len(result.stage_errors)}")
            for err in result.stage_errors:
                print(f"  - {err}")
        print("=" * 60)

        logger.info("SP2 pipeline completed successfully")
        return 0

    except Exception as e:
        logger.exception("SP2 pipeline failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
