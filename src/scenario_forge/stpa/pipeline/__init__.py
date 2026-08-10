"""STPA end-to-end pipeline orchestration.

This package chains SP1 (system model), SP2 (threat enumeration), and
SP3 (scenario production) into a single ``run_stpa_pipeline`` call,
followed by STPA HTML report generation.
"""

from scenario_forge.stpa.pipeline.runner import STPARunResult, run_stpa_pipeline

__all__ = ["STPARunResult", "run_stpa_pipeline"]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T17:26:00Z","module_hash":"11098affbb243b50a0a3c348b51fa1c6382d1335d6fc62761d9a7a97fd18ace9","functions":[]}
# mutate4py-manifest-end
