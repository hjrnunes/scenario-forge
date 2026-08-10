"""Constants for the SP3 Scenario Production package.

This module exists so that every sub-module can import ``PROMPTS_DIR``
without creating a circular dependency through ``__init__``.

No other modules are imported here — this is a leaf module.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR: Path = Path(__file__).parent / "prompts"


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T14:14:46Z","module_hash":"c97a54ffcf49a091f4f2d1389163da1e71ace45e27647f682531a982d3673b74","functions":[]}
# mutate4py-manifest-end
