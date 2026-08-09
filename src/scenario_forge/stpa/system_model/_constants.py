"""Constants for the SP1 System Model package.

This module exists so that :mod:`system_model.__init__` and every
sub-module can import ``PROMPTS_DIR`` without creating a circular
dependency through ``__init__``.

No other modules are imported here — this is a leaf module.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR: Path = Path(__file__).parent / "prompts"


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T13:27:20Z","module_hash":"0ea08fc14f8c43f5ff4a674e60f0ebd70d701fbb59b0e1f8328002c5e56d8db0","functions":[]}
# mutate4py-manifest-end
