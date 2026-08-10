"""Constants for the SP2 Threat Enumeration package.

This module exists so that every sub-module can import ``PROMPTS_DIR``
without creating a circular dependency through ``__init__``.

No other modules are imported here — this is a leaf module.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR: Path = Path(__file__).parent / "prompts"


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-10T00:14:19Z","module_hash":"169df8f6d62894cc496bdd610c44a0139f673b86e6258cfb315ccf1534374da0","functions":[]}
# mutate4py-manifest-end
