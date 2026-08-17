"""Make the project package importable from acceptance entry points."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from paths import project_root
except ModuleNotFoundError:
    from acceptance.paths import project_root

PROJECT_ROOT = project_root(Path(__file__))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
