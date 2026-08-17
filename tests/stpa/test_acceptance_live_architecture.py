"""Architecture guards for live-LLM acceptance authorization."""

from __future__ import annotations

import ast
from pathlib import Path

ACCEPTANCE = (
    Path(__file__).resolve().parent.parent.parent / "acceptance"
)
POLICY = ACCEPTANCE / "live_llm_opt_in.py"
RUNTIME = ACCEPTANCE / "acceptance_runtime.py"
FEATURE_HANDLERS = ACCEPTANCE / "runtime_features"


def _imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_policy_module_does_not_import_runtime_or_handlers() -> None:
    imports = _imported_modules(POLICY)
    forbidden = {
        "acceptance_runtime",
        "runtime_features",
        "runtime_features.acceptance_live_opt_in",
        "runtime_shared",
    }
    assert forbidden.isdisjoint(imports)


def test_runtime_does_not_import_live_opt_in_handlers() -> None:
    imports = _imported_modules(RUNTIME)
    assert "runtime_features.acceptance_live_opt_in" not in imports
    assert "live_llm_opt_in" in imports


def test_live_opt_in_handlers_depend_inward_on_policy() -> None:
    imports = _imported_modules(FEATURE_HANDLERS / "acceptance_live_opt_in.py")
    assert "live_llm_opt_in" in imports
