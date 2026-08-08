"""Architecture guard tests for the STPA-Sec foundation.

These tests enforce structural invariants that are easy to regress:

1. **Clean-copy enforcement**: ``stpa/infra/`` must not import from the
   existing pipeline modules.  The clean-copy decision is a deliberate
   architectural boundary — accidental imports would re-couple the new
   pipeline to the 85K-line manifest system and hardcoded template loader.

2. **No import cycles**: All stpa modules must import without circular
   dependency errors.

3. **Model dependency direction**: Higher-level models (scenario_spec,
   scenario_envelope) may import from lower-level models (loss_analysis,
   control_structure, enriched_threat_set, ica_enumeration), but not the
   reverse.  ``_validation`` is the lowest-level shared helper and may be
   imported by any model, but must not import any model.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

STPA_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "scenario_forge" / "stpa"
INFRA_DIR = STPA_ROOT / "infra"
MODELS_DIR = STPA_ROOT / "models"
SYSTEM_MODEL_DIR = STPA_ROOT / "system_model"

# Modules that stpa/infra/ must NOT import from.
_FORBIDDEN_INFRA_PREFIXES = (
    "scenario_forge.pipeline",
    "scenario_forge.llm",
    "scenario_forge.prompts",
    "scenario_forge.data",
    "scenario_forge.models.capability_profile",
    "scenario_forge.models.risk_card",
    "scenario_forge.models.stage",
    "scenario_forge.report",
    "scenario_forge.cli",
    "scenario_forge.config",
    "scenario_forge.io",
)

# Dependency layers (lower number = lower level).
# A module may only import from same-or-lower layers.
_MODEL_LAYERS: dict[str, int] = {
    "_validation": 0,
    "loss_analysis": 1,
    "control_structure": 1,
    "enriched_threat_set": 1,
    "ica_enumeration": 2,
    "scenario_spec": 3,
    "scenario_envelope": 4,
}


def _extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*.

    Handles both ``import X.Y`` and ``from X.Y import ...`` forms,
    including ``TYPE_CHECKING`` guarded imports.
    """
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    return imports


def _stpa_model_imports(file_path: Path) -> list[str]:
    """Return stpa model module names imported by *file_path*.

    Returns bare module names (e.g. ``"loss_analysis"``) for any import
    starting with ``scenario_forge.stpa.models``.
    """
    result: list[str] = []
    for imp in _extract_imports(file_path):
        if imp.startswith("scenario_forge.stpa.models."):
            result.append(imp.rsplit(".", 1)[-1])
        elif imp == "scenario_forge.stpa.models":
            result.append(imp)
    return result


# ---------------------------------------------------------------------------
# Clean-copy enforcement
# ---------------------------------------------------------------------------


class TestCleanCopyEnforcement:
    """stpa/infra/ must have zero coupling to the existing pipeline."""

    @pytest.fixture
    def infra_python_files(self) -> list[Path]:
        return sorted(INFRA_DIR.glob("*.py"))

    def test_no_forbidden_imports_in_infra(self, infra_python_files):
        """No file in stpa/infra/ imports from the existing pipeline."""
        violations: list[str] = []
        for path in infra_python_files:
            for imp in _extract_imports(path):
                for forbidden in _FORBIDDEN_INFRA_PREFIXES:
                    if imp == forbidden or imp.startswith(forbidden + "."):
                        violations.append(
                            f"{path.name}: imports '{imp}' — "
                            f"forbidden by clean-copy policy"
                        )
        assert not violations, (
            "Clean-copy violation in stpa/infra/:\n" + "\n".join(violations)
        )

    def test_infra_only_imports_stpa_or_external(self, infra_python_files):
        """infra modules may only import from stpa, stdlib, or third-party."""
        allowed_prefixes = (
            "scenario_forge.stpa",
            "openai",
            "pydantic",
            "yaml",
            "jinja2",
            "hashlib",
            "json",
            "os",
            "time",
            "datetime",
            "pathlib",
            "typing",
            "functools",
            "enum",
            "dataclasses",
            "abc",
            "collections",
            "io",
            "re",
            "copy",
            "math",
            "itertools",
            "contextlib",
        )
        violations: list[str] = []
        for path in infra_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("_") or imp.startswith("."):
                    continue  # relative or private
                if any(imp.startswith(p) or imp == p for p in allowed_prefixes):
                    continue
                violations.append(f"{path.name}: unexpected import '{imp}'")
        assert not violations, (
            "Unexpected imports in stpa/infra/:\n" + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# Import cycle detection
# ---------------------------------------------------------------------------


class TestNoImportCycles:
    """All stpa modules must import without circular dependency errors."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "scenario_forge.stpa",
            "scenario_forge.stpa.infra",
            "scenario_forge.stpa.infra.llm",
            "scenario_forge.stpa.infra.call_log",
            "scenario_forge.stpa.infra.yaml_io",
            "scenario_forge.stpa.infra.templates",
            "scenario_forge.stpa.infra.manifest",
            "scenario_forge.stpa.models",
            "scenario_forge.stpa.models._validation",
            "scenario_forge.stpa.models.loss_analysis",
            "scenario_forge.stpa.models.control_structure",
            "scenario_forge.stpa.models.ica_enumeration",
            "scenario_forge.stpa.models.enriched_threat_set",
            "scenario_forge.stpa.models.scenario_spec",
            "scenario_forge.stpa.models.scenario_envelope",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        """Module can be imported without errors."""
        mod = importlib.import_module(module_name)
        assert mod is not None


# ---------------------------------------------------------------------------
# Model dependency direction
# ---------------------------------------------------------------------------


class TestModelDependencyDirection:
    """Higher-level models must not import lower-level models in reverse."""

    @pytest.fixture
    def model_files(self) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for path in sorted(MODELS_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            name = path.stem  # e.g. "loss_analysis"
            files[name] = path
        return files

    def test_no_reverse_dependencies(self, model_files):
        """A model at layer N must not import from a model at layer > N."""
        violations: list[str] = []
        for name, path in model_files.items():
            my_layer = _MODEL_LAYERS.get(name, 99)
            for imported in _stpa_model_imports(path):
                if imported == "scenario_forge.stpa.models":
                    continue  # package import, not a model
                target_layer = _MODEL_LAYERS.get(imported, 99)
                if target_layer > my_layer:
                    violations.append(
                        f"{name} (layer {my_layer}) imports "
                        f"{imported} (layer {target_layer}) — "
                        f"dependency direction violation"
                    )
        assert not violations, (
            "Model dependency direction violations:\n" + "\n".join(violations)
        )

    def test_validation_module_imports_no_models(self, model_files):
        """_validation.py must not import any boundary schema model."""
        path = model_files.get("_validation")
        assert path is not None, "_validation.py not found"
        model_imports = _stpa_model_imports(path)
        assert not model_imports, (
            f"_validation.py imports models: {model_imports}"
        )

    def test_loss_analysis_does_not_import_higher_models(self, model_files):
        """loss_analysis.py must not import control_structure or higher."""
        path = model_files["loss_analysis"]
        imports = _stpa_model_imports(path)
        forbidden = {"control_structure", "ica_enumeration", "enriched_threat_set",
                     "scenario_spec", "scenario_envelope"}
        found = forbidden & set(imports)
        assert not found, f"loss_analysis.py imports higher-level models: {found}"

    def test_control_structure_does_not_import_higher_models(self, model_files):
        """control_structure.py must not import ica_enumeration or higher."""
        path = model_files["control_structure"]
        imports = _stpa_model_imports(path)
        forbidden = {"ica_enumeration", "enriched_threat_set",
                     "scenario_spec", "scenario_envelope"}
        found = forbidden & set(imports)
        assert not found, f"control_structure.py imports higher-level models: {found}"

    def test_enriched_threat_set_imports_no_stpa_models(self, model_files):
        """enriched_threat_set.py is a pure data model — no stpa imports."""
        path = model_files["enriched_threat_set"]
        imports = _stpa_model_imports(path)
        assert not imports, f"enriched_threat_set.py imports stpa models: {imports}"


# ---------------------------------------------------------------------------
# System Model architecture guards
# ---------------------------------------------------------------------------

# Dependency layers within system_model (lower = closer to IO/constants).
# A module at layer N may import from modules at layer <= N.
_SYSTEM_MODEL_LAYERS: dict[str, int] = {
    "_constants": 0,
    "heuristics": 1,
    "loss_analysis": 1,
    "profile": 1,
    "control_structure": 1,
    "critic": 2,
    "run": 3,
}

# Existing-pipeline modules that system_model is allowed to import.
# These are the I/O contract types (CapabilityProfile, RiskCard) that
# cross the STPA/existing-pipeline boundary by design.
_ACCEPTED_PIPELINE_IMPORTS: frozenset[str] = frozenset(
    {
        "scenario_forge.models.capability_profile",
        "scenario_forge.models.risk_card",
    }
)

# Modules that system_model must NOT import from (existing pipeline).
_FORBIDDEN_SYSTEM_MODEL_PREFIXES = (
    "scenario_forge.pipeline",
    "scenario_forge.llm",
    "scenario_forge.prompts",
    "scenario_forge.data",
    "scenario_forge.models.stage",
    "scenario_forge.report",
    "scenario_forge.cli",
    "scenario_forge.config",
    "scenario_forge.io",
)


def _system_model_internal_imports(file_path: Path) -> list[str]:
    """Return bare module names imported from within system_model.

    E.g. ``from scenario_forge.stpa.system_model.heuristics import X``
    yields ``"heuristics"``.
    """
    result: list[str] = []
    for imp in _extract_imports(file_path):
        prefix = "scenario_forge.stpa.system_model."
        if imp.startswith(prefix):
            result.append(imp[len(prefix):].split(".")[0])
    return result


class TestSystemModelCleanCopy:
    """system_model/ must have no coupling to the existing pipeline
    beyond the accepted I/O contract types."""

    @pytest.fixture
    def system_model_python_files(self) -> list[Path]:
        return sorted(
            p for p in SYSTEM_MODEL_DIR.glob("*.py")
            if p.name != "__init__.py"
        )

    def test_no_forbidden_imports_in_system_model(self, system_model_python_files):
        """No system_model file imports from forbidden existing-pipeline modules."""
        violations: list[str] = []
        for path in system_model_python_files:
            for imp in _extract_imports(path):
                for forbidden in _FORBIDDEN_SYSTEM_MODEL_PREFIXES:
                    if imp == forbidden or imp.startswith(forbidden + "."):
                        violations.append(
                            f"{path.name}: imports '{imp}' — "
                            f"forbidden by clean-copy policy"
                        )
        assert not violations, (
            "Clean-copy violation in system_model/:\n" + "\n".join(violations)
        )

    def test_pipeline_imports_limited_to_accepted_types(
        self, system_model_python_files
    ):
        """Any import from scenario_forge.models must be an accepted contract type."""
        violations: list[str] = []
        for path in system_model_python_files:
            for imp in _extract_imports(path):
                if imp.startswith("scenario_forge.models.") or imp == "scenario_forge.models":
                    if imp not in _ACCEPTED_PIPELINE_IMPORTS:
                        violations.append(
                            f"{path.name}: imports '{imp}' — "
                            f"not an accepted I/O contract type"
                        )
        assert not violations, (
            "Unexpected pipeline model imports in system_model/:\n"
            + "\n".join(violations)
        )


class TestSystemModelNoImportCycles:
    """All system_model modules must import without circular dependency errors."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "scenario_forge.stpa.system_model",
            "scenario_forge.stpa.system_model._constants",
            "scenario_forge.stpa.system_model.loss_analysis",
            "scenario_forge.stpa.system_model.profile",
            "scenario_forge.stpa.system_model.control_structure",
            "scenario_forge.stpa.system_model.critic",
            "scenario_forge.stpa.system_model.heuristics",
            "scenario_forge.stpa.system_model.run",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        """Module can be imported without errors."""
        mod = importlib.import_module(module_name)
        assert mod is not None


class TestSystemModelDependencyDirection:
    """Higher-level system_model modules must not import lower-level ones in reverse.

    Dependency layers (lower = closer to IO/constants):
      0: _constants     (leaf — no imports)
      1: heuristics, loss_analysis, profile, control_structure  (stages)
      2: critic         (uses heuristics)
      3: run            (orchestrator — uses all)
    """

    @pytest.fixture
    def system_model_files(self) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for path in sorted(SYSTEM_MODEL_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            files[path.stem] = path
        return files

    def test_no_reverse_dependencies(self, system_model_files):
        """A module at layer N must not import from a module at layer > N."""
        violations: list[str] = []
        for name, path in system_model_files.items():
            my_layer = _SYSTEM_MODEL_LAYERS.get(name, 99)
            for imported in _system_model_internal_imports(path):
                target_layer = _SYSTEM_MODEL_LAYERS.get(imported, 99)
                if target_layer > my_layer:
                    violations.append(
                        f"{name} (layer {my_layer}) imports "
                        f"{imported} (layer {target_layer}) — "
                        f"dependency direction violation"
                    )
        assert not violations, (
            "System model dependency direction violations:\n"
            + "\n".join(violations)
        )

    def test_constants_is_leaf(self, system_model_files):
        """_constants.py must not import any other module."""
        path = system_model_files.get("_constants")
        assert path is not None, "_constants.py not found"
        all_imports = _extract_imports(path)
        # Allow only stdlib imports (from __future__ and pathlib).
        non_stdlib = [
            imp for imp in all_imports
            if not imp.startswith("_") and imp not in ("pathlib",)
        ]
        assert not non_stdlib, (
            f"_constants.py imports non-stdlib modules: {non_stdlib}"
        )

    def test_stage_modules_do_not_import_each_other(self, system_model_files):
        """Stage modules (loss_analysis, profile, control_structure, heuristics)
        must not import from each other or from critic/run."""
        stage_modules = {"loss_analysis", "profile", "control_structure", "heuristics"}
        forbidden_targets = {"critic", "run"}
        for name in stage_modules:
            path = system_model_files[name]
            imports = set(_system_model_internal_imports(path))
            cross_stage = imports & (stage_modules - {name})
            higher = imports & forbidden_targets
            assert not cross_stage, (
                f"{name}.py imports sibling stage module(s): {cross_stage}"
            )
            assert not higher, (
                f"{name}.py imports higher-level module(s): {higher}"
            )

    def test_critic_does_not_import_run(self, system_model_files):
        """critic.py must not import the orchestrator (run.py)."""
        path = system_model_files["critic"]
        imports = set(_system_model_internal_imports(path))
        assert "run" not in imports, "critic.py imports run.py — direction violation"

    def test_heuristics_imports_no_system_model_modules(self, system_model_files):
        """heuristics.py is a pure post-check — must not import any system_model module."""
        path = system_model_files["heuristics"]
        imports = _system_model_internal_imports(path)
        assert not imports, (
            f"heuristics.py imports system_model modules: {imports}"
        )
