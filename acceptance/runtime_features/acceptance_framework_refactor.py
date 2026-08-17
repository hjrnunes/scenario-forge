"""Acceptance handlers for the framework refactor contracts.

These steps exercise the public seams of the acceptance framework rather than
the feature handlers that happen to use those seams.  The fixtures are
intentionally small: they make registry, lifecycle, snapshot, and runner
behavior observable without contacting an LLM.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from live_llm_opt_in import LIVE_LLM_ACCEPTANCE_MARKER
from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import World
from snapshot import artifact_paths, snapshot_layout


FEATURE_ID = "acceptance_framework_refactor"

_LAYOUT_ENVIRONMENT = (
    "SWARMFORGE_FEATURES_DIR",
    "SWARMFORGE_ACCEPTANCE_FEATURES_DIR",
    "SWARMFORGE_ACCEPTANCE_IR_DIR",
    "SWARMFORGE_ACCEPTANCE_DRY_DIR",
    "SWARMFORGE_ACCEPTANCE_GENERATED_DIR",
    "SWARMFORGE_ACCEPTANCE_MUTATION_DIR",
)

_AFR_BACKGROUND_STEP = "acceptance framework background observes its world"
_AFR_MUTATION_STEP = "acceptance framework first example changes its state"
_AFR_SCENARIO_STEP = "acceptance framework scenario observes its world"
_AFR_SUPPORTED_STEP = "acceptance framework supported passing step"
_AFR_ATOMIC_STAGED_PATTERN = "acceptance framework staged replacement witness"
_AFR_PRIORITY_PATTERN = "acceptance framework priority witness"
_AFR_ENVIRONMENT_VARIABLE = "ACCEPTANCE_FRAMEWORK_REFACTOR_TEST"

_ISOLATION_STATE_STACK: list[dict[str, Any]] = []


def _restore_environment(saved: dict[str, str | None]) -> None:
    """Restore only the layout variables changed by a framework fixture."""
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _without_layout_overrides() -> dict[str, str | None]:
    """Temporarily select the repository-relative default layout."""
    saved = {name: os.environ.get(name) for name in _LAYOUT_ENVIRONMENT}
    for name in _LAYOUT_ENVIRONMENT:
        os.environ.pop(name, None)
    return saved


def _fixture_state() -> dict[str, Any]:
    if not _ISOLATION_STATE_STACK:
        raise RuntimeError("acceptance framework isolation state is not active")
    return _ISOLATION_STATE_STACK[-1]


def _feature_ir(
    *,
    name: str,
    steps: list[str],
    examples: list[dict[str, str]] | None = None,
    background: list[str] | None = None,
) -> dict[str, Any]:
    """Build the small JSON IR shape consumed by ``execute_ir``."""
    return {
        "name": name,
        "background": [
            {"keyword": "Given", "text": text} for text in (background or [])
        ],
        "scenarios": [
            {
                "name": name,
                "steps": [{"keyword": "Then", "text": text} for text in steps],
                "examples": examples or [],
            }
        ],
    }


def _write_ir(payload: dict[str, Any], directory: Path | None = None) -> Path:
    root = directory or Path(tempfile.mkdtemp(prefix="acceptance-framework-ir-"))
    root.mkdir(parents=True, exist_ok=True)
    path = root / "fixture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# AFR-01: artifact mapping -------------------------------------------------


def _h_afr_layout_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle the repo-relative layout precondition."""
    layout = snapshot_layout()
    values = (
        layout.features_dir,
        layout.ir_dir,
        layout.dry_dir,
        layout.generated_dir,
        layout.mutation_dir,
    )
    if any(Path(value).is_absolute() for value in values):
        return False, f"acceptance layout contains an absolute path: {values}"
    return True, ""


def _h_afr_artifact_paths(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Request the canonical paths while ignoring caller output overrides."""
    saved = _without_layout_overrides()
    try:
        world.afr_artifact_paths = artifact_paths("features/group/example.feature")
    finally:
        _restore_environment(saved)
    return True, ""


def _h_afr_artifact_path_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.fullmatch(r'the (IR|dry|test|metadata) path is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse artifact assertion: {text}"
    artifact, expected = match.groups()
    field = {
        "IR": "ir_path",
        "dry": "dry_path",
        "test": "test_path",
        "metadata": "metadata_path",
    }[artifact]
    actual = getattr(world.afr_artifact_paths, field, None)
    return actual == expected, f"Unexpected {artifact} path: {actual}"


# AFR-02: deterministic snapshot refresh ----------------------------------


def _h_afr_snapshot_project(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Create nested features and stale output in intentionally odd order."""
    root = Path(tempfile.mkdtemp(prefix="acceptance-framework-snapshot-"))
    (root / "pyproject.toml").write_text(
        '[project]\nname = "acceptance-framework-fixture"\n',
        encoding="utf-8",
    )
    features = root / "features"
    # Create zeta before alpha; discover_features must still return alpha first.
    (features / "zeta.feature").parent.mkdir(parents=True, exist_ok=True)
    (features / "zeta.feature").write_text(
        "Feature: Zeta\n  Scenario: Zeta scenario\n    Given a supported fixture\n",
        encoding="utf-8",
    )
    (features / "group").mkdir(parents=True)
    (features / "group" / "alpha.feature").write_text(
        "Feature: Alpha\n  Scenario: Alpha scenario\n    Given a supported fixture\n",
        encoding="utf-8",
    )

    build = root / "build" / "acceptance"
    (build / "ir").mkdir(parents=True)
    (build / "generated" / "metadata").mkdir(parents=True)
    (build / "ir" / "group").mkdir(parents=True)
    (build / "ir" / "group" / "stale.json").write_text("{}\n", encoding="utf-8")
    (build / "generated" / "stale_acceptance_test.py").write_text(
        "stale\n", encoding="utf-8"
    )
    (build / "generated" / "metadata" / "stale.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (build / "generated" / "unrelated.txt").write_text(
        "preserve me\n", encoding="utf-8"
    )
    world.afr_snapshot_root = root
    return True, ""


def _h_afr_snapshot_outputs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Refresh the fixture twice and retain the observed processing order."""
    import refresh_snapshot

    root = world.afr_snapshot_root
    saved = _without_layout_overrides()
    processed: list[str] = []
    original_run_tool = refresh_snapshot.run_tool

    def recording_run_tool(command: list[str], cwd: Path | None = None) -> int:
        if command and command[0] == "gherkin-parser":
            processed.append(Path(command[1]).relative_to(root).as_posix())
        return original_run_tool(command, cwd=cwd)

    refresh_snapshot.run_tool = recording_run_tool
    try:
        refresh_snapshot.refresh_snapshot(root)
        first = _afr_snapshot_bytes(root)
        processed_first = list(processed)
        processed.clear()
        refresh_snapshot.refresh_snapshot(root)
        second = _afr_snapshot_bytes(root)
        world.afr_snapshot_processed = processed_first
        world.afr_snapshot_processed_again = processed
        world.afr_snapshot_deterministic = first == second
    except Exception as exc:
        return False, f"snapshot refresh failed: {exc}"
    finally:
        refresh_snapshot.run_tool = original_run_tool
        _restore_environment(saved)
    return True, ""


def _afr_snapshot_bytes(root: Path) -> list[tuple[str, bytes]]:
    """Read only mapped snapshot files, excluding unrelated files."""
    saved = _without_layout_overrides()
    try:
        rows: list[tuple[str, bytes]] = []
        from snapshot import discover_features

        for feature in discover_features(root):
            paths = artifact_paths(feature)
            for relative in (
                paths.ir_path,
                paths.dry_path,
                paths.test_path,
                paths.metadata_path,
            ):
                path = root / relative
                rows.append((relative, path.read_bytes()))
        return rows
    finally:
        _restore_environment(saved)


def _h_afr_snapshot_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = ["features/group/alpha.feature", "features/zeta.feature"]
    actual = getattr(world, "afr_snapshot_processed", [])
    return actual == expected, f"Unexpected feature order: {actual}"


def _h_afr_snapshot_complete(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    root = world.afr_snapshot_root
    saved = _without_layout_overrides()
    try:
        from snapshot import discover_features

        for feature in discover_features(root):
            paths = artifact_paths(feature)
            for relative in (
                paths.ir_path,
                paths.dry_path,
                paths.test_path,
                paths.metadata_path,
            ):
                if not (root / relative).is_file():
                    return False, f"missing mapped artifact: {relative}"
    finally:
        _restore_environment(saved)
    return True, ""


def _h_afr_snapshot_metadata(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    root = world.afr_snapshot_root
    saved = _without_layout_overrides()
    try:
        from snapshot import discover_features

        for feature in discover_features(root):
            paths = artifact_paths(feature)
            metadata = json.loads((root / paths.metadata_path).read_text())
            if metadata.get("feature_path") != paths.feature_path:
                return False, f"incorrect feature metadata: {metadata}"
            if metadata.get("ir_path") != paths.ir_path:
                return False, f"incorrect IR metadata: {metadata}"
            if any(
                Path(str(metadata.get(field, ""))).is_absolute()
                for field in ("feature_path", "ir_path")
            ):
                return False, f"absolute metadata path: {metadata}"
    finally:
        _restore_environment(saved)
    return True, ""


def _h_afr_snapshot_stale(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = world.afr_snapshot_root
    stale = (
        root / "build" / "acceptance" / "ir" / "group" / "stale.json",
        root / "build" / "acceptance" / "generated" / "stale_acceptance_test.py",
        root / "build" / "acceptance" / "generated" / "metadata" / "stale.json",
    )
    missing = [str(path) for path in stale if path.exists()]
    return not missing, f"stale artifacts remain: {missing}"


def _h_afr_snapshot_unrelated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    path = (
        world.afr_snapshot_root / "build" / "acceptance" / "generated" / "unrelated.txt"
    )
    return path.is_file(), f"unrelated file was removed: {path}"


# AFR-03: atomic registry publication --------------------------------------


def _h_afr_registry_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import acceptance_runtime

    world.afr_registry_patterns = [
        (pattern.pattern, id(handler), tag)
        for pattern, handler, tag in acceptance_runtime.STEP_PATTERNS
    ]
    world.afr_registry_keys = set(acceptance_runtime._REGISTERED_PATTERN_KEYS)
    return bool(world.afr_registry_patterns), "the acceptance registry is empty"


def _h_afr_registry_replacement(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    import acceptance_runtime
    import runtime_manifest
    import runtime_shared

    def valid_register(api: Any) -> None:
        api.register(_AFR_ATOMIC_STAGED_PATTERN, _afr_noop_handler)

    def failing_register(api: Any) -> None:
        api.register(
            "acceptance framework failing replacement witness", _afr_noop_handler
        )
        raise ValueError("injected registration failure")

    valid = SimpleNamespace(FEATURE_ID="replacement-valid", register=valid_register)
    failing = SimpleNamespace(
        FEATURE_ID="replacement-failing", register=failing_register
    )
    original_load_modules = runtime_manifest.load_modules
    original_register_all = runtime_manifest.register_all
    before_patterns = list(acceptance_runtime.STEP_PATTERNS)
    before_keys = set(acceptance_runtime._REGISTERED_PATTERN_KEYS)

    def register_all(api: Any, modules: tuple[Any, ...] | None = None) -> None:
        selected = modules or (valid, failing)
        for module in selected:
            runtime_manifest._register_one(api, module.FEATURE_ID, module)

    runtime_manifest.load_modules = lambda: (valid, failing)
    runtime_manifest.register_all = register_all
    try:
        try:
            acceptance_runtime._load_feature_registry()
        except RuntimeError as exc:
            world.afr_registry_failure = str(exc)
        else:
            return False, "replacement registration unexpectedly succeeded"
        world.afr_registry_unchanged = (
            acceptance_runtime.STEP_PATTERNS == before_patterns
            and acceptance_runtime._REGISTERED_PATTERN_KEYS == before_keys
        )
        world.afr_staged_executable = any(
            pattern.pattern == _AFR_ATOMIC_STAGED_PATTERN
            for pattern, _, _ in acceptance_runtime.STEP_PATTERNS
        )
    finally:
        runtime_manifest.load_modules = original_load_modules
        runtime_manifest.register_all = original_register_all
    # Keep the imported module alive for environments that import it only via
    # the facade; this also documents the installation boundary.
    _ = runtime_shared
    return True, ""


def _h_afr_registry_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    failure = getattr(world, "afr_registry_failure", "")
    return (
        "replacement-failing" in failure,
        f"failure did not identify runtime feature: {failure}",
    )


def _h_afr_registry_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        bool(getattr(world, "afr_registry_unchanged", False)),
        "published registry changed after failed replacement",
    )


def _h_afr_registry_not_executable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        not bool(getattr(world, "afr_staged_executable", True)),
        "staged replacement pattern was published",
    )


def _afr_noop_handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


# AFR-04: scoped resolution -------------------------------------------------


def _h_afr_scoped_registry(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import acceptance_runtime

    counts = {"global": 0, "first": 0, "other": 0}

    def make_handler(name: str):
        def handler(inner_world: World, inner_text: str, inner_examples: dict):
            counts[name] += 1
            return True, ""

        return handler

    stage = acceptance_runtime._RegistrationStage()
    api = acceptance_runtime._RegistrationAPI(stage)
    api.register(_AFR_PRIORITY_PATTERN, make_handler("global"), source_order=30)
    api.set_feature("first-feature")
    api.register_first(_AFR_PRIORITY_PATTERN, make_handler("first"), source_order=10)
    api.set_feature("other-feature")
    api.register_first(_AFR_PRIORITY_PATTERN, make_handler("other"), source_order=20)
    api.set_feature(None)

    saved_patterns = list(acceptance_runtime.STEP_PATTERNS)
    saved_keys = set(acceptance_runtime._REGISTERED_PATTERN_KEYS)
    previous_feature = acceptance_runtime._CURRENT_EXECUTION_FEATURE
    try:
        acceptance_runtime._publish(stage)
        acceptance_runtime._CURRENT_EXECUTION_FEATURE = "first-feature"
        first_success, first_error = acceptance_runtime.execute_step(
            World(),
            {"keyword": "Given", "text": _AFR_PRIORITY_PATTERN},
            {},
        )
        acceptance_runtime._CURRENT_EXECUTION_FEATURE = None
        unscoped_success, unscoped_error = acceptance_runtime.execute_step(
            World(),
            {"keyword": "Given", "text": _AFR_PRIORITY_PATTERN},
            {},
        )
    finally:
        acceptance_runtime._CURRENT_EXECUTION_FEATURE = previous_feature
        acceptance_runtime.STEP_PATTERNS[:] = saved_patterns
        acceptance_runtime._REGISTERED_PATTERN_KEYS.clear()
        acceptance_runtime._REGISTERED_PATTERN_KEYS.update(saved_keys)

    world.afr_scope_counts = counts
    world.afr_scope_results = (
        first_success,
        first_error,
        unscoped_success,
        unscoped_error,
    )
    return True, ""


def _h_afr_other_scope_ineligible(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        world.afr_scope_counts["other"] == 0,
        f"other feature handler executed: {world.afr_scope_counts}",
    )


def _h_afr_first_scope_priority(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    counts = world.afr_scope_counts
    return (
        counts == {"global": 1, "first": 1, "other": 0},
        f"unexpected scoped resolution counts: {counts}",
    )


def _h_afr_unscoped_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    success, error = world.afr_scope_results[2:]
    counts = world.afr_scope_counts
    return (
        success and not error and counts == {"global": 1, "first": 1, "other": 0},
        f"unscoped resolution selected a scoped handler: {counts}, {error}",
    )


# AFR-05: scenario and process isolation ----------------------------------


def _h_afr_isolation_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"before it (passes|fails)$", text)
    if match is None:
        return False, f"Could not parse isolation result: {text}"
    state = {
        "requested_result": match.group(1),
        "original_environment": dict(os.environ),
        "before_feature": None,
        "observations": {},
    }
    _ISOLATION_STATE_STACK.append(state)
    world.afr_isolation_state = state
    return True, ""


def _h_afr_isolation_mutation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _fixture_state()
    row = examples.get("row", "")
    record = state["observations"].setdefault(row, {})
    record["mutation_world"] = getattr(world, "afr_world_token", None)
    if row == "first":
        world.afr_mutated = True
        os.environ[_AFR_ENVIRONMENT_VARIABLE] = "changed-by-first-example"
        record["changed_environment"] = True
    else:
        record["changed_environment"] = False
    return True, ""


def _h_afr_isolation_background(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _fixture_state()
    row = examples.get("row", "")
    record = state["observations"].setdefault(row, {})
    world.afr_world_token = object()
    record["background_world"] = world.afr_world_token
    record["background_environment"] = dict(os.environ)
    return True, ""


def _h_afr_isolation_scenario(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _fixture_state()
    row = examples.get("row", "")
    record = state["observations"].setdefault(row, {})
    record["scenario_world"] = getattr(world, "afr_world_token", None)
    record["scenario_environment"] = dict(os.environ)
    record["same_world"] = record.get("background_world") == record.get(
        "scenario_world"
    )
    if row == "first" and state["requested_result"] == "fails":
        return False, "injected first-example failure"
    return True, ""


def _h_afr_isolation_ir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import acceptance_runtime

    state = _fixture_state()
    state["before_feature"] = acceptance_runtime._CURRENT_EXECUTION_FEATURE
    root = Path(tempfile.mkdtemp(prefix="acceptance-refresh-nested-"))
    ir_path = root / "acceptance-refresh" / "nested.json"
    ir_path.parent.mkdir(parents=True)
    ir_path.write_text(
        json.dumps(
            _feature_ir(
                name="nested isolation",
                background=[_AFR_BACKGROUND_STEP],
                steps=[_AFR_MUTATION_STEP, _AFR_SCENARIO_STEP],
                examples=[{"row": "first"}, {"row": "second"}],
            )
        ),
        encoding="utf-8",
    )
    try:
        state["result"], state["output"] = acceptance_runtime.execute_ir(str(ir_path))
        state["after_environment"] = dict(os.environ)
        state["after_feature"] = acceptance_runtime._CURRENT_EXECUTION_FEATURE
    finally:
        _ISOLATION_STATE_STACK.pop()
    world.afr_isolation_observations = state["observations"]
    world.afr_isolation_state = state
    return True, ""


def _h_afr_isolation_observers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = world.afr_isolation_state
    observations = state["observations"]
    first = observations.get("first", {})
    second = observations.get("second", {})
    original = state["original_environment"]
    if not second.get("same_world"):
        return False, f"second example did not share its world: {observations}"
    if first.get("background_world") == second.get("background_world"):
        return False, f"examples reused a world: {observations}"
    if second.get("background_environment") != original:
        return False, "second example inherited process environment changes"
    if second.get("scenario_environment") != original:
        return False, "second scenario inherited process environment changes"
    if state.get("requested_result") == "passes" and not first.get("same_world"):
        return False, f"passing example did not share its world: {observations}"
    return True, ""


def _h_afr_isolation_environment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = world.afr_isolation_state
    return (
        state.get("after_environment") == state.get("original_environment"),
        "process environment was not restored after IR execution",
    )


def _h_afr_isolation_feature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = world.afr_isolation_state
    return (
        state.get("after_feature") == state.get("before_feature"),
        "enclosing feature context was not restored",
    )


# AFR-06: execution outcomes ----------------------------------------------


def _h_afr_contract_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r'an isolated IR scenario named "contract" has the (.+)', text)
    if match is None:
        return False, f"Could not parse contract condition: {text}"
    world.afr_contract_condition = match.group(1)
    return True, ""


def _h_afr_contract_supported(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_afr_contract_execute(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    import acceptance_runtime

    condition = world.afr_contract_condition
    if condition == "supported passing step":
        steps = [_AFR_SUPPORTED_STEP]
    elif condition == "exact live-LLM marker":
        steps = [LIVE_LLM_ACCEPTANCE_MARKER]
    else:
        steps = ["acceptance framework unsupported contract step"]
    ir_path = _write_ir(_feature_ir(name="contract", steps=steps))
    saved = os.environ.pop("SCENARIO_FORGE_QA_PIPELINE", None)
    try:
        world.afr_contract_result, world.afr_contract_output = (
            acceptance_runtime.execute_ir(str(ir_path))
        )
    finally:
        if saved is not None:
            os.environ["SCENARIO_FORGE_QA_PIPELINE"] = saved
    return True, ""


def _h_afr_contract_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r"its result is (true|false)", text.strip(), re.IGNORECASE)
    if match is None:
        return False, f"Could not parse contract result: {text}"
    expected = match.group(1).casefold() == "true"
    actual = bool(world.afr_contract_result)
    return actual == expected, f"expected result {expected}, got {actual}"


def _h_afr_contract_output(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r'its output begins with "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse output assertion: {text}"
    expected = match.group(1)
    actual = (
        world.afr_contract_output.splitlines()[0] if world.afr_contract_output else ""
    )
    return actual.startswith(expected), f"unexpected output: {actual}"


# AFR-07: namespaced manifest ---------------------------------------------


class _CountingAPI:
    """Minimal API used to count each manifest module invocation."""

    def __init__(self) -> None:
        self.calls: dict[str, int] = {}
        self.current_feature: str | None = None

    def set_feature(self, tag: str | None) -> None:
        self.current_feature = tag

    def register(
        self, pattern: str, handler: Any, *, source_order: int | None = None
    ) -> None:
        return None

    def register_first(
        self, pattern: str, handler: Any, *, source_order: int | None = None
    ) -> None:
        return None


def _h_afr_manifest_root(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return Path.cwd() == PROJECT_ROOT, f"unexpected project root: {Path.cwd()}"


def _h_afr_manifest_load(world: World, text: str, examples: dict) -> tuple[bool, str]:
    manifest = importlib.import_module("acceptance.runtime_manifest")
    modules = manifest.load_modules()
    world.afr_manifest = manifest
    world.afr_manifest_modules = modules
    return True, ""


def _h_afr_manifest_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    actual = tuple(module.FEATURE_ID for module in world.afr_manifest_modules)
    expected = tuple(world.afr_manifest.MODULES)
    return actual == expected, f"manifest order changed: {actual}"


def _h_afr_manifest_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    invalid = [
        (name, getattr(module, "FEATURE_ID", None))
        for name, module in zip(world.afr_manifest.MODULES, world.afr_manifest_modules)
        if getattr(module, "FEATURE_ID", None) != name
    ]
    return not invalid, f"invalid feature identities: {invalid}"


def _h_afr_manifest_register(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    class Proxy:
        def __init__(self, module: Any, calls: dict[str, int]) -> None:
            self.FEATURE_ID = module.FEATURE_ID
            self._module = module
            self._calls = calls

        def register(self, api: Any) -> None:
            self._calls[self.FEATURE_ID] = self._calls.get(self.FEATURE_ID, 0) + 1
            self._module.register(api)

    calls: dict[str, int] = {}
    proxies = tuple(Proxy(module, calls) for module in world.afr_manifest_modules)
    api = _CountingAPI()
    world.afr_manifest.register_all(api, proxies)
    world.afr_manifest_calls = calls
    return True, ""


def _h_afr_manifest_exactly_once(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    expected = set(world.afr_manifest.MODULES)
    actual = world.afr_manifest_calls
    return (
        set(actual) == expected and all(count == 1 for count in actual.values()),
        f"manifest registration counts were not exactly once: {actual}",
    )


# AFR-08: mutation runner outcomes ----------------------------------------


def _h_afr_runner_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(
        r' the mutation worker receives job "job-1" for an IR runtime that (.+)',
        text,
    )
    if match is None:
        match = re.fullmatch(
            r'the mutation worker receives job "job-1" for an IR runtime that (.+)',
            text,
        )
    if match is None:
        return False, f"Could not parse runner condition: {text}"
    world.afr_runner_condition = match.group(1)
    return True, ""


def _h_afr_runner_execute(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import runner_adapter

    condition = world.afr_runner_condition

    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        if condition == "exits with status 0":
            return SimpleNamespace(returncode=0, stdout="stdout", stderr="stderr")
        if condition == "exits with status 1":
            return SimpleNamespace(returncode=1, stdout="stdout", stderr="stderr")
        if condition == "exits with another status":
            return SimpleNamespace(returncode=2, stdout="stdout", stderr="stderr")
        if condition == "exceeds its requested timeout":
            raise subprocess.TimeoutExpired("runtime", 1)
        raise RuntimeError("injected worker execution exception")

    original_run = runner_adapter.subprocess.run
    runner_adapter.subprocess.run = fake_run
    try:
        world.afr_runner_response = runner_adapter.run_job(
            {
                "id": "job-1",
                "feature_json": "fixture.json",
                "timeout": "1s",
            }
        )
    finally:
        runner_adapter.subprocess.run = original_run
    return True, ""


def _h_afr_runner_id(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.afr_runner_response.get("id") == "job-1",
        f"unexpected runner id: {world.afr_runner_response}",
    )


def _h_afr_runner_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(r'the response outcome is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse runner outcome: {text}"
    expected = match.group(1)
    actual = world.afr_runner_response.get("outcome")
    return actual == expected, f"unexpected outcome: {actual}"


def _h_afr_runner_duration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    duration = world.afr_runner_response.get("duration")
    return (
        type(duration) is int and duration >= 0,
        f"invalid duration: {duration!r}",
    )


def _h_afr_runner_streams(world: World, text: str, examples: dict) -> tuple[bool, str]:
    response = world.afr_runner_response
    return (
        isinstance(response.get("output"), str)
        and isinstance(response.get("error"), str)
        and response["output"] != response["error"],
        f"runner streams were conflated: {response}",
    )


# AFR-09: persistent JSON-lines protocol ----------------------------------


def _h_afr_worker_ready(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.afr_worker_ready = True
    return True, ""


def _h_afr_worker_protocol(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = Path(tempfile.mkdtemp(prefix="acceptance-framework-worker-"))
    ir_path = _write_ir(_feature_ir(name="worker-valid", steps=[]), root)
    command = [sys.executable, str(PROJECT_ROOT / "acceptance" / "runner_adapter.py")]
    process = subprocess.Popen(
        command,
        cwd=str(PROJECT_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready = process.stderr.readline() if process.stderr else ""
        if ready.strip() != "runner_adapter: ready":
            return False, f"runner did not announce readiness: {ready!r}"
        if process.stdin is None:
            return False, "runner stdin was unavailable"
        process.stdin.write(
            "not-json\n"
            + json.dumps(
                {
                    "id": "job-valid",
                    "feature_json": str(ir_path),
                    "timeout": "30s",
                }
            )
            + "\n"
        )
        process.stdin.close()
        stdout = process.stdout.read() if process.stdout else ""
        stderr = process.stderr.read() if process.stderr else ""
        return_code = process.wait(timeout=60)
    except Exception as exc:
        process.kill()
        process.wait()
        return False, f"mutation worker protocol failed: {exc}"

    world.afr_worker_ready_line = ready.strip()
    world.afr_worker_stdout_lines = stdout.splitlines()
    world.afr_worker_stderr = ready + stderr
    world.afr_worker_return_code = return_code
    try:
        world.afr_worker_responses = [
            json.loads(line) for line in world.afr_worker_stdout_lines
        ]
    except json.JSONDecodeError as exc:
        world.afr_worker_responses = []
        return False, f"worker emitted non-JSON output: {exc}"
    return True, ""


def _h_afr_worker_malformed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    responses = world.afr_worker_responses
    matches = [
        response
        for response in responses
        if response.get("id") == "unknown"
        and response.get("outcome") == "infrastructure_error"
    ]
    return len(matches) == 1, f"malformed request response missing: {responses}"


def _h_afr_worker_continues(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    responses = world.afr_worker_responses
    valid = [response for response in responses if response.get("id") == "job-valid"]
    return len(responses) == 2 and len(valid) == 1, f"worker stopped early: {responses}"


def _h_afr_worker_json_lines(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        all(isinstance(response, dict) for response in world.afr_worker_responses)
        and world.afr_worker_return_code == 0,
        f"invalid worker protocol output: {world.afr_worker_responses}",
    )


def register(api: object) -> None:
    """Register framework-contract steps through the supplied facade API."""
    api.set_feature(None)

    # Mapping and deterministic snapshot refresh.
    api.register_first(
        r"^acceptance directories are configured as repo-relative paths$",
        _h_afr_layout_given,
    )
    api.register_first(
        r'^artifact paths are requested for "features/group/example\.feature"$',
        _h_afr_artifact_paths,
    )
    api.register_first(
        r'^the (IR|dry|test|metadata) path is "([^"]+)"$',
        _h_afr_artifact_path_assertion,
    )
    api.register_first(
        r"^a temporary project has nested source features in unsorted creation order$",
        _h_afr_snapshot_project,
    )
    api.register_first(
        r"^its configured output trees contain stale generated artifacts and an unrelated file$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^the acceptance snapshot is refreshed$",
        _h_afr_snapshot_outputs,
    )
    api.register_first(
        r"^source features are processed in lexicographic repo-relative order$",
        _h_afr_snapshot_order,
    )
    api.register_first(
        r"^each source feature has one mapped IR, dry report, generated test, and metadata file$",
        _h_afr_snapshot_complete,
    )
    api.register_first(
        r"^generated metadata contains only repo-relative source and IR paths$",
        _h_afr_snapshot_metadata,
    )
    api.register_first(
        r"^stale mapped IR, generated test, and metadata files are removed$",
        _h_afr_snapshot_stale,
    )
    api.register_first(
        r"^the unrelated file is preserved$",
        _h_afr_snapshot_unrelated,
    )

    # Registry staging/publication and feature-scoped resolution.
    api.register_first(
        r"^an acceptance registry has already published a valid pattern and key set$",
        _h_afr_registry_given,
    )
    api.register_first(
        r"^a replacement manifest stages one valid module before a module whose registration fails$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^the replacement manifest is registered$",
        _h_afr_registry_replacement,
    )
    api.register_first(
        r"^the failure identifies the failing runtime feature$",
        _h_afr_registry_failure,
    )
    api.register_first(
        r"^the previously published pattern and key set remain unchanged$",
        _h_afr_registry_unchanged,
    )
    api.register_first(
        r"^no staged replacement pattern is executable$",
        _h_afr_registry_not_executable,
    )
    api.register_first(
        r"^one step text matches a global pattern and patterns scoped to two different features$",
        _h_afr_scoped_registry,
    )
    api.register_first(
        r"^the step executes for the first feature$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^patterns scoped to the other feature are ineligible$",
        _h_afr_other_scope_ineligible,
    )
    api.register_first(
        r"^the first eligible pattern in deterministic registration priority executes exactly once$",
        _h_afr_first_scope_priority,
    )
    api.register_first(
        r"^executing an unscoped feature cannot select either feature-scoped pattern$",
        _h_afr_unscoped_scope,
    )

    # Scenario/example lifecycle and result reporting.
    api.register_first(
        r"^an IR scenario has two examples and an original process environment$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^the first example changes its world state and process environment before it (passes|fails)$",
        _h_afr_isolation_given,
    )
    api.register_first(
        r"^the IR is executed for a nested feature context$",
        _h_afr_isolation_ir,
    )
    api.register_first(
        rf"^{re.escape(_AFR_BACKGROUND_STEP)}$",
        _h_afr_isolation_background,
    )
    api.register_first(
        rf"^{re.escape(_AFR_MUTATION_STEP)}$",
        _h_afr_isolation_mutation,
    )
    api.register_first(
        rf"^{re.escape(_AFR_SCENARIO_STEP)}$",
        _h_afr_isolation_scenario,
    )
    api.register_first(
        r"^the second example receives a fresh world and the original process environment$",
        _h_afr_isolation_observers,
    )
    api.register_first(
        r"^each example shares one world between its own background and scenario steps$",
        _h_afr_isolation_observers,
    )
    api.register_first(
        r"^the process environment is restored after the IR execution$",
        _h_afr_isolation_environment,
    )
    api.register_first(
        r"^the enclosing feature context is restored after the IR execution$",
        _h_afr_isolation_feature,
    )
    api.register_first(
        r'^an isolated IR scenario named "contract" has the (.+)$',
        _h_afr_contract_given,
    )
    api.register_first(
        rf"^{re.escape(_AFR_SUPPORTED_STEP)}$",
        _h_afr_contract_supported,
    )
    api.register_first(
        r"^the isolated IR is executed without live-LLM authorization$",
        _h_afr_contract_execute,
    )
    api.register_first(
        r"^its result is (true|false)$",
        _h_afr_contract_result,
    )
    api.register_first(
        r'^its output begins with "([^"]+)"$',
        _h_afr_contract_output,
    )

    # Namespaced manifest loading.
    api.register_first(
        r"^the project root is the current working directory$",
        _h_afr_manifest_root,
    )
    api.register_first(
        r'^the runtime manifest is loaded through the "acceptance\.runtime_manifest" namespace$',
        _h_afr_manifest_load,
    )
    api.register_first(
        r"^every declared runtime feature loads in manifest order$",
        _h_afr_manifest_order,
    )
    api.register_first(
        r"^every loaded feature identity matches its declared name$",
        _h_afr_manifest_identity,
    )
    api.register_first(
        r"^every loaded feature exposes a registration operation$",
        lambda world, text, examples: (
            all(
                callable(getattr(module, "register", None))
                for module in world.afr_manifest_modules
            ),
            "a manifest feature has no registration operation",
        ),
    )
    api.register_first(
        r"^the complete manifest registers each feature exactly once$",
        _h_afr_manifest_register,
    )

    # Mutation runner outcome mapping and persistent protocol.
    api.register_first(
        r'^the mutation worker receives job "job-1" for an IR runtime that (.+)$',
        _h_afr_runner_given,
    )
    api.register_first(
        r"^the worker emits the job response$",
        _h_afr_runner_execute,
    )
    api.register_first(
        r'^the response id is "job-1"$',
        _h_afr_runner_id,
    )
    api.register_first(
        r'^the response outcome is "([^"]+)"$',
        _h_afr_runner_outcome,
    )
    api.register_first(
        r"^the response duration is a non-negative integer of nanoseconds$",
        _h_afr_runner_duration,
    )
    api.register_first(
        r"^standard output and standard error are returned in separate fields$",
        _h_afr_runner_streams,
    )
    api.register_first(
        r"^the persistent mutation worker is ready$",
        _h_afr_worker_ready,
    )
    api.register_first(
        r"^it receives a malformed JSON line followed by a valid job line$",
        _h_afr_worker_protocol,
    )
    api.register_first(
        r'^it emits one infrastructure_error response with id "unknown" for the malformed line$',
        _h_afr_worker_malformed,
    )
    api.register_first(
        r"^it remains running to emit one response for the valid job$",
        _h_afr_worker_continues,
    )
    api.register_first(
        r"^every response is one JSON object on one standard-output line$",
        _h_afr_worker_json_lines,
    )


__all__ = ["FEATURE_ID", "register"]
