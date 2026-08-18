from __future__ import annotations

import ast
import importlib
import os
import sys
from pathlib import Path

from hypothesis import given, strategies as st


_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))
sys.path.insert(0, str(_PROJECT_ROOT))

from acceptance_runtime import _derive_feature_tag  # noqa: E402
from registry import (  # noqa: E402
    PatternRegistry,
    RegistrationAPI,
    RegistrationStage,
)
from runtime_features import phase4_qa_refresh_migration  # noqa: E402
from runtime_features import phase4_qa_refresh_migration_scope as phase4_scope  # noqa: E402
from runtime_features.acceptance_qa_runtime_cleanup import (  # noqa: E402
    register as register_aqrc,
)
from runtime_features.phase4_qa_refresh_migration_support import (  # noqa: E402
    _ENDPOINT_VARIABLES,
    _finish_sentinel,
    _start_sentinel,
)

_PHASE4_ID = "phase4_qa_refresh_migration"
_PHASE4_MODULES = (
    "phase4_qa_refresh_migration",
    "phase4_qa_refresh_migration_cli",
    "phase4_qa_refresh_migration_generated",
    "phase4_qa_refresh_migration_isolation",
    "phase4_qa_refresh_migration_process",
    "phase4_qa_refresh_migration_scope",
    "phase4_qa_refresh_migration_support",
)
_OVERLAPPING_STEPS = (
    "the parent environment and working directory remain unchanged",
    'the acceptance-refresh source feature "acceptance-refresh/stage1b-grounding.feature" is generated',
    'no production path beneath "src/" is added, modified, or deleted',
)


def test_phase4_handlers_register_each_feature_step_once():
    stage = RegistrationStage()
    phase4_qa_refresh_migration.register(RegistrationAPI(stage))

    patterns = [entry[3] for entry in stage.entries]

    assert phase4_qa_refresh_migration.FEATURE_ID == "phase4_qa_refresh_migration"
    assert len(patterns) == len(set(patterns))
    assert all(
        expected in patterns
        for expected in (
            r'the Phase 4 migration baseline is commit "([^"]+)"',
            "live endpoint opt-in is unset",
            "acceptance-refresh QA help is requested",
            r'help advertises option "([^"]+)"',
            "the migrated suite and generated Phase 4 acceptance test are run",
        )
    )
    assert stage.feature is None


def test_phase4_sentinel_restores_endpoint_environment(monkeypatch):
    original = {name: f"original-{name.lower()}" for name in _ENDPOINT_VARIABLES}
    missing = _ENDPOINT_VARIABLES[-1]
    for name, value in original.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)
    original[missing] = None

    world = type("World", (), {})()
    _start_sentinel(world)
    assert world.p4qrm_endpoint_environment == original

    _finish_sentinel(world)

    assert all(os.environ.get(name) == value for name, value in original.items())
    assert world.p4qrm_endpoint_environment is None


def test_phase4_existing_suite_check_ignores_new_qa_executable(monkeypatch):
    expected = "acceptance/qa/acceptance-refresh/qa_suite.py"
    added = "acceptance/qa/phase4-qa-refresh-migration/qa_suite.py"
    world = type(
        "World",
        (),
        {"p4qrm_qa_changes": [expected, added]},
    )()
    monkeypatch.setattr(
        phase4_scope,
        "_git_tree_paths",
        lambda _root: [expected],
    )

    passed, detail = phase4_scope._h_only_refresh_suite(world, "", {})

    assert passed, detail


def _imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def _phase4_stage() -> RegistrationStage:
    stage = RegistrationStage()
    phase4_qa_refresh_migration.register(RegistrationAPI(stage))
    return stage


def test_phase4_handlers_are_scoped_to_one_feature_identity():
    stage = _phase4_stage()
    scopes = {entry[5] for entry in stage.entries}
    first_patterns = {entry[3] for entry in stage.entries if entry[2]}

    assert scopes == {_PHASE4_ID, None}
    assert first_patterns == {
        r"^the parent environment and working directory remain unchanged$",
        r'^the acceptance-refresh source feature "([^"]+)" is generated$',
        r'^no production path beneath "src/" is added, modified, or deleted$',
    }
    assert all(entry[5] == _PHASE4_ID for entry in stage.entries if entry[2])
    assert stage.feature is None


def _published_overlap_registry() -> PatternRegistry:
    stage = RegistrationStage()
    api = RegistrationAPI(stage)
    register_aqrc(api)
    phase4_qa_refresh_migration.register(api)
    registry = PatternRegistry()
    registry.publish(stage)
    return registry


def test_phase4_overlap_does_not_steal_cleanup_handlers():
    registry = _published_overlap_registry()
    parent_text = "the parent environment and working directory remain unchanged"
    source_text = (
        "the acceptance-refresh source feature "
        '"acceptance-refresh/stage1b-grounding.feature" is generated'
    )
    src_text = 'no production path beneath "src/" is added, modified, or deleted'

    assert registry.resolve(parent_text).__name__ == "_h_aqrc_parent_unchanged"
    assert registry.resolve(parent_text, _PHASE4_ID).__name__ == "_h_parent_unchanged"
    assert registry.resolve(source_text).__name__ == "_h_aqrc_source_generated"
    assert registry.resolve(source_text, _PHASE4_ID).__name__ == "_h_source_generated"
    assert registry.resolve(src_text).__name__ == "_h_aqrc_scope_and_config"
    assert registry.resolve(src_text, _PHASE4_ID).__name__ == "_h_no_src_changes"


@given(st.sampled_from(_OVERLAPPING_STEPS))
def test_phase4_overlap_resolution_is_feature_scoped(text: str):
    registry = _published_overlap_registry()
    unscoped = registry.resolve(text)
    scoped = registry.resolve(text, _PHASE4_ID)
    assert unscoped is not None and scoped is not None
    assert unscoped is not scoped
    assert unscoped.__name__.startswith("_h_aqrc_")
    assert not scoped.__name__.startswith("_h_aqrc_")


def test_phase4_feature_tag_is_derived_from_generated_ir_path():
    assert (
        _derive_feature_tag("build/acceptance/ir/phase4_qa_refresh_migration.json")
        == _PHASE4_ID
    )
    assert (
        _derive_feature_tag("build/acceptance/ir/acceptance_qa_runtime_cleanup.json")
        is None
    )
    assert _derive_feature_tag("foundation_test.json") is None


def test_phase4_helpers_do_not_import_qa_only_modules():
    forbidden = (
        "qa_harness",
        "acceptance.qa",
        "acceptance_qa_runtime_cleanup",
        "acceptance_qa_runtime_cleanup_checks",
        "acceptance_qa_runtime_cleanup_harness",
    )
    for name in _PHASE4_MODULES:
        imports = _imported_modules(
            _PROJECT_ROOT / "acceptance" / "runtime_features" / f"{name}.py"
        )
        assert all(
            imported != banned and not imported.startswith(f"{banned}.")
            for imported in imports
            for banned in forbidden
        ), name


def test_phase4_modules_import_from_top_level_and_namespace():
    top_level = importlib.import_module("runtime_features.phase4_qa_refresh_migration")
    namespaced = importlib.import_module(
        "acceptance.runtime_features.phase4_qa_refresh_migration"
    )
    support_top = importlib.import_module(
        "runtime_features.phase4_qa_refresh_migration_support"
    )
    support_ns = importlib.import_module(
        "acceptance.runtime_features.phase4_qa_refresh_migration_support"
    )

    assert top_level.FEATURE_ID == _PHASE4_ID
    assert namespaced.FEATURE_ID == _PHASE4_ID
    assert callable(top_level.register)
    assert callable(namespaced.register)
    assert support_top._generated_test_path("phase4.feature").name.endswith(
        "_acceptance_test.py"
    )
    assert support_ns._generated_test_path is support_top._generated_test_path or (
        support_ns._generated_test_path("phase4.feature")
        == support_top._generated_test_path("phase4.feature")
    )
