"""Stable facade for the acceptance runtime registry and executor."""

from __future__ import annotations

import json
import re
import sys
import traceback
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from runtime_features.sp1_revision import _h_rev_revision_run as _retained_rev_revision_run
from runtime_shared import (
    World,
    _GDStageError,
    _h_sp1_rev_run as _retained_sp1_rev_run,
    _resolve_value,
)

STEP_PATTERNS: list[tuple[re.Pattern, Any, str | None]] = []
_CURRENT_REGISTRATION_FEATURE: str | None = None
_CURRENT_EXECUTION_FEATURE: str | None = None
_REGISTERED_PATTERN_KEYS: set[tuple[str, str, str | None]] = set()

def _set_feature(tag: str | None) -> None:
    """Set the feature tag for subsequent _register_first calls."""
    global _CURRENT_REGISTRATION_FEATURE
    _CURRENT_REGISTRATION_FEATURE = tag

def _track_registration(pattern: str, handler: Any, feature_tag: str | None) -> None:
    """Record a registration and assert no exact duplicate exists.

    Catches the most obvious shadowing bug: the same pattern string
    registered twice with the same handler in the same scope.  A different
    handler with the same pattern is a more subtle shadowing bug that is
    detected at test time by ``find_pattern_conflicts`` rather than at
    registration time, to avoid breaking pre-existing registrations that
    predate this integrity check.
    """
    handler_name = getattr(handler, "__name__", repr(handler))
    key = (pattern, handler_name, feature_tag)
    if key in _REGISTERED_PATTERN_KEYS:
        scope = f"feature {feature_tag!r}" if feature_tag else "global scope"
        raise RuntimeError(
            f"Duplicate step pattern registration in {scope}: "
            f"{pattern!r} (handler {handler_name}) — "
            f"second registration is redundant"
        )
    _REGISTERED_PATTERN_KEYS.add(key)

def _register(pattern: str, handler: Any) -> None:
    _track_registration(pattern, handler, None)
    STEP_PATTERNS.append((re.compile(pattern, re.IGNORECASE), handler, None))

def _register_first(pattern: str, handler: Any) -> None:
    """Register a pattern at the front of the list (higher priority).

    The pattern is tagged with the current registration feature (set via
    _set_feature). During execution, tagged patterns only match when the
    current IR file's feature matches, preventing cross-feature hijacking.
    """
    _track_registration(pattern, handler, _CURRENT_REGISTRATION_FEATURE)
    STEP_PATTERNS.insert(
        0,
        (re.compile(pattern, re.IGNORECASE), handler, _CURRENT_REGISTRATION_FEATURE),
    )

def find_pattern_conflicts(
    step_texts: list[str],
) -> list[tuple[str, str, str]]:
    """Return same-scope conflicts from duplicate raw pattern registrations.

    A conflict is two registrations with identical ``pattern`` strings but
    different handlers in the same global or feature-tag scope.  Broad and
    specific regular expressions may intentionally overlap and are not a
    conflict.  The returned tuple keeps the existing
    ``(step_text, first_pattern, second_pattern)`` shape: when supplied,
    ``step_texts`` contributes the first witness matching the duplicate
    pattern.  A deterministic sentinel is used when no witness is supplied.
    """
    scoped_patterns: dict[str | None, dict[str, list[tuple[Any, Any]]]] = {}
    for pattern, handler, tag in STEP_PATTERNS:
        scoped_patterns.setdefault(tag, {}).setdefault(pattern.pattern, []).append(
            (pattern, handler)
        )

    conflicts: list[tuple[str, str, str]] = []
    for patterns_by_raw_pattern in scoped_patterns.values():
        for raw_pattern, registrations in patterns_by_raw_pattern.items():
            distinct_handlers: list[tuple[Any, Any]] = []
            for compiled_pattern, handler in registrations:
                if not any(
                    existing_handler is handler
                    for _, existing_handler in distinct_handlers
                ):
                    distinct_handlers.append((compiled_pattern, handler))
            if len(distinct_handlers) < 2:
                continue

            witness = next(
                (
                    text
                    for text in step_texts
                    if distinct_handlers[0][0].search(text)
                ),
                "<no supplied witness>",
            )
            conflicts.append((witness, raw_pattern, raw_pattern))
    return conflicts

class _RegistrationStage:
    """Private transaction buffer used before publishing the registry."""

    def __init__(self) -> None:
        self.entries: list[tuple[int, int, bool, str, Any, str | None]] = []
        self.keys: set[tuple[str, str, str | None]] = set()
        self.feature: str | None = None
        self._sequence = 0

    def add(self, pattern: str, handler: Any, first: bool, source_order: int | None) -> None:
        tag = self.feature if first else None
        handler_name = getattr(handler, "__name__", repr(handler))
        key = (pattern, handler_name, tag)
        if key in self.keys:
            scope = f"feature {tag!r}" if tag else "global scope"
            raise RuntimeError(
                f"Duplicate step pattern registration in {scope}: "
                f"{pattern!r} (handler {handler_name}) — second registration is redundant"
            )
        self.keys.add(key)
        order = source_order if source_order is not None else self._sequence
        self.entries.append((order, self._sequence, first, pattern, handler, tag))
        self._sequence += 1

class _RegistrationAPI:
    """Explicit feature-module registration API backed by one stage."""

    def __init__(self, stage: _RegistrationStage) -> None:
        self._stage = stage
        self.bindings: dict[str, Any] = {
            "STEP_PATTERNS": STEP_PATTERNS,
            "_REGISTERED_PATTERN_KEYS": _REGISTERED_PATTERN_KEYS,
            "_register": _register,
            "_register_first": _register_first,
            "_set_feature": _set_feature,
            "_track_registration": _track_registration,
            "find_pattern_conflicts": find_pattern_conflicts,
        }

    def set_feature(self, tag: str | None) -> None:
        self._stage.feature = tag

    def register(self, pattern: str, handler: Any, *, source_order: int | None = None) -> None:
        self._stage.add(pattern, handler, False, source_order)

    def register_first(self, pattern: str, handler: Any, *, source_order: int | None = None) -> None:
        self._stage.add(pattern, handler, True, source_order)

    def install_handlers(self, namespaces: list[dict[str, Any]]) -> None:
        for namespace in namespaces:
            self.bindings.update({name: value for name, value in namespace.items() if name.startswith("_h_")})
        for namespace in namespaces:
            namespace.update(self.bindings)

def _publish(stage: _RegistrationStage) -> None:
    patterns: list[tuple[re.Pattern, Any, str | None]] = []
    for _, _, first, raw_pattern, handler, tag in sorted(stage.entries, key=lambda entry: (entry[0], entry[1])):
        value = (re.compile(raw_pattern, re.IGNORECASE), handler, tag)
        if first:
            patterns.insert(0, value)
        else:
            patterns.append(value)
    STEP_PATTERNS[:] = patterns
    _REGISTERED_PATTERN_KEYS.clear()
    _REGISTERED_PATTERN_KEYS.update(stage.keys)

def _load_feature_registry() -> None:
    """Validate, stage, and atomically publish all feature registrations."""
    import runtime_manifest
    stage = _RegistrationStage()
    api = _RegistrationAPI(stage)
    modules = runtime_manifest.load_modules()
    import runtime_shared
    api.install_handlers([runtime_shared.__dict__, *[module.__dict__ for module in modules]])
    runtime_manifest.register_all(api, modules)
    _publish(stage)

def execute_step(world: World, step: dict, examples: dict) -> tuple[bool, str]:
    """Execute a single step against the world.

    If a handler raises ValidationError or ValueError during model
    construction, the error is stored in world.validation_error and
    the step is considered successful (the error is an expected outcome
    that will be checked by a subsequent 'Then' step).
    """
    keyword = step.get("keyword", "")
    raw_text = step.get("text", "")
    text = _resolve_value(raw_text, examples)
    # Store data table (if any) in world so handlers can access it
    world.current_data_table = step.get("data_table")

    try:
        for pattern, handler, feature_tag in STEP_PATTERNS:
            # Skip patterns tagged for a different feature than the one
            # currently executing. Untagged patterns (feature_tag is None)
            # are global and always match.
            if feature_tag is not None and feature_tag != _CURRENT_EXECUTION_FEATURE:
                continue
            if pattern.search(text):
                return handler(world, text, examples)

        return False, f"Unsupported step: {keyword} {text}"
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
        return True, ""

def _derive_feature_tag(ir_path: str) -> str | None:
    """Derive a feature tag from the IR filename.

    Returns a feature tag for sub-project-specific IR files, or None for
    foundation/boundary/SP1 features whose handlers should remain global.

    Currently only SP2 is feature-tagged. Add future sub-projects here:
        if stem.startswith("sp3_"): return "sp3"
    """
    stem = Path(ir_path).stem
    if "acceptance-refresh" in Path(ir_path).parts:
        return "acceptance_refresh"
    if "shadow-cleanup" in Path(ir_path).parts:
        return "shadow_cleanup"
    if stem.startswith("sp2_"):
        return "sp2"
    if stem.startswith("sp3_"):
        return "sp3"
    if stem.startswith("stpa_report"):
        return "stpa_report"
    if stem.startswith("stage6_"):
        return "sp3"
    return None

def execute_ir(ir_path: str) -> tuple[bool, str]:
    """Execute all scenarios in a JSON IR file.

    Returns (all_passed, output).
    """
    global _CURRENT_EXECUTION_FEATURE
    _CURRENT_EXECUTION_FEATURE = _derive_feature_tag(ir_path)

    with open(ir_path) as f:
        ir = json.load(f)

    background_steps = ir.get("background", [])
    scenarios = ir.get("scenarios", [])

    output_lines: list[str] = []
    all_passed = True

    for s_idx, scenario in enumerate(scenarios):
        scenario_name = scenario.get("name", f"scenario_{s_idx}")
        steps = scenario.get("steps", [])
        examples = scenario.get("examples", [])

        if not examples:
            examples = [{}]

        for e_idx, example in enumerate(examples):
            exec_name = f"{scenario_name}/example_{e_idx + 1}"
            world = World()

            # Execute background steps
            for bg_step in background_steps:
                success, error = execute_step(world, bg_step, example)
                if not success:
                    output_lines.append(f"FAIL {exec_name}: background step failed: {error}")
                    all_passed = False
                    break
            else:
                # Execute scenario steps
                for step in steps:
                    success, error = execute_step(world, step, example)
                    if not success:
                        output_lines.append(f"FAIL {exec_name}: {error}")
                        all_passed = False
                        break
                else:
                    output_lines.append(f"PASS {exec_name}")

    return all_passed, "\n".join(output_lines)

_load_feature_registry()

def _h_rev_revision_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Delegate the retained revision handler through the stable facade."""
    return _retained_rev_revision_run(world, text, examples)

def _h_sp1_rev_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Delegate the retained SP1 revision helper through the stable facade."""
    return _retained_sp1_rev_run(world, text, examples)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: acceptance_runtime.py <ir-path>", file=sys.stderr)
        sys.exit(2)
    try:
        all_passed, output = execute_ir(sys.argv[1])
        print(output)
        sys.exit(0 if all_passed else 1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

__all__ = [
    "execute_ir", "execute_step", "STEP_PATTERNS", "_REGISTERED_PATTERN_KEYS",
    "_track_registration", "_register", "_register_first", "_set_feature",
    "_derive_feature_tag", "find_pattern_conflicts", "World",
    "_h_rev_revision_run", "_h_sp1_rev_run",
]
