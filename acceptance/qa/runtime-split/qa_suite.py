"""Scoped QA specification for the acceptance runtime module split.

This suite intentionally does not implement the split.  Checks that can run
against the current tree execute normally.  Checks requiring the proposed
manifest or feature modules report PENDING and make the command non-green.

The runtime source is inspected as a stream of targeted lines.  This avoids
loading or printing the 23k-line monolith wholesale.  The existing shadow
cleanup inventory is imported and is the single source of truth for the
39-registration invariant.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Iterable

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
ACCEPTANCE = ROOT / "acceptance"
RUNTIME = ACCEPTANCE / "acceptance_runtime.py"
IR_DIR = ACCEPTANCE / "ir"
GENERATED = ACCEPTANCE / "generated"
FEATURE_DIR = ACCEPTANCE / "features" / "runtime-split"
FEATURE_MODULE_DIR = ACCEPTANCE / "runtime_features"
MANIFEST = ACCEPTANCE / "runtime_manifest.py"
SHARED = ACCEPTANCE / "runtime_shared.py"
PROPERTY_TEST = ROOT / "tests" / "stpa" / "test_acceptance_harness_property.py"
SHADOW_QA = ACCEPTANCE / "qa" / "shadow-cleanup" / "qa_suite.py"

EXPECTED_FEATURE_FILES = (
    FEATURE_DIR / "compatibility.feature",
    FEATURE_DIR / "registry.feature",
    FEATURE_DIR / "migration.feature",
)
EXPECTED_MODULES = (
    "foundation",
    "infrastructure",
    "models",
    "sp1",
    "sp1_revision",
    "parallel_llm",
    "stage2",
    "sp2",
    "sp3",
    "report",
    "stage1_split",
    "acceptance_refresh",
    "critic_revision_fix",
    "shadow_cleanup",
)

KNOWN_BASELINE_UNRESOLVED = (
    "in `calls.jsonl` the `stage_2` `call_1_requirements` call appears before "
    "the `stage_2` `call_2a_responsibilities` call",
    "in `calls.jsonl` the `stage_2` `call_2a_responsibilities` call appears before "
    "the `stage_2` `call_2b_control_elements` call",
    "in `calls.jsonl` the `stage_2` `call_2b_control_elements` call appears before "
    "the `stage_2` `call_3_coordination` call",
    "`run-manifest.yaml` has `stage_summary.stage_2.call_count` equal to `4`",
    "`control-structure.yaml` contains a non-empty `responsibilities` list",
    "every responsibility in `control-structure.yaml` has at least one `process_model_part`",
    "every responsibility in `control-structure.yaml` has at least one `control_action`",
    "every responsibility in `control-structure.yaml` has at least one `feedback_channel`",
    "every `rc_id` in `control-structure.yaml` starts with `RC-`",
    "no `rc_id` in `control-structure.yaml` starts with `PM-`",
    "every `pm_id` in `control-structure.yaml` appears in at least one `updates` field "
    "of a feedback channel",
    "for every responsibility in `control-structure.yaml` the feedback channel count is "
    "greater than or equal to the process model part count",
    "`control-structure.yaml` contains a `coordination_links` list",
)


@dataclass
class Result:
    name: str
    status: str
    detail: str = ""


class Runner:
    def __init__(self) -> None:
        self.results: list[Result] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.results.append(Result(name, "PASS" if condition else "FAIL", detail))

    def pending(self, name: str, detail: str) -> None:
        self.results.append(Result(name, "PENDING", detail))

    def summary(self) -> int:
        counts = {status: sum(r.status == status for r in self.results)
                  for status in ("PASS", "FAIL", "PENDING")}
        print("=" * 72)
        print(
            f"QA SUMMARY: {counts['PASS']} passed, {counts['FAIL']} failed, "
            f"{counts['PENDING']} pending"
        )
        print("=" * 72)
        for result in self.results:
            suffix = f" — {result.detail}" if result.detail else ""
            print(f"[{result.status}] {result.name}{suffix}")
        if counts["FAIL"] or counts["PENDING"]:
            print("\nNOT GREEN: split-dependent checks are intentionally not hidden.")
            return 1
        return 0


def _load_shadow_inventory() -> ModuleType:
    """Load the existing inventory without importing the acceptance runtime."""
    spec = importlib.util.spec_from_file_location("shadow_cleanup_qa", SHADOW_QA)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load shadow QA inventory: {SHADOW_QA}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lines(path: Path) -> Iterable[tuple[int, str]]:
    """Yield source lines without retaining the whole file."""
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            yield number, line.rstrip("\n")


def _function_source(path: Path, name: str, max_lines: int = 160) -> str:
    """Read only a bounded source window around one top-level function."""
    start = None
    collected: list[str] = []
    for number, line in _lines(path):
        if re.match(rf"^def {re.escape(name)}\s*\(", line):
            start = number
            collected.append(line)
            continue
        if start is None:
            continue
        if number > start and line and not line.startswith((" ", "\t")):
            break
        if number - start >= max_lines:
            break
        collected.append(line)
    return "\n".join(collected)


def _defined_names(path: Path) -> set[str]:
    return {
        match.group(1)
        for _, line in _lines(path)
        if (match := re.match(r"^def ([A-Za-z_][A-Za-z0-9_]*)\s*\(", line))
    }


_REGISTRATION_RE = re.compile(
    r"""^\s*(_register_first|_register)\(\s*((?:r)?["'].*?["'])\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$"""
)


def _registration_tuples(path: Path) -> list[tuple[str, str, str]]:
    """Extract single-line literal registrations without AST-loading runtime."""
    found: list[tuple[str, str, str]] = []
    for _, line in _lines(path):
        match = _REGISTRATION_RE.match(line)
        if not match:
            continue
        registration, literal, handler = match.groups()
        try:
            pattern = ast.literal_eval(literal)
        except (SyntaxError, ValueError):
            continue
        if isinstance(pattern, str):
            found.append((registration, pattern, handler))
    return found


def _executable_ir() -> list[Path]:
    return sorted(p for p in IR_DIR.rglob("*.json") if not p.stem.endswith("_dry"))


def _entrypoint_refs(path: Path) -> list[Path]:
    body = path.read_text(encoding="utf-8")
    return [
        Path(raw).resolve()
        for raw in re.findall(r'Path\(r"([^"]+\.json)"\)', body)
    ]


def _feature_texts(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    texts: list[str] = []
    for section in ("background", "scenarios"):
        values = data.get(section, [])
        if isinstance(values, dict):
            values = [values]
        for scenario in values:
            examples = scenario.get("examples") or [{}]
            for example in examples:
                for step in scenario.get("steps", []):
                    text = step.get("text", "")
                    for key, value in example.items():
                        text = text.replace(f"<{key}>", str(value))
                    if text:
                        texts.append(text)
    return texts


def _run_child(script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ACCEPTANCE), str(ROOT), env.get("PYTHONPATH", "")]
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def static_checks(runner: Runner) -> None:
    """Run bounded source and artifact checks."""
    for feature in EXPECTED_FEATURE_FILES:
        runner.check(
            f"static feature exists: {feature.name}",
            feature.is_file(),
            f"missing {feature}",
        )
        if feature.is_file():
            source = feature.read_text(encoding="utf-8")
            runner.check(
                f"static feature is no-live-LLM: {feature.name}",
                "live LLM" in source and "SKIP" in source,
                "feature must state no-live-LLM and SKIP policy",
            )
            runner.check(
                f"static feature has indexed scenarios: {feature.name}",
                bool(re.search(r"Scenario: [^\n]+ — \d\d ", source))
                and bool(re.search(r"^  # .* — \d\d ", source, re.MULTILINE)),
                "each scenario needs an indexed name and preceding comment",
            )

    inventory = _load_shadow_inventory()
    registrations = _registration_tuples(RUNTIME)
    dead = set(inventory.DEAD_REGISTRATIONS)
    runner.check(
        "static jrds inventory contains exactly 39 tuples",
        len(inventory.DEAD_REGISTRATIONS) == 39,
        f"inventory size: {len(inventory.DEAD_REGISTRATIONS)}",
    )
    remaining = [
        item for item in registrations
        if item in dead
    ]
    runner.check(
        "static jrds inventory: all 39 exact registrations are absent",
        not remaining,
        f"remaining inventory entries: {remaining[:3]}",
    )

    names = _defined_names(RUNTIME)
    for required in (
        "_track_registration",
        "_register",
        "_register_first",
        "find_pattern_conflicts",
        "execute_step",
        "execute_ir",
        "_derive_feature_tag",
    ):
        runner.check(
            f"static facade export: {required}",
            required in names,
            f"{required} is not defined in the current facade",
        )

    register_source = _function_source(RUNTIME, "_register")
    first_source = _function_source(RUNTIME, "_register_first")
    runner.check(
        "static _register append semantics",
        "STEP_PATTERNS.append" in register_source,
        "_register must append",
    )
    runner.check(
        "static _register_first priority semantics",
        "STEP_PATTERNS.insert" in first_source and "0" in first_source,
        "_register_first must insert at index zero",
    )

    for retained in inventory.RETAIN_FUNCTIONS:
        runner.check(
            f"static retained delegation helper: {retained}",
            retained in names,
            f"{retained} must remain callable for delegation",
        )

    missing_modules = [
        name for name in EXPECTED_MODULES
        if not (FEATURE_MODULE_DIR / f"{name}.py").is_file()
    ]
    if missing_modules:
        runner.pending(
            "static split module manifest",
            "runtime split not implemented; missing feature modules: "
            + ", ".join(missing_modules),
        )
    if not MANIFEST.is_file() or not SHARED.is_file():
        runner.pending(
            "static manifest/shared ownership",
            "runtime_manifest.py and runtime_shared.py are not implemented yet",
        )

    if PROPERTY_TEST.is_file():
        source = PROPERTY_TEST.read_text(encoding="utf-8")
        runner.check(
            "static property tests are not strict xfail",
            "strict=False" not in source,
            "strict=False would hide xpass",
        )
    else:
        runner.check("static property test exists", False, str(PROPERTY_TEST))


def dynamic_checks(runner: Runner) -> None:
    """Run isolated import, IR coverage, and conflict checks."""
    baseline_fragments = repr(KNOWN_BASELINE_UNRESOLVED)
    script = r"""
import json
import hashlib
from pathlib import Path
import acceptance_runtime as runtime

root = Path.cwd()
ir_dir = root / "acceptance" / "ir"
generated = root / "acceptance" / "generated"
irs = sorted(p for p in ir_dir.rglob("*.json") if not p.stem.endswith("_dry"))
errors = []

if len(runtime.STEP_PATTERNS) != len(runtime._REGISTERED_PATTERN_KEYS):
    errors.append("registry key/pattern lengths differ")

for ir in irs:
    data = json.loads(ir.read_text())
    tag = runtime._derive_feature_tag(str(ir))
    sections = []
    for section in ("background", "scenarios"):
        value = data.get(section, [])
        sections.extend(value if isinstance(value, list) else [value])
    for scenario in sections:
        examples = scenario.get("examples") or [{}]
        for example in examples:
            for step in scenario.get("steps", []):
                text = step.get("text", "")
                for key, value in example.items():
                    text = text.replace(f"<{key}>", str(value))
                selected = [
                    (pattern, handler)
                    for pattern, handler, feature_tag in runtime.STEP_PATTERNS
                    if (feature_tag is None or feature_tag == tag)
                    and pattern.search(text)
                ]
                if not selected:
                    errors.append(f"unresolved: {ir.name}: {text}")

conflicts = runtime.find_pattern_conflicts([])
if conflicts:
    errors.append(f"same-scope conflicts: {conflicts[:3]}")

known = [
    error for error in errors
    if any(fragment in error for fragment in BASELINE_FRAGMENTS)
]
unknown = [error for error in errors if error not in known]
print(json.dumps({
    "ir_count": len(irs),
    "pattern_count": len(runtime.STEP_PATTERNS),
    "errors": errors[:20],
    "known_error_count": len(known),
    "unknown_errors": unknown[:20],
}))
raise SystemExit(1 if unknown else 0)
"""
    script = script.replace("BASELINE_FRAGMENTS", baseline_fragments)
    result = _run_child(script)
    try:
        dynamic_payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        dynamic_payload = {}
    runner.check(
        "dynamic fresh-process facade import and IR resolution",
        result.returncode == 0,
        "known baseline unresolved steps are unchanged; "
        + (result.stdout + result.stderr)[-2000:],
    )
    runner.check(
        "dynamic known-red baseline",
        dynamic_payload.get("known_error_count") == len(KNOWN_BASELINE_UNRESOLVED),
        f"expected {len(KNOWN_BASELINE_UNRESOLVED)} known unresolved steps, "
        f"got {dynamic_payload.get('known_error_count')}",
    )

    if not MANIFEST.is_file() or not FEATURE_MODULE_DIR.is_dir():
        runner.pending(
            "dynamic import-order and idempotence",
            "split manifest and feature modules are not implemented yet",
        )
        runner.pending(
            "dynamic omitted-module anti-vacuity",
            "cannot exercise manifest omission until the manifest exists",
        )
        runner.pending(
            "dynamic duplicate-register anti-vacuity",
            "cannot exercise module register functions until the split exists",
        )
        runner.pending(
            "dynamic atomic publish/rollback",
            "cannot exercise staged registration until the split exists",
        )
        return

    permutation = _run_child(
        r"""
import hashlib
import importlib
import json
import runtime_manifest

def digest(runtime):
    rows = [(p.pattern, handler.__name__, tag)
            for p, handler, tag in runtime.STEP_PATTERNS]
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()

runtime = importlib.import_module("acceptance_runtime")
first = digest(runtime)
for name in runtime_manifest.MODULES:
    importlib.import_module(f"runtime_features.{name}")
importlib.reload(runtime_manifest)
second = digest(runtime)
if first != second:
    raise SystemExit(f"facade-first digest changed: {first} != {second}")
print(first)
"""
    )
    module_first = _run_child(
        r"""
import hashlib
import importlib
import json
import runtime_manifest

for name in runtime_manifest.MODULES:
    importlib.import_module(f"runtime_features.{name}")
runtime = importlib.import_module("acceptance_runtime")
rows = [(p.pattern, handler.__name__, tag)
        for p, handler, tag in runtime.STEP_PATTERNS]
print(hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest())
"""
    )
    permutation_ok = (
        permutation.returncode == 0
        and module_first.returncode == 0
        and permutation.stdout.strip().splitlines()[-1:]
        == module_first.stdout.strip().splitlines()[-1:]
    )
    runner.check(
        "dynamic import-order and idempotence",
        permutation_ok,
        (permutation.stdout + permutation.stderr + module_first.stdout + module_first.stderr)[-2000:],
    )

    omitted = _run_child(
        r"""
import runtime_manifest
runtime_manifest.MODULES = runtime_manifest.MODULES[:-1]
try:
    import acceptance_runtime
except RuntimeError as exc:
    if "manifest mismatch" not in str(exc):
        raise SystemExit(f"unexpected omission error: {exc}")
    print("omission rejected before facade import completed")
else:
    raise SystemExit("omitted module was silently accepted")
"""
    )
    runner.check(
        "dynamic omitted-module anti-vacuity",
        omitted.returncode == 0 and "omission rejected" in omitted.stdout,
        (omitted.stdout + omitted.stderr)[-2000:],
    )

    duplicate = _run_child(
        r"""
import importlib
import acceptance_runtime as runtime
import runtime_manifest

modules = runtime_manifest.load_modules()
stage = runtime._RegistrationStage()
api = runtime._RegistrationAPI(stage)
api.install_handlers([importlib.import_module("runtime_shared").__dict__,
                      *[module.__dict__ for module in modules]])
modules[0].register(api)
before = (len(runtime.STEP_PATTERNS), len(runtime._REGISTERED_PATTERN_KEYS))
try:
    modules[0].register(api)
except RuntimeError as exc:
    if "Duplicate step pattern registration" not in str(exc):
        raise SystemExit(f"unexpected duplicate error: {exc}")
else:
    raise SystemExit("duplicate registration was silently accepted")
after = (len(runtime.STEP_PATTERNS), len(runtime._REGISTERED_PATTERN_KEYS))
if before != after:
    raise SystemExit(f"global registry changed: {before} != {after}")
print("duplicate rejected without global partial publish")
"""
    )
    runner.check(
        "dynamic duplicate-register anti-vacuity",
        duplicate.returncode == 0 and "without global partial publish" in duplicate.stdout,
        (duplicate.stdout + duplicate.stderr)[-2000:],
    )

    atomic = _run_child(
        r"""
import types
import runtime_manifest

faulty = types.ModuleType("runtime_features.faulty")
faulty.FEATURE_ID = "faulty"
def register(api):
    api.register("atomic witness", lambda world, text, examples: (True, ""))
    raise ValueError("injected registration failure")
faulty.register = register
runtime_manifest.MODULES = ("faulty",)
runtime_manifest.load_modules = lambda: (faulty,)
try:
    import acceptance_runtime as runtime
except RuntimeError as exc:
    message = str(exc)
    if "faulty" not in message or "injected registration failure" not in message:
        raise SystemExit(f"missing failure context: {message}")
    import sys
    runtime = sys.modules.get("acceptance_runtime")
    if runtime is not None and (runtime.STEP_PATTERNS or runtime._REGISTERED_PATTERN_KEYS):
        raise SystemExit("partial registry was published")
    print("atomic registration failure rolled back")
else:
    raise SystemExit("injected registration failure was ignored")
"""
    )
    runner.check(
        "dynamic atomic publish/rollback",
        atomic.returncode == 0 and "rolled back" in atomic.stdout,
        (atomic.stdout + atomic.stderr)[-2000:],
    )


def entrypoint_checks(runner: Runner) -> None:
    """Check canonical executable IR to generated-entrypoint coverage."""
    irs = set(p.resolve() for p in _executable_ir())
    references: dict[Path, list[Path]] = {}
    for entrypoint in sorted(GENERATED.glob("*_acceptance_test.py")):
        # Each generated file references its IR in both pytest and __main__
        # paths.  Count entrypoint files, not literal references.
        for ref in set(_entrypoint_refs(entrypoint)):
            references.setdefault(ref, []).append(entrypoint)

    missing = sorted(str(path) for path in irs if len(references.get(path, [])) != 1)
    extra = sorted(
        str(path) for path in references
        if path not in irs
    )
    runner.check(
        "dynamic executable IR has exactly one generated entrypoint",
        not missing and not extra,
        f"missing/non-one-to-one: {missing[:5]}, extra: {extra[:5]}",
    )


def run(mode: str) -> int:
    runner = Runner()
    if mode in {"static", "all"}:
        static_checks(runner)
    if mode in {"dynamic", "all"}:
        entrypoint_checks(runner)
        dynamic_checks(runner)
    return runner.summary()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--static", action="store_true",
        help="run bounded source and specification checks",
    )
    parser.add_argument(
        "--dynamic", action="store_true",
        help="run isolated import, registry, and IR checks",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="run static and dynamic checks",
    )
    args = parser.parse_args()
    if not (args.static or args.dynamic or args.all):
        parser.error("choose --static, --dynamic, or --all")
    mode = "all" if args.all else "static" if args.static else "dynamic"
    return run(mode)


if __name__ == "__main__":
    raise SystemExit(main())
