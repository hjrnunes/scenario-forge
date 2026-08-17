"""Runtime manifest contract handlers."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from runtime_bootstrap import PROJECT_ROOT
from runtime_world import World


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


class _CountingAPI:
    """Minimal API used to count each manifest module invocation."""

    def __init__(self) -> None:
        self.calls: dict[str, int] = {}
        self.current_feature: str | None = None

    def set_feature(self, tag: str | None) -> None:
        self.current_feature = tag

    def _register_noop(
        self, pattern: str, handler: Any, *, source_order: int | None = None
    ) -> None:
        return None

    register = _register_noop
    register_first = _register_noop
