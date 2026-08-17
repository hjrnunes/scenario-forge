"""Shared path discovery for acceptance entry points and tools."""

from __future__ import annotations

from pathlib import Path


def project_root(start: Path) -> Path:
    """Find the nearest ancestor containing the project manifest."""
    start = start.resolve()
    for parent in (start, *start.parents):
        if (parent / "pyproject.toml").is_file():
            return parent
    raise FileNotFoundError(f"could not find project root from {start}")


def acceptance_root() -> Path:
    """Return the acceptance source directory."""
    return Path(__file__).resolve().parent


__all__ = ["acceptance_root", "project_root"]
