"""Pure data and filesystem helpers for the acceptance-framework QA suite."""

from __future__ import annotations

import json
from pathlib import Path


def feature_paths(features_dir: Path) -> list[Path]:
    return sorted(features_dir.rglob("*.feature"))


def collect_generated(root: Path, pattern: str) -> set[str]:
    if not root.exists():
        return set()
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob(pattern)
        if path.is_file()
    }


def file_digest_map(root: Path, pattern: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not root.exists():
        return mapping
    for path in root.rglob(pattern):
        if path.is_file():
            mapping[path.relative_to(root).as_posix()] = path.read_text()
    return mapping


def metadata_has_absolute_paths(path: Path, project_root: Path) -> list[str]:
    problems: list[str] = []
    data = json.loads(path.read_text())
    for key in ("feature_path", "ir_path"):
        value = data.get(key, "")
        if not isinstance(value, str) or not value:
            problems.append(f"{path.name}: missing {key}")
            continue
        if Path(value).is_absolute() or value.startswith(str(project_root)):
            problems.append(f"{path.name}: {key} is absolute ({value})")
    return problems


def parse_runtime_lines(text: str) -> dict[str, list[str]]:
    found = {"PASS": [], "FAIL": [], "SKIP": []}
    for raw in text.splitlines():
        line = raw.strip()
        for status in found:
            if line.startswith(f"{status} "):
                found[status].append(line)
    return found


def write_ir(path: Path, name: str, step_text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "name": name,
                "background": [],
                "scenarios": [
                    {
                        "name": name,
                        "steps": [{"keyword": "Given", "text": step_text}],
                        "examples": [],
                    }
                ],
            }
        )
        + "\n"
    )


def slug(stem: str) -> str:
    cleaned = []
    last_dash = False
    for char in stem.lower():
        if char.isalnum():
            cleaned.append(char)
            last_dash = False
        elif not last_dash:
            cleaned.append("-")
            last_dash = True
    return "".join(cleaned).strip("-")


__all__ = [
    "collect_generated",
    "feature_paths",
    "file_digest_map",
    "metadata_has_absolute_paths",
    "parse_runtime_lines",
    "slug",
    "write_ir",
]
