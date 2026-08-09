"""YAML I/O helpers for the STPA pipeline — clean copy.

``write_yaml(model, path)`` serializes a Pydantic model to YAML.
``read_yaml(path, model_class)`` loads a YAML file and validates it
against a Pydantic model class.

Follows the pattern in ``scenario_forge.pipeline.io`` but decoupled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel


def write_yaml(
    model: BaseModel,
    path: Path,
    post_process: Callable[[dict], dict] | None = None,
) -> Path:
    """Serialize *model* to a YAML file at *path*.

    Args:
        model: A Pydantic model instance.
        path: Destination file path.
        post_process: Optional callable that receives the dumped dict
            and returns a (possibly modified) dict before YAML
            serialization.  Used by callers to inject companion display
            fields (e.g. ``kc_subcodes_display`` on CapabilityProfile).

    Returns:
        The path that was written.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = model.model_dump(mode="json", exclude_none=True)
    if post_process is not None:
        data = post_process(data)
    path.write_text(
        yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return path


def read_yaml(path: Path, model_class: type[BaseModel]) -> BaseModel:
    """Load a YAML file and validate it against *model_class*.

    Args:
        path: Source YAML file path.
        model_class: Pydantic model class to validate against.

    Returns:
        A validated model instance.

    Raises:
        pydantic.ValidationError: If the data does not satisfy the schema.
    """
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return model_class.model_validate(raw)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T00:31:41Z","module_hash":"e4223336446c8dabf9d1a065b733d02945a34bf089f09a63f1ae0e36e38232cf","functions":[{"id":"func/write_yaml","name":"write_yaml","line":19,"end_line":51,"hash":"9c701f2357e0581f43ad8f0e38eb3aeb355425e6cd09249b80e7a9b03f455ed4"},{"id":"func/read_yaml","name":"read_yaml","line":54,"end_line":69,"hash":"ff05853616a7dd881a650822852f4c42d1dee015ada855d8116699ae5d763209"}]}
# mutate4py-manifest-end
