"""YAML I/O helpers for the STPA pipeline — clean copy.

``write_yaml(model, path)`` serializes a Pydantic model to YAML.
``read_yaml(path, model_class)`` loads a YAML file and validates it
against a Pydantic model class.

Follows the pattern in ``scenario_forge.pipeline.io`` but decoupled.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


def write_yaml(model: BaseModel, path: Path) -> Path:
    """Serialize *model* to a YAML file at *path*.

    Args:
        model: A Pydantic model instance.
        path: Destination file path.

    Returns:
        The path that was written.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = model.model_dump(mode="json", exclude_none=True)
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
# {"version":1,"tested_at":"2026-08-08T12:00:50Z","module_hash":"c829bb176d33bc070908628a863d119d69fb6ad0c1ee64b9e348bf376bb6bd93","functions":[{"id":"func/write_yaml","name":"write_yaml","line":18,"end_line":40,"hash":"3c04f4cf25d7047b0bb45957e38140fa3d2ab5169c5ed7a79d8065d82ac7c1a0"},{"id":"func/read_yaml","name":"read_yaml","line":43,"end_line":58,"hash":"ff05853616a7dd881a650822852f4c42d1dee015ada855d8116699ae5d763209"}]}
# mutate4py-manifest-end
