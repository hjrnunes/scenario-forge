"""Model profile loader for the STPA pipeline.

Loads named LLM connection and generation parameters from a YAML file,
replacing the need to edit environment variables to switch models.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REQUIRED_FIELDS: tuple[str, ...] = ("base_url", "model", "api_key")
OPTIONAL_FIELDS: tuple[str, ...] = (
    "max_completion_tokens",
    "temperature",
    "top_p",
    "top_k",
    "headers",
)


def load_profile(profiles_path: Path | str, profile_name: str) -> dict[str, Any]:
    """Load a named profile from a YAML profiles file.

    Args:
        profiles_path: Path to the YAML file containing model profiles.
        profile_name: Name of the profile to load (top-level key).

    Returns:
        A dict with keys ``base_url``, ``model``, ``api_key`` and any
        optional fields present (``max_completion_tokens``, ``temperature``,
        ``top_p``, ``top_k``, ``headers``).

    Raises:
        FileNotFoundError: If the profiles file does not exist.
        KeyError: If *profile_name* is not found in the file.
        ValueError: If a required field is missing or empty.
    """
    path = Path(profiles_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Model profiles file not found: {path}"
        )

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or profile_name not in raw:
        raise KeyError(
            f"Profile '{profile_name}' not found in {path}"
        )

    profile = raw[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(
            f"Profile '{profile_name}' in {path} is not a mapping"
        )

    result: dict[str, Any] = {}
    for field in REQUIRED_FIELDS:
        value = profile.get(field)
        if value is None or (isinstance(value, str) and value == ""):
            raise ValueError(
                f"Profile '{profile_name}' is missing required field '{field}'"
            )
        result[field] = value

    for field in OPTIONAL_FIELDS:
        if field in profile and profile[field] is not None:
            result[field] = profile[field]

    return result
