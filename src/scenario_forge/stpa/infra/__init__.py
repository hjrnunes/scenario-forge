"""STPA infrastructure — clean copies of minimal pipeline utilities.

Zero coupling to the existing pipeline infrastructure modules.

Public API: import infrastructure utilities from here rather than from
individual sub-modules.
"""

from scenario_forge.stpa.infra.call_log import (
    append_call_log,
    make_call_log_entry,
)
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.manifest import STPARunManifest
from scenario_forge.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml

__all__ = [
    # llm
    "LLMClient",
    "LLMResult",
    # call_log
    "append_call_log",
    "make_call_log_entry",
    # yaml_io
    "read_yaml",
    "write_yaml",
    # templates
    "TemplateLoader",
    "hash_prompt_templates",
    # manifest
    "STPARunManifest",
]
