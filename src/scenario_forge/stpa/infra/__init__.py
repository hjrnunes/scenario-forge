"""STPA infrastructure — clean copies of minimal pipeline utilities.

Zero coupling to the existing pipeline infrastructure modules.

Public API: import infrastructure utilities from here rather than from
individual sub-modules.
"""

from scenario_forge.stpa.infra.call_log import (
    append_call_log,
    make_call_log_entry,
)
from scenario_forge.stpa.infra.calls_html import render_calls_html
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.llm_helpers import log_llm_call, parse_llm_result, safe_llm_call_raw
from scenario_forge.stpa.infra.manifest import STPARunManifest
from scenario_forge.stpa.infra.model_profiles import load_profile
from scenario_forge.stpa.infra.parallel_llm import (
    LLMCallResult,
    LLMCallSpec,
    parallel_safe_llm_calls,
)
from scenario_forge.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml

__all__ = [
    # llm
    "LLMClient",
    "LLMResult",
    # llm_helpers
    "log_llm_call",
    "parse_llm_result",
    "safe_llm_call_raw",
    # call_log
    "append_call_log",
    "make_call_log_entry",
    # calls_html
    "render_calls_html",
    # model_profiles
    "load_profile",
    # yaml_io
    "read_yaml",
    "write_yaml",
    # templates
    "TemplateLoader",
    "hash_prompt_templates",
    # manifest
    "STPARunManifest",
    # parallel_llm
    "LLMCallSpec",
    "LLMCallResult",
    "parallel_safe_llm_calls",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"4e591bb85398f0de8d29db741bb62eb569d9302972363a95634f5c982e673d6a","functions":[]}
# mutate4py-manifest-end
