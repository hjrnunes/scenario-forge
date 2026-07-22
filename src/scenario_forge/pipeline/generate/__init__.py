"""Stage 4: Scenario Generation.

Four sequential LLM calls per scenario seed produce a complete multi-layered
ScenarioEnvelope:

  Call 0  Actor Profile   -- threat actor type, motivation, capability, resources
  Call 1  Narrative       -- zone-annotated attack prose (grounded in actor)
  Call 2  Attack Tree     -- AND/OR YAML tree
  Call 3  Behavior Spec   -- Gherkin with native keywords

This package was split from a monolithic ``generate.py`` for maintainability.
All previously importable names are re-exported here so existing call sites
(``from scenario_forge.pipeline.generate import X``) continue to work
unchanged.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Re-exports — every name that was importable from the old generate.py
# ---------------------------------------------------------------------------

# constants
from scenario_forge.pipeline.generate.constants import (
    ALL_ACTOR_TYPES,
    CHAIN_TECHNIQUE_PAIRS,
    THREAT_VIOLATION_CATEGORY,
    _ACTOR_GOAL_INCOMPATIBLE,
    _ADVERSARIAL_ONLY_THREATS,
    _ASSERTIONS_MARKER,
    _CAPABILITY_ORDER,
    _CONSISTENCY_MAX_RETRIES,
    _ENTRY_POINT_ZONE_KEYWORDS,
    _GENERATOR_VERSION,
    _OWASP_LLM_NAMES,
    _PATTERN_STOP_WORDS,
    _PHASE_KEYWORDS,
    _THREAT_GOAL_EXCLUSIONS,
    _ZONE_TO_DEFAULT_MAESTRO,
)

# ontology
from scenario_forge.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _format_taxonomy_ids,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
    build_kc_definitions_block,
)

# zones
from scenario_forge.pipeline.generate.zones import (
    _collect_zones_from_tree,
    _enforce_zones_attack_tree,
    _enforce_zones_narrative,
    _enforce_zones_tree_node,
)

# diversity
from scenario_forge.pipeline.generate.diversity import (
    _format_structural_exclusions,
    assign_entry_point,
    compute_entry_point_affinity,
    extract_narrative_keywords,
    extract_structural_pattern,
    get_overused_entry_points,
    get_overused_patterns,
    get_overused_structural_patterns,
)

# goals
from scenario_forge.pipeline.generate.goals import (
    _build_attack_goal_context_block,
    _fair_share_pick,
    compute_compatible_goal_ids,
    filter_sub_goals_by_zones,
    get_all_sub_goals,
    select_attack_goal,
)

# priority
from scenario_forge.pipeline.generate.priority import (
    _compute_priority,
    _continuous_technique_maturity_score,
    _continuous_tree_complexity_score,
    _continuous_zone_score,
    _extract_maestro_layers_from_tree,
    _extract_structural_exposures_from_tree,
    _heuristic_attack_complexity,
    _heuristic_risk_impact,
    _heuristic_risk_likelihood,
    _heuristic_technique_maturity,
    _tree_depth,
    _tree_node_count,
)

# actor
from scenario_forge.pipeline.generate.actor import (
    Call0Response,
    _call_actor_profile,
    _enforce_capability_floor,
    _max_capability_level,
    _normalize_actor_type,
    _normalize_capability_level,
    _validate_actor_type,
    build_call0_context,
    compute_compatible_actor_types,
    compute_minimum_capability_level,
)

# narrative
from scenario_forge.pipeline.generate.narrative import (
    Call1Response,
    Call1Step,
    _call_narrative,
    _derive_zone_sequence,
    _is_latin_or_common,
    _map_call1_to_narrative,
    _sanitize_narrative,
    _sanitize_non_latin,
    build_call1_context,
)

# tree
from scenario_forge.pipeline.generate.tree import (
    _build_tree_skeleton,
    _call_attack_tree,
    _check_consistency,
    _collect_threat_ids_from_tree,
    _count_leaves,
    _format_skeleton_yaml,
    _parse_attack_tree_yaml,
    _sanitize_yaml_colons,
    _strip_non_skeleton_techniques,
    _strip_non_skeleton_techniques_node,
    _validate_mandatory_leaves,
    _validate_technique_zone_compatibility,
    _validate_technique_zone_node,
    _warn_dominant_threat_id_crossref,
    build_call2_context,
)

# gherkin
from scenario_forge.pipeline.generate.gherkin import (
    MAX_OR_PATHS,
    _build_gherkin_template,
    _call_behavior_spec,
    _collect_leaf_nodes_dfs,
    _enumerate_paths,
    build_call3_context,
)

# External dependencies used in patches
from scenario_forge.llm.client import LLMClient

# assembly
from scenario_forge.pipeline.generate.assembly import (
    GenerationError,
    _assemble_envelope,
    _call_log_entry,
    _call_log_entry_error,
    _call_metadata,
    _scenario_hash,
    generate_scenario,
    write_call_log,
    write_scenario_outputs,
)

__all__ = [
    # constants
    "ALL_ACTOR_TYPES",
    "CHAIN_TECHNIQUE_PAIRS",
    "THREAT_VIOLATION_CATEGORY",
    "_ACTOR_GOAL_INCOMPATIBLE",
    "_ADVERSARIAL_ONLY_THREATS",
    "_ASSERTIONS_MARKER",
    "_CAPABILITY_ORDER",
    "_CONSISTENCY_MAX_RETRIES",
    "_ENTRY_POINT_ZONE_KEYWORDS",
    "_GENERATOR_VERSION",
    "_OWASP_LLM_NAMES",
    "_PATTERN_STOP_WORDS",
    "_PHASE_KEYWORDS",
    "_THREAT_GOAL_EXCLUSIONS",
    "_ZONE_TO_DEFAULT_MAESTRO",
    # ontology
    "_build_ontology_context",
    "_build_technique_context_block",
    "_format_taxonomy_ids",
    "_lookup_entry_point_controllability",
    "_lookup_entry_point_direction",
    "build_kc_definitions_block",
    # zones
    "_collect_zones_from_tree",
    "_enforce_zones_attack_tree",
    "_enforce_zones_narrative",
    "_enforce_zones_tree_node",
    # diversity
    "_format_structural_exclusions",
    "assign_entry_point",
    "compute_entry_point_affinity",
    "extract_narrative_keywords",
    "extract_structural_pattern",
    "get_overused_entry_points",
    "get_overused_patterns",
    "get_overused_structural_patterns",
    # goals
    "_build_attack_goal_context_block",
    "_fair_share_pick",
    "compute_compatible_goal_ids",
    "filter_sub_goals_by_zones",
    "get_all_sub_goals",
    "select_attack_goal",
    # priority
    "_compute_priority",
    "_continuous_technique_maturity_score",
    "_continuous_tree_complexity_score",
    "_continuous_zone_score",
    "_extract_maestro_layers_from_tree",
    "_extract_structural_exposures_from_tree",
    "_heuristic_attack_complexity",
    "_heuristic_risk_impact",
    "_heuristic_risk_likelihood",
    "_heuristic_technique_maturity",
    "_tree_depth",
    "_tree_node_count",
    # actor
    "Call0Response",
    "_call_actor_profile",
    "_enforce_capability_floor",
    "_max_capability_level",
    "_normalize_actor_type",
    "_normalize_capability_level",
    "_validate_actor_type",
    "build_call0_context",
    "compute_compatible_actor_types",
    "compute_minimum_capability_level",
    # narrative
    "Call1Response",
    "Call1Step",
    "_call_narrative",
    "_derive_zone_sequence",
    "_is_latin_or_common",
    "_map_call1_to_narrative",
    "_sanitize_narrative",
    "_sanitize_non_latin",
    "build_call1_context",
    # tree
    "_build_tree_skeleton",
    "_call_attack_tree",
    "_check_consistency",
    "_collect_threat_ids_from_tree",
    "_count_leaves",
    "_format_skeleton_yaml",
    "_parse_attack_tree_yaml",
    "_sanitize_yaml_colons",
    "_strip_non_skeleton_techniques",
    "_strip_non_skeleton_techniques_node",
    "_validate_mandatory_leaves",
    "_validate_technique_zone_compatibility",
    "_validate_technique_zone_node",
    "_warn_dominant_threat_id_crossref",
    "build_call2_context",
    # gherkin
    "MAX_OR_PATHS",
    "_build_gherkin_template",
    "_call_behavior_spec",
    "_collect_leaf_nodes_dfs",
    "_enumerate_paths",
    "build_call3_context",
    # External dependencies
    "LLMClient",
    # assembly
    "GenerationError",
    "_assemble_envelope",
    "_call_log_entry",
    "_call_log_entry_error",
    "_call_metadata",
    "_scenario_hash",
    "generate_scenario",
    "write_call_log",
    "write_scenario_outputs",
]
