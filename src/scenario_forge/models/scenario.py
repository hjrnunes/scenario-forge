"""Pydantic models for the Scenario Envelope.

The scenario envelope is the top-level document wrapping all four output layers
of a scenario-forge scenario:

  1. Narrative       -- Zone-annotated attack prose (LLM Call 1)
  2. Attack tree     -- AND/OR YAML tree (LLM Call 2)
  3. Behavior spec   -- Tool-neutral test specifications (LLM Call 3)
  4. Faceting metadata -- Deterministic fields for querying/filtering

Plus priority signals and generation metadata.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field

from scenario_forge.models.attack_tree import AttackTree
from scenario_forge.models.capability_profile import ConfidenceLevel


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TechniqueMaturity(str, Enum):
    """MITRE ATLAS technique maturity level."""

    feasible = "feasible"
    demonstrated = "demonstrated"
    realized = "realized"


class SeverityLevel(str, Enum):
    """Severity / impact / likelihood levels."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class AttackComplexity(str, Enum):
    """Complexity of the attack path."""

    low = "low"
    medium = "medium"
    high = "high"


class LikelihoodLevel(str, Enum):
    """How feasible and motivated the attack is."""

    high = "high"
    medium = "medium"
    low = "low"


class ArchitectureMatch(str, Enum):
    """Whether the scenario matches explicit or inferred capabilities."""

    explicit = "explicit"
    inferred = "inferred"


class StructuralExposureSignal(str, Enum):
    """Structural exposure type for priority signals."""

    single_point_of_failure = "single_point_of_failure"
    convergence_point = "convergence_point"
    probabilistic_control = "probabilistic_control"
    defense_in_depth_claim = "defense_in_depth_claim"
    none = "none"


class CallName(str, Enum):
    """Which generation call produced a piece of the scenario."""

    actor_profile = "actor_profile"
    narrative = "narrative"
    attack_tree = "attack_tree"
    behavior_spec = "behavior_spec"


# ---------------------------------------------------------------------------
# Narrative sub-models
# ---------------------------------------------------------------------------


class NarrativeStep(BaseModel):
    """A single step in the attack narrative."""

    step_number: int = Field(description="Sequence number of this step.")
    zone: str = Field(description="Schneider zone where this step occurs.")
    action: str = Field(
        description="What the attacker does at this step (adversarial voice)."
    )
    effect: str = Field(
        description="What happens as a result -- system response or state change."
    )
    control_point: Optional[str] = Field(
        default=None,
        description="Defensive control at this step, if one exists.",
    )


class NarrativeLayer(BaseModel):
    """Layer 1: Schneider-style attack narrative with structured steps."""

    title: str = Field(description="Human-readable scenario title.")
    summary: str = Field(
        description="One-paragraph executive summary in adversarial voice."
    )
    entry_point: str = Field(
        description="Entry point from the capability profile (e.g. 'user prompts (zone 1)').",
    )
    zone_sequence: list[str] = Field(
        description="Ordered attack propagation path through Schneider zones.",
        min_length=1,
    )
    steps: list[NarrativeStep] = Field(
        description="Ordered sequence of attack steps.",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Actor profile sub-models
# ---------------------------------------------------------------------------

ActorType = Literal[
    "cybercriminal",  # External, financially motivated (data theft, fraud, ransomware)
    "nation-state",  # State-sponsored, well-resourced, strategic objectives
    "malicious-insider",  # Privileged user acting deliberately (poisons data, abuses admin access)
    "negligent-insider",  # Legitimate user, unintentional harm (pastes secrets, misconfigures)
    "competitor",  # Rival organization (IP theft, output sabotage, reverse-engineering)
    "hacktivist",  # Ideologically motivated (disruption, exposure, defacement)
    "supply-chain-actor",  # Compromised upstream dependency (plugin, data source, tool, model provider)
    "adversarial-user",  # End-user deliberately weaponizing the AI (jailbreaking, prompt injection)
    "automated-agent",  # Another AI/bot attacking programmatically (agent-to-agent, automated injection)
]

ACTOR_TYPES: list[str] = list(ActorType.__args__)  # type: ignore[attr-defined]
"""All valid actor type values as a plain list (for diversity tracking)."""


class ActorProfile(BaseModel):
    """Threat actor profile grounding the scenario narrative."""

    actor_type: ActorType = Field(
        description="Category of threat actor (e.g. cybercriminal, nation-state).",
    )
    capability_level: Literal["novice", "intermediate", "advanced", "expert"] = Field(
        description="Skill and sophistication level of the actor.",
    )
    beliefs: list[str] = Field(
        description="Deployment-time, black-box observations about the target system.",
    )
    desires: list[str] = Field(
        description="Concrete goals — what success looks like for this actor.",
    )
    intentions: list[str] = Field(
        description="Committed attack approach — techniques and sequence.",
    )
    resources: list[str] = Field(
        description="What the actor has access to (e.g. 'open-source tools', 'insider credentials').",
    )
    goal_category: str | None = Field(
        default=None,
        description="Attack goal sub-category ID from the attack goals taxonomy.",
    )
    goal_category_name: str | None = Field(
        default=None,
        description="Human-readable attack goal name from the attack goals taxonomy.",
    )
    goal_category_parent: str | None = Field(
        default=None,
        description="Top-level attack goal category (availability, integrity, privacy, abuse).",
    )


# ---------------------------------------------------------------------------
# Faceting sub-models
# ---------------------------------------------------------------------------


class RiskCardRef(BaseModel):
    """Provenance linking back to the input risk card."""

    risk_id: str = Field(
        description="Risk taxonomy ID (e.g. 'atlas-prompt-injection')."
    )
    risk_name: str = Field(description="Human-readable risk name from the risk card.")
    risk_description: str = Field(description="Risk description from the risk card.")
    taxonomy: Literal["ibm-risk-atlas"] = Field(
        description="Source taxonomy identifier."
    )
    confidence: float = Field(
        description="Cross-encoder confidence score from the risk card (0.0 - 1.0).",
        ge=0.0,
        le=1.0,
    )
    grounding_confidence: ConfidenceLevel = Field(
        description="Grounding confidence level: high, medium, or low.",
    )
    threat: Optional[str] = None
    threat_source: Optional[str] = None
    vulnerability: Optional[str] = None
    consequence: Optional[str] = None
    impact: Optional[str] = None


class TaxonomyChain(BaseModel):
    """The full three-hop taxonomy chain that seeded this scenario."""

    owasp_llm_ids: list[str] = Field(
        description="OWASP LLM Top 10 entry IDs (e.g. ['LLM06', 'LLM03']).",
        min_length=1,
    )
    agentic_threat_ids: list[str] = Field(
        description="OWASP Agentic Threat IDs (e.g. ['T2']).",
        min_length=1,
    )
    atlas_technique_ids: Optional[list[str]] = Field(
        default=None,
        description="MITRE ATLAS technique IDs (e.g. ['AML.T0051']). May be empty.",
    )
    scenario_seed: str = Field(
        description="The attack pattern that seeded this scenario (e.g. 'AP-T7-01').",
    )


class CapabilityProfileRef(BaseModel):
    """References to the capability profile that scoped this scenario."""

    zones_traversed: list[str] = Field(
        description="Ordered attack propagation path through Schneider zones.",
        min_length=1,
    )
    architecture_match: ArchitectureMatch = Field(
        description="Whether the scenario targets explicit or inferred capabilities.",
    )
    entry_point: str = Field(
        description="Which entry point the attack uses from the capability profile.",
    )


class FacetingMetadata(BaseModel):
    """Layer 4: Structured metadata enabling queries across the scenario collection."""

    risk_card: RiskCardRef = Field(
        description="Provenance linking to the input risk card."
    )
    taxonomy_chain: TaxonomyChain = Field(description="Full three-hop taxonomy chain.")
    capability_profile: CapabilityProfileRef = Field(
        description="References to the capability profile that scoped this scenario.",
    )
    maestro_layers: list[Annotated[int, Field(ge=1, le=7)]] = Field(
        description="MAESTRO architectural layers targeted (1-7).",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Priority sub-models
# ---------------------------------------------------------------------------


class PrioritySignals(BaseModel):
    """Individual priority signals preserved as facets."""

    technique_maturity: TechniqueMaturity = Field(
        description="MITRE ATLAS maturity level.",
    )
    risk_impact: SeverityLevel = Field(
        description="Severity of consequence if the attack succeeds.",
    )
    risk_likelihood: LikelihoodLevel = Field(
        description="How feasible and motivated the attack is: high, medium, or low.",
    )
    attack_complexity: AttackComplexity = Field(
        description="Complexity of the attack path.",
    )
    architecture_match: ArchitectureMatch = Field(
        description="Whether the scenario targets explicit or inferred capabilities.",
    )
    structural_exposure: StructuralExposureSignal = Field(
        description="Structural exposure type from Schneider's node selection criteria.",
    )


class Priority(BaseModel):
    """Priority signals for human navigation of the scenario collection."""

    composite: float = Field(
        description="Composite priority score for default sort order (0.0 - 1.0).",
        ge=0.0,
        le=1.0,
    )
    signals: PrioritySignals = Field(description="Individual priority signals.")


# ---------------------------------------------------------------------------
# Generation metadata sub-models
# ---------------------------------------------------------------------------


class CallMetadata(BaseModel):
    """Metadata for a single LLM generation call."""

    call: CallName = Field(description="Which generation call this is.")
    prompt_tokens: int = Field(description="Number of prompt tokens used.")
    completion_tokens: int = Field(description="Number of completion tokens generated.")
    duration_ms: int = Field(
        description="Wall-clock duration of the LLM call in milliseconds."
    )


class GenerationMetadata(BaseModel):
    """Metadata about the generation process."""

    model: str = Field(description="LLM model used for generation.")
    call_metadata: list[CallMetadata] = Field(
        description="Per-call metadata for each LLM call that produced this scenario.",
    )
    notes: Optional[list[str]] = Field(
        default=None,
        description="Generation-time notes and warnings.",
    )


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class ScenarioEnvelope(BaseModel):
    """Top-level scenario document wrapping all four output layers.

    Layers:
      1. narrative      -- Zone-annotated attack prose
      2. attack_tree    -- AND/OR decomposition with taxonomy refs
      3. behavior_spec  -- Tool-neutral test specifications (opaque, stored as dict or str)
      4. faceting       -- Deterministic metadata for querying/filtering
    """

    # --- Identity ---

    scenario_id: str = Field(
        description="Stable identifier: <attack_pattern_id>-<hash>.",
    )
    version: int = Field(
        default=1,
        description="Monotonically increasing version number.",
    )
    generated_at: datetime = Field(
        description="ISO 8601 timestamp of scenario generation.",
    )
    generator_version: str = Field(
        description="Version of the scenario-forge pipeline that produced this scenario.",
    )

    # --- Scenario Seed Metadata ---

    scenario_seed_metadata: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Rich metadata from the scenario seed: seed_id, threat_id, "
            "threat_name, mechanism_name, mechanism_description."
        ),
    )

    # --- Actor Profile ---

    actor_profile: ActorProfile | None = Field(
        default=None,
        description="Threat actor profile grounding the scenario narrative.",
    )

    # --- Layer 1: Narrative ---

    narrative: NarrativeLayer = Field(
        description="Schneider-style attack narrative with structured steps.",
    )

    # --- Layer 2: Attack Tree ---

    attack_tree: AttackTree = Field(
        description="AND/OR decomposition with zone annotations and taxonomy references.",
    )

    # --- Layer 3: Behavior Specification ---

    behavior_spec: Any = Field(
        description="Tool-neutral test specification. Stored as dict or Gherkin text.",
    )

    # --- Layer 4: Faceting Metadata ---

    faceting: FacetingMetadata = Field(
        description="Structured metadata for querying across the scenario collection.",
    )

    # --- Priority ---

    priority: Priority = Field(
        description="Priority signals for human navigation.",
    )

    # --- Generation Metadata ---

    generation: GenerationMetadata = Field(
        description="Metadata about the generation process.",
    )
