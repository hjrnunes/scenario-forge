"""Pydantic models for the Capability Profile artifact.

The capability profile is produced by Stage 1 (Capability Profile Inference)
and optionally enriched by Stage 2.  It captures structural properties of the
system under assessment that determine which threat families are in scope and
how specific the generated scenarios can be.

Architecture model: Schneider's five-zone model
  Zone 1 = Input Surfaces
  Zone 2 = Planning & Reasoning
  Zone 3 = Tool Execution
  Zone 4 = Memory & State
  Zone 5 = Inter-Agent Communication
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DepthSetting(str, Enum):
    """Controls the extent of Stage 2 LLM-inferred enrichment."""

    minimal = "minimal"
    moderate = "moderate"
    thorough = "thorough"


class ConfidenceLevel(str, Enum):
    """How well the use-case description supported Stage 1 inferences."""

    high = "high"
    medium = "medium"
    low = "low"


class DataSensitivity(str, Enum):
    """Sensitivity level for data accessible through a tool or integration."""

    none = "none"
    low = "low"
    medium = "medium"
    high = "high"


class BoundaryConfidence(str, Enum):
    """Whether a trust boundary was explicit, inferred, or hypothesized."""

    explicit = "explicit"
    inferred = "inferred"
    hypothesized = "hypothesized"


class MemoryType(str, Enum):
    """Category of memory mechanism."""

    conversation_history = "conversation_history"
    vector_store = "vector_store"
    key_value_store = "key_value_store"
    relational_db = "relational_db"
    knowledge_graph = "knowledge_graph"
    session_cache = "session_cache"
    other = "other"


class MemoryScope(str, Enum):
    """Whether memory is isolated per user, shared, or global."""

    per_user = "per_user"
    shared = "shared"
    global_ = "global"


class MemoryPersistence(str, Enum):
    """How long data persists in a memory mechanism."""

    session = "session"
    short_term = "short_term"
    long_term = "long_term"
    permanent = "permanent"


class IntegrationType(str, Enum):
    """How the agent connects to an external system."""

    api = "api"
    database = "database"
    message_queue = "message_queue"
    file_system = "file_system"
    web_service = "web_service"
    other = "other"


class AuthMethod(str, Enum):
    """Authentication mechanism used by an external integration."""

    api_key = "api_key"
    oauth = "oauth"
    service_account = "service_account"
    none = "none"
    unknown = "unknown"


# ---------------------------------------------------------------------------
# Stage 2 sub-models
# ---------------------------------------------------------------------------


class ToolType(BaseModel):
    """A tool or API the system can invoke, with risk-relevant properties."""

    name: str = Field(description="Tool or API name (e.g. 'database_query', 'send_email')")
    zone: int = Field(description="Schneider zone where this tool operates (typically 3)", ge=1, le=5)
    can_modify_state: bool = Field(description="Whether the tool can write/modify external systems")
    data_sensitivity: DataSensitivity = Field(description="Sensitivity of data the tool can access")
    code_execution: bool = Field(description="Whether the tool can execute arbitrary code")


class DataFlow(BaseModel):
    """A data flow between zones and components."""

    source: str = Field(description="Origin of the data (e.g. 'user input', 'RAG store')")
    source_zone: int = Field(description="Schneider zone of the data source", ge=1, le=5)
    destination: str = Field(description="Where the data flows to (e.g. 'LLM context', 'tool parameter')")
    destination_zone: int = Field(description="Schneider zone of the destination", ge=1, le=5)
    data_type: str = Field(description="Nature of the data (e.g. 'user query', 'retrieved document')")
    validated: bool = Field(description="Whether the data is validated/sanitized at this boundary")


class TrustBoundary(BaseModel):
    """A trust boundary in the system architecture."""

    name: str = Field(description="Descriptive name for the boundary (e.g. 'user-to-LLM')")
    from_zone: int = Field(description="Schneider zone on the untrusted side", ge=1, le=5)
    to_zone: int = Field(description="Schneider zone on the trusted side", ge=1, le=5)
    controls: list[str] = Field(
        default_factory=list,
        description="Security controls at this boundary (e.g. 'input validation')",
    )
    confidence: BoundaryConfidence = Field(
        description="Whether this boundary was explicit, inferred, or hypothesized",
    )


class MemoryMechanism(BaseModel):
    """A memory and state persistence mechanism."""

    type: MemoryType = Field(description="Category of memory mechanism")
    scope: MemoryScope = Field(description="Whether memory is isolated per user, shared, or global")
    persistence: MemoryPersistence = Field(description="How long data persists")
    writable_by_agent: bool = Field(
        description="Whether the agent can write to this store (vs read-only retrieval)",
    )


class ExternalIntegration(BaseModel):
    """An external system or service the agent integrates with."""

    name: str = Field(description="Name of the external system (e.g. 'CRM', 'payment gateway')")
    integration_type: IntegrationType = Field(description="How the agent connects to this system")
    auth_method: AuthMethod = Field(description="Authentication mechanism used")
    data_sensitivity: DataSensitivity = Field(
        description="Sensitivity of data accessible through this integration",
    )


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class CapabilityProfile(BaseModel):
    """Capability profile artifact for a system under assessment.

    Stage 1 fields (required) determine threat scope.
    Stage 2 fields (optional) determine scenario specificity.
    """

    # --- Stage 1 (required) ---

    zones_active: list[int] = Field(
        description=(
            "Schneider zones active in the system. Minimum [1, 2]. "
            "Zone 3=Tool Execution, 4=Memory/State, 5=Inter-Agent Communication."
        ),
    )
    has_persistent_memory: bool = Field(
        description="Whether the system maintains state across sessions or interactions.",
    )
    multi_agent: bool = Field(
        description="Whether the system involves multiple AI agents that communicate or coordinate.",
    )
    hitl: bool = Field(
        description="Whether the system includes human-in-the-loop checkpoints.",
    )
    entry_points: list[str] = Field(
        description="Attack entry points annotated with their Schneider zone.",
        min_length=1,
    )
    confidence: ConfidenceLevel = Field(
        description="How well the use-case description supported Stage 1 inferences.",
    )

    # --- Stage 2 (optional) ---

    tool_types: Optional[list[ToolType]] = Field(
        default=None,
        description="Tools and APIs the system can invoke (populated at moderate/thorough depth).",
    )
    data_flows: Optional[list[DataFlow]] = Field(
        default=None,
        description="Data flows between zones and components (populated at moderate/thorough depth).",
    )
    trust_boundaries: Optional[list[TrustBoundary]] = Field(
        default=None,
        description="Trust boundaries in the system architecture (populated at thorough depth).",
    )
    memory_mechanisms: Optional[list[MemoryMechanism]] = Field(
        default=None,
        description="Memory and state persistence mechanisms (populated at moderate/thorough depth).",
    )
    external_integrations: Optional[list[ExternalIntegration]] = Field(
        default=None,
        description="External systems the agent integrates with (populated at moderate/thorough depth).",
    )

    # --- Validation ---

    @model_validator(mode="after")
    def validate_zones_and_flags(self) -> CapabilityProfile:
        """Cross-field validation for zone/flag consistency."""
        zones = set(self.zones_active)

        # Every LLM system must have zones 1 and 2
        if not {1, 2}.issubset(zones):
            raise ValueError("zones_active must contain at least [1, 2] — all LLM systems have input and reasoning")

        # Zone values must be 1-5
        if not zones.issubset({1, 2, 3, 4, 5}):
            raise ValueError("zones_active values must be between 1 and 5")

        # Zone 4 active implies has_persistent_memory
        if 4 in zones and not self.has_persistent_memory:
            raise ValueError("Zone 4 (Memory/State) active implies has_persistent_memory must be true")

        # Zone 5 active implies multi_agent
        if 5 in zones and not self.multi_agent:
            raise ValueError("Zone 5 (Inter-Agent Communication) active implies multi_agent must be true")

        return self
