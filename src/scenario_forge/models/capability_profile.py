"""Pydantic models for the Capability Profile artifact.

The capability profile is produced by Stage 1 (Capability Profile Inference)
and optionally enriched by Stage 2.  It captures structural properties of the
system under assessment that determine which threat families are in scope and
how specific the generated scenarios can be.

Architecture model: Schneider's five-zone model
  input            = Input Surfaces
  reasoning        = Planning & Reasoning
  tool_execution   = Tool Execution
  memory           = Memory & State
  inter_agent      = Inter-Agent Communication
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zone constants
# ---------------------------------------------------------------------------

ZONE_NAMES: tuple[str, ...] = (
    "input",
    "reasoning",
    "tool_execution",
    "memory",
    "inter_agent",
)

# ---------------------------------------------------------------------------
# OWASP KC sub-code constants
# ---------------------------------------------------------------------------

VALID_KC_SUBCODES: frozenset[str] = frozenset({
    "KC1.1", "KC1.2", "KC1.3", "KC1.4",
    "KC2.1", "KC2.2", "KC2.3",
    "KC3.1", "KC3.2", "KC3.3", "KC3.4",
    "KC4.1", "KC4.2", "KC4.3", "KC4.4", "KC4.5", "KC4.6",
    "KC5.1", "KC5.2", "KC5.3",
    "KC6.1.1", "KC6.1.2", "KC6.2.1", "KC6.2.2",
    "KC6.3.1", "KC6.3.2", "KC6.3.3",
    "KC6.4", "KC6.5", "KC6.6", "KC6.7",
})

# ---------------------------------------------------------------------------
# scenario-forge KC extensions — NOT from OWASP.
# These gate attack patterns requiring structural capabilities beyond
# standard OWASP KC codes. KCX-prefixed codes are scenario-forge-specific
# and are NOT part of the OWASP Agentic AI taxonomy.
# ---------------------------------------------------------------------------

KCX_SUBCODES: dict[str, str] = {
    "KCX-PRIV": (
        "System has dynamic privilege tiers or permission escalation paths"
    ),
    "KCX-XAUTH": (
        "System has cross-boundary credential propagation between trust domains"
    ),
    "KCX-PMEM": (
        "System has persistent memory architecture (cross-session state)"
    ),
    "KCX-SHMEM": (
        "System has shared writable memory accessible to multiple agents"
    ),
    "KCX-MAGENT": (
        "System has multi-agent or outbound inter-agent communication"
    ),
    "KCX-VSTORE": (
        "System has vector store or RAG write access"
    ),
    "KCX-HITL": (
        "System has human-in-the-loop review or approval controls"
    ),
    "KCX-AUDIT": (
        "System has exploitable audit or logging architecture"
    ),
    "KCX-PSTATE": (
        "System has persistent state enabling self-model or self-preservation"
    ),
}

KCX_PREFIX = "KCX-"

ZONE_DISPLAY_NAMES: dict[str, str] = {
    "input": "Input Surfaces",
    "reasoning": "Planning & Reasoning",
    "tool_execution": "Tool Execution",
    "memory": "Memory & State",
    "inter_agent": "Inter-Agent Communication",
}


# ---------------------------------------------------------------------------
# Zone derivation from KC sub-codes
# ---------------------------------------------------------------------------


def derive_zones_from_kc(kc_subcodes: list[str]) -> list[str]:
    """Derive zones_active from KC sub-codes.

    Mapping logic:
    - KC1.*/KC3.* -> input + reasoning (always present since KC1.* is mandatory)
    - KC2.1/KC2.2 -> reasoning (already covered by default)
    - KC2.3 -> inter_agent
    - KC4.1/KC4.2 -> NO zone activation (session-only memory, not persistent)
    - KC4.3-KC4.6 -> memory (cross-session persistence)
    - KC5.* -> tool_execution
    - KC6.* -> tool_execution
    """
    zones: set[str] = {"input", "reasoning"}  # always present (KC1.* is mandatory)
    for kc in kc_subcodes:
        if kc.startswith("KC4.") and kc not in ("KC4.1", "KC4.2"):
            zones.add("memory")
        elif kc.startswith("KC5.") or kc.startswith("KC6."):
            zones.add("tool_execution")
        elif kc == "KC2.3":
            zones.add("inter_agent")
    return sorted(zones)


# KC4 sub-codes that imply cross-session persistence (not session-only)
_KC4_PERSISTENT: frozenset[str] = frozenset({"KC4.3", "KC4.4", "KC4.5", "KC4.6"})


def derive_flags_from_kc(kc_subcodes: list[str]) -> dict[str, bool]:
    """Derive boolean capability flags from KC sub-codes.

    Returns a dict of flags that should be forced True based on KC evidence:
    - has_persistent_memory: True if any KC4.3+ (cross-session memory)
    - multi_agent: True if KC2.3 (multi-agent communication)

    Only returns keys that should be set True; absent keys mean the KC
    sub-codes provide no evidence for that flag (leave it as-is).
    """
    flags: dict[str, bool] = {}
    for kc in kc_subcodes:
        if kc in _KC4_PERSISTENT:
            flags["has_persistent_memory"] = True
        elif kc == "KC2.3":
            flags["multi_agent"] = True
    return flags


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
    zone: str = Field(description="Schneider zone where this tool operates (typically 'tool_execution')")
    can_modify_state: bool = Field(description="Whether the tool can write/modify external systems")
    data_sensitivity: DataSensitivity = Field(description="Sensitivity of data the tool can access")
    code_execution: bool = Field(description="Whether the tool can execute arbitrary code")


class DataFlow(BaseModel):
    """A data flow between zones and components."""

    source: str = Field(description="Origin of the data (e.g. 'user input', 'RAG store')")
    source_zone: str = Field(description="Schneider zone of the data source")
    destination: str = Field(description="Where the data flows to (e.g. 'LLM context', 'tool parameter')")
    destination_zone: str = Field(description="Schneider zone of the destination")
    data_type: str = Field(description="Nature of the data (e.g. 'user query', 'retrieved document')")
    validated: bool = Field(description="Whether the data is validated/sanitized at this boundary")


class TrustBoundary(BaseModel):
    """A trust boundary in the system architecture."""

    name: str = Field(description="Descriptive name for the boundary (e.g. 'user-to-LLM')")
    from_zone: str = Field(description="Schneider zone on the untrusted side")
    to_zone: str = Field(description="Schneider zone on the trusted side")
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
# Entry point with direction tag
# ---------------------------------------------------------------------------


class EntryPoint(BaseModel):
    """An entry point with a direction tag indicating data flow.

    Direction controls whether the entry point is considered as attacker
    ingress during candidate expansion:
    - ``input``: attacker can send data in (included in candidate cross-product)
    - ``output``: system sends data out only (excluded from candidate cross-product)
    - ``bidirectional``: both input and output (included in candidate cross-product)
    """

    name: str = Field(description="Entry point description, e.g. 'user prompts via chat widget'.")
    direction: Literal["input", "output", "bidirectional"] = Field(
        default="bidirectional",
        description=(
            "Data flow direction: 'input' (attacker can send data in), "
            "'output' (system sends data out), or 'bidirectional' (both)."
        ),
    )

    def __str__(self) -> str:
        """Return the entry point name for backward-compatible string formatting."""
        return self.name


def _coerce_entry_points(
    v: list[Union[str, dict, EntryPoint]],
) -> list[EntryPoint]:
    """Coerce a list of mixed entry point representations to EntryPoint objects.

    Accepts:
    - Plain strings (backward compat) -> EntryPoint(name=string, direction="bidirectional")
    - Dicts with at least a ``name`` key -> EntryPoint(**dict)
    - EntryPoint objects -> passed through
    """
    result: list[EntryPoint] = []
    for item in v:
        if isinstance(item, EntryPoint):
            result.append(item)
        elif isinstance(item, str):
            result.append(EntryPoint(name=item, direction="bidirectional"))
        elif isinstance(item, dict):
            result.append(EntryPoint(**item))
        else:
            raise ValueError(
                f"entry_points items must be str, dict, or EntryPoint, got {type(item)}"
            )
    return result


# ---------------------------------------------------------------------------
# Stage 1-only model (used for LLM inference to avoid schema bloat)
# ---------------------------------------------------------------------------


class Stage1Profile(BaseModel):
    """Slim Stage 1-only profile for the LLM structured-output call.

    Excludes Stage 2 sub-models so the schema stays small and the model
    doesn't generate runaway output trying to fill optional nested fields.

    zones_active is NOT an LLM-inferred field — it is derived from
    kc_subcodes in to_capability_profile().
    """

    has_persistent_memory: bool = Field(
        description="Whether the system maintains state across sessions or interactions.",
    )
    multi_agent: bool = Field(
        description="Whether the system involves multiple AI agents that communicate or coordinate.",
    )
    hitl: bool = Field(
        description="Whether the system includes human-in-the-loop checkpoints.",
    )
    entry_points: list[EntryPoint] = Field(
        description=(
            "Attack entry points, each with a name and direction tag. "
            "Direction is one of: input (attacker can send data in), "
            "output (system sends data out), bidirectional (both)."
        ),
        min_length=1,
    )
    confidence: ConfidenceLevel = Field(
        description="How well the use-case description supported Stage 1 inferences.",
    )
    kc_subcodes: list[str] = Field(
        default_factory=list,
        description=(
            "OWASP KC (Key Component) sub-codes identifying the system's "
            "granular capabilities. E.g. ['KC1.1', 'KC4.1', 'KC6.1.1']."
        ),
    )

    @field_validator("entry_points", mode="before")
    @classmethod
    def coerce_entry_points(
        cls, v: list[Union[str, dict, EntryPoint]],
    ) -> list[EntryPoint]:
        return _coerce_entry_points(v)

    @field_validator("kc_subcodes")
    @classmethod
    def validate_kc_subcodes(cls, v: list[str]) -> list[str]:
        if not v:
            return v
        # KCX-prefixed codes are scenario-forge extensions (NOT from OWASP)
        # and pass through without checking against VALID_KC_SUBCODES.
        invalid = [
            code for code in v
            if not code.startswith(KCX_PREFIX) and code not in VALID_KC_SUBCODES
        ]
        if invalid:
            raise ValueError(
                f"Invalid KC sub-code(s): {invalid}. "
                f"Valid codes: {sorted(VALID_KC_SUBCODES)} "
                f"(codes prefixed with '{KCX_PREFIX}' are also accepted)"
            )
        return sorted(set(v))

    def to_capability_profile(self) -> CapabilityProfile:
        """Promote to a full CapabilityProfile (Stage 2 fields left as None).

        zones_active and boolean flags are derived from kc_subcodes rather
        than trusting LLM-inferred values.
        """
        data = self.model_dump()
        data["zones_active"] = derive_zones_from_kc(self.kc_subcodes)
        # Derive boolean flags — KC evidence upgrades False→True, never downgrades
        flags = derive_flags_from_kc(self.kc_subcodes)
        if flags.get("has_persistent_memory"):
            data["has_persistent_memory"] = True
        if flags.get("multi_agent"):
            data["multi_agent"] = True
        return CapabilityProfile(**data)


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class CapabilityProfile(BaseModel):
    """Capability profile artifact for a system under assessment.

    Stage 1 fields (required) determine threat scope.
    Stage 2 fields (optional) determine scenario specificity.
    """

    # --- Stage 1 (required) ---

    zones_active: list[str] = Field(
        description=(
            "Schneider zones active in the system. "
            "Minimum ['input', 'reasoning']. "
            "Other zones: 'tool_execution', 'memory', 'inter_agent'."
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
    entry_points: list[EntryPoint] = Field(
        description=(
            "Attack entry points, each with a name and direction tag. "
            "Direction is one of: input (attacker can send data in), "
            "output (system sends data out), bidirectional (both)."
        ),
        min_length=1,
    )
    confidence: ConfidenceLevel = Field(
        description="How well the use-case description supported Stage 1 inferences.",
    )
    kc_subcodes: list[str] = Field(
        default_factory=list,
        description=(
            "OWASP KC (Key Component) sub-codes identifying the system's "
            "granular capabilities. E.g. ['KC1.1', 'KC4.1', 'KC6.1.1']."
        ),
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

    @field_validator("entry_points", mode="before")
    @classmethod
    def coerce_entry_points(
        cls, v: list[Union[str, dict, EntryPoint]],
    ) -> list[EntryPoint]:
        return _coerce_entry_points(v)

    @field_validator("kc_subcodes")
    @classmethod
    def validate_kc_subcodes(cls, v: list[str]) -> list[str]:
        if not v:
            return v
        # KCX-prefixed codes are scenario-forge extensions (NOT from OWASP)
        # and pass through without checking against VALID_KC_SUBCODES.
        invalid = [
            code for code in v
            if not code.startswith(KCX_PREFIX) and code not in VALID_KC_SUBCODES
        ]
        if invalid:
            raise ValueError(
                f"Invalid KC sub-code(s): {invalid}. "
                f"Valid codes: {sorted(VALID_KC_SUBCODES)} "
                f"(codes prefixed with '{KCX_PREFIX}' are also accepted)"
            )
        return sorted(set(v))

    @model_validator(mode="after")
    def validate_zones_and_flags(self) -> CapabilityProfile:
        """Cross-field validation for zone/flag consistency.

        When kc_subcodes is populated, zones_active and boolean flags are
        derived from them, overriding any explicitly provided value.  When
        kc_subcodes is empty (e.g. profile loaded from YAML via --profile),
        explicit zones and flags are kept as-is.
        """
        # Derive zones and flags from KC sub-codes when available
        if self.kc_subcodes:
            self.zones_active = derive_zones_from_kc(self.kc_subcodes)
            # Derive boolean flags — KC evidence upgrades False→True, never downgrades
            flags = derive_flags_from_kc(self.kc_subcodes)
            if flags.get("has_persistent_memory"):
                self.has_persistent_memory = True
            if flags.get("multi_agent"):
                self.multi_agent = True

        zones = set(self.zones_active)

        # Every LLM system must have input and reasoning
        if not {"input", "reasoning"}.issubset(zones):
            raise ValueError(
                "zones_active must contain at least ['input', 'reasoning'] "
                "— all LLM systems have input and reasoning"
            )

        # Zone values must be valid names
        if not zones.issubset(set(ZONE_NAMES)):
            invalid = zones - set(ZONE_NAMES)
            raise ValueError(
                f"zones_active contains invalid zone names: {invalid}. "
                f"Valid names: {ZONE_NAMES}"
            )

        # memory active implies has_persistent_memory
        if "memory" in zones and not self.has_persistent_memory:
            raise ValueError(
                "Zone 'memory' (Memory & State) active implies "
                "has_persistent_memory must be true"
            )

        # inter_agent active implies multi_agent
        if "inter_agent" in zones and not self.multi_agent:
            raise ValueError(
                "Zone 'inter_agent' (Inter-Agent Communication) active "
                "implies multi_agent must be true"
            )

        return self
