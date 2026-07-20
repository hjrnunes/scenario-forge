"""Module-level constants for the generate package."""

from __future__ import annotations

from scenario_forge.data.atlas import (
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_NAMES,
)

# ---------------------------------------------------------------------------
# Generator version
# ---------------------------------------------------------------------------

_GENERATOR_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Canonical threat_id -> violation category tag mapping
# Source of truth: call3_system.j2 lines 88-108.
# Extracted here so the deterministic Gherkin template can assign the tag
# without an LLM round-trip.
# ---------------------------------------------------------------------------

THREAT_VIOLATION_CATEGORY: dict[str, str] = {
    "T1": "uncontrolled-autonomy",
    "T2": "insufficient-access-controls",
    "T3": "privilege-compromise",
    "T4": "resource-overload",
    "T5": "memory-integrity-breach",
    "T6": "goal-manipulation",
    "T7": "misaligned-and-deceptive-behavior",
    "T8": "repudiation-and-untraceability",
    "T9": "improper-output-handling",
    "T10": "hitl-bypass",
    "T11": "unexpected-code-execution",
    "T12": "agent-communication-poisoning",
    "T13": "rogue-agent",
    "T14": "human-attack-on-multi-agent",
    "T15": "human-manipulation",
    "T16": "insecure-inter-agent-protocol",
    "T17": "insufficient-logging",
}


# ---------------------------------------------------------------------------
# Entry point zone keywords for diversity helpers
# ---------------------------------------------------------------------------

# Maps keywords found in entry point descriptions to the Schneider zones
# they naturally feed into.  A simple heuristic — sufficient for pre-alpha.
_ENTRY_POINT_ZONE_KEYWORDS: dict[str, list[str]] = {
    "input": ["input"],
    "prompt": ["input"],
    "chat": ["input"],
    "upload": ["input"],
    "form": ["input"],
    "api": ["input", "tool_execution"],
    "endpoint": ["input", "tool_execution"],
    "webhook": ["input", "tool_execution"],
    "admin": ["reasoning", "tool_execution"],
    "console": ["reasoning", "tool_execution"],
    "dashboard": ["reasoning"],
    "config": ["reasoning", "tool_execution"],
    "tool": ["tool_execution"],
    "plugin": ["tool_execution"],
    "extension": ["tool_execution"],
    "memory": ["memory"],
    "state": ["memory"],
    "storage": ["memory"],
    "database": ["memory"],
    "agent": ["inter_agent"],
    "inter-agent": ["inter_agent"],
    "message": ["inter_agent"],
    "channel": ["inter_agent"],
}


# ---------------------------------------------------------------------------
# Pattern stop words for narrative keyword extraction
# ---------------------------------------------------------------------------

# Stop words excluded from attack pattern keyword extraction.
_PATTERN_STOP_WORDS: set[str] = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "but",
    "in",
    "on",
    "at",
    "to",
    "for",
    "of",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "by",
    "from",
    "with",
    "that",
    "this",
    "it",
    "as",
    "its",
    "i",
    "my",
    "me",
    "we",
    "our",
    "zone",
    "step",
    "attack",
    "attacker",
    "system",
    "use",
    "using",
    # Security-domain common words that appear in nearly every narrative
    # and dominate counts without adding discriminative signal.
    "exploit",
    "model",
    "data",
    "user",
    "access",
    "information",
    "security",
    "service",
    "response",
    "request",
    "input",
    "output",
    "process",
    "control",
    "policy",
    "target",
    "threat",
    "risk",
    "vulnerability",
    "lack",
    "agent",
    "prompt",
    "reasoning",
    "tool",
}


# ---------------------------------------------------------------------------
# Canonical attack phase vocabulary for structural diversity
# ---------------------------------------------------------------------------

_PHASE_KEYWORDS: dict[str, list[str]] = {
    "poison": [
        "poison",
        "taint",
        "corrupt",
        "contaminate",
        "inject false",
        "plant false",
        "fabricat",
        "supply-chain",
    ],
    "inject": ["inject", "craft", "embed", "insert", "smuggle", "implant"],
    "probe": [
        "probe",
        "reconn",
        "enumerate",
        "discover",
        "scan",
        "map",
        "fingerprint",
        "survey",
    ],
    "hallucinate": [
        "hallucin",
        "confabulat",
        "fabricat",
        "generate false",
        "produce false",
        "make up",
        "invent",
    ],
    "exfiltrate": [
        "exfiltrat",
        "extract",
        "steal",
        "leak",
        "siphon",
        "harvest",
        "scrape",
        "dump",
    ],
    "persist": [
        "persist",
        "store",
        "memory",
        "cache",
        "retain",
        "embed in",
        "long-term",
        "permanent",
    ],
    "escalate": ["escalat", "privilege", "elevat", "admin", "root", "lateral", "pivot"],
    "bypass": [
        "bypass",
        "circumvent",
        "evade",
        "defeat",
        "overwhelm",
        "fatigue",
        "exhaust",
        "fool",
        "trick review",
    ],
    "deny": [
        "deny",
        "denial",
        "flood",
        "overwhelm",
        "exhaust",
        "degrade",
        "disrupt",
        "dos",
    ],
    "manipulate": [
        "manipulat",
        "alter",
        "modify",
        "tamper",
        "forge",
        "spoof",
        "impersonat",
    ],
}


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 v2025 name lookup (for descriptive taxonomy refs)
# ---------------------------------------------------------------------------

_OWASP_LLM_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


# ---------------------------------------------------------------------------
# Actor-related constants
# ---------------------------------------------------------------------------

_CAPABILITY_ORDER: list[str] = ["novice", "intermediate", "advanced", "expert"]

# Minimum capability levels by actor type. If the LLM returns a level below
# the floor, we bump it up and log a warning. This is defence-in-depth
# behind the prompt constraint in call0_system.j2.
_CAPABILITY_FLOORS: dict[str, str] = {
    "nation-state": "advanced",
    "supply-chain-actor": "advanced",
    "automated-agent": "intermediate",
}

# Threat IDs where negligent-insider is structurally implausible.
# These threats describe inherently adversarial actions (prompt injection,
# privilege escalation, identity spoofing, etc.) that cannot arise from
# mere negligence.  For these seeds, "negligent-insider" is excluded from
# the actor-type pool *before* the LLM call, preventing the generator from
# producing an incoherent actor profile.
#
# Allowed (negligent-insider plausible):
#   T2  — Tool Misuse (accidental misuse)
_ADVERSARIAL_ONLY_THREATS: frozenset[str] = frozenset({
    "T3",   # Privilege Compromise
    "T6",   # Intent Breaking / Goal Manipulation (prompt injection)
    "T7",   # Misaligned & Deceptive Behaviors (emergent agent misalignment)
    "T8",   # Repudiation & Untraceability (deliberate audit trail manipulation)
    "T9",   # Identity Spoofing
    "T10",  # Overwhelming HITL (deliberate flooding)
    "T15",  # Human Manipulation
})

# Technique pairs that form a natural execution chain (one enables the other).
# When a 2-technique seed's pair is in this set, the multi-technique escalation
# rule (R2) does NOT trigger — the chain is a single logical step.
CHAIN_TECHNIQUE_PAIRS: frozenset[tuple[str, str]] = frozenset({
    ("AML.T0051.001", "AML.T0067"),
    ("AML.T0066", "AML.T0057"),
    ("AML.T0070", "AML.T0057"),
})

ALL_ACTOR_TYPES: frozenset[str] = frozenset({
    "adversarial-user",
    "malicious-insider",
    "negligent-insider",
    "supply-chain-actor",
    "cybercriminal",
    "nation-state",
    "hacktivist",
    "competitor",
    "automated-agent",
})

# Actor-goal incompatibility map.  For each goal_id, lists actor types
# whose motivational profile is structurally incompatible with that goal.
# AB-3 (Fraud Facilitation) is purely financially motivated — hacktivists
# (ideological) and competitors (competitive advantage) do not pursue
# raw financial fraud without a matching motive.
_ACTOR_GOAL_INCOMPATIBLE: dict[str, frozenset[str]] = {
    "AB-3": frozenset({"hacktivist", "competitor"}),
}

# Keywords in intentions that indicate adversarial (non-negligent) behaviour.
_ADVERSARIAL_INTENTION_KEYWORDS: set[str] = {
    "exploit",
    "extract",
    "bypass",
    "fraud",
    "inject",
    "jailbreak",
    "manipulate",
    "exfiltrate",
    "compromise",
    "steal",
    "hijack",
    "confuse",
    "trick",
    "probe",
    "probing",
    "deceive",
    "fool",
    "subvert",
    "circumvent",
    "coerce",
    "impersonate",
    # v16 escapees — adversarial language that negligent-insiders should never use
    "craft",
    "phishing",
    "destroy",
    "forge",
    "fabricate",
    "sabotage",
    "disrupt",
    "corrupt",
    "undermine",
    "tamper",
    "obfuscate",
    "evade",
    # additional adversarial-only verbs
    "spoof",
    "weaponize",
    "poison",
    "siphon",
    "infiltrate",
    "counterfeit",
}


# ---------------------------------------------------------------------------
# Goal zone requirements and HITL
# ---------------------------------------------------------------------------

# Sub-goals that require specific zones to be active in the target system.
# If a zone is listed here but not in the profile's zones_active, the
# sub-goal is filtered out as irrelevant.
_GOAL_ZONE_REQUIREMENTS: dict[str, list[str]] = {
    "AV-4": ["reasoning"],  # Alert saturation needs HITL (checked separately)
    "AV-5": ["inter_agent"],  # Cascading failure needs multi-agent
    "IN-3": ["tool_execution"],  # Decision corruption needs tool execution
    "IN-4": ["reasoning"],  # Goal manipulation needs reasoning (usually present)
    "IN-5": ["memory"],  # Memory poisoning needs persistent memory
    "IN-6": ["inter_agent"],  # Trust exploitation needs inter-agent or tool_execution
    "PR-5": ["memory"],  # Cross-session leakage needs persistent memory
    "AB-3": ["tool_execution"],  # Fraud facilitation needs tool execution
    "AB-6": ["tool_execution"],  # Privilege escalation needs tool execution
    "AB-7": ["inter_agent"],  # Impersonation needs inter-agent
    "AB-8": ["tool_execution"],  # Evidence destruction needs tool execution
}

# Sub-goals that specifically require HITL to be true.
_GOAL_HITL_REQUIREMENTS: set[str] = {"AV-4"}

# Threat-specific sub-goal exclusions.  These goals are structurally
# implausible for the given threat regardless of system capabilities.
_THREAT_GOAL_EXCLUSIONS: dict[str, set[str]] = {
    # T2 (Prompt Injection): about data poisoning / injection, not safety bypass
    "T2": {"AB-1"},  # AB-1 Jailbreak is content bypass, not injection mechanism
    # T9 (Identity Spoofing): about impersonation, not model extraction
    "T9": {"PR-3"},  # PR-3 Model Extraction is theft, not spoofing
    # T10 (Overwhelming HITL): about trust calibration degradation, not flooding
    "T10": {"AV-1", "AV-5"},  # AV-1 Service Denial / AV-5 Cascading Failure are DoS, not trust abuse
    # T15 (Human Manipulation): no evidence destruction or resource hijack
    "T15": {"AB-8", "AB-9"},
}


# ---------------------------------------------------------------------------
# ATLAS technique backward-compatible aliases
# ---------------------------------------------------------------------------

# Backward-compatible aliases for in-module references.
_ATLAS_TECHNIQUE_NAMES = ATLAS_TECHNIQUE_NAMES
_ATLAS_TECHNIQUE_DESCRIPTIONS = ATLAS_TECHNIQUE_DESCRIPTIONS


# ---------------------------------------------------------------------------
# Zone-to-MAESTRO mapping
# ---------------------------------------------------------------------------

_ZONE_TO_DEFAULT_MAESTRO: dict[str, int] = {
    "input": 1,  # Input -> Foundation Models
    "reasoning": 3,  # Reasoning -> Agent Frameworks
    "tool_execution": 4,  # Tool Execution -> Deployment Infrastructure
    "memory": 2,  # Memory -> Data Operations
    "inter_agent": 7,  # Inter-Agent -> Agent Ecosystem
}


# ---------------------------------------------------------------------------
# Consistency enforcement constants
# ---------------------------------------------------------------------------

# Configurable floor for step-node correspondence ratio.
_STEP_NODE_CORRESPONDENCE_FLOOR = 0.7

# Maximum number of Call 2 retries for consistency violations.
_CONSISTENCY_MAX_RETRIES = 2


# ---------------------------------------------------------------------------
# Call 3 constants
# ---------------------------------------------------------------------------

_ASSERTIONS_MARKER = "{ASSERTIONS}"
