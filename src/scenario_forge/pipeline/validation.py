"""Validation passes for generated scenarios.

Contains:
  1. Phantom capability validation — flags scenarios that reference
     capabilities the system does not possess.
  2. Parsimony pruning — trims excess unannotated leaf nodes from
     attack trees to satisfy the parsimony budget constraint.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
    _repair_node,
)

if TYPE_CHECKING:
    from scenario_forge.models.capability_profile import CapabilityProfile
    from scenario_forge.models.scenario import ScenarioEnvelope

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Violation data structures
# ---------------------------------------------------------------------------


@dataclass
class PhantomViolation:
    """A single phantom capability violation detected in a scenario step."""

    step_number: int
    field: str  # "action" or "effect"
    category: (
        str  # e.g. "privilege_escalation", "credential_exposure", "code_execution"
    )
    matched_text: str  # the substring that triggered the match
    reason: str  # why this is phantom given the profile


@dataclass
class ValidationResult:
    """Result of phantom capability validation across a batch of scenarios."""

    valid_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, list[PhantomViolation]]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def valid_count(self) -> int:
        return len(self.valid_scenarios)

    @property
    def violation_categories(self) -> list[str]:
        """Unique violation categories across all flagged scenarios."""
        cats: set[str] = set()
        for _scenario, violations in self.flagged_scenarios:
            for v in violations:
                cats.add(v.category)
        return sorted(cats)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Privilege escalation: references to tiered privileges, elevated tokens,
# admin access, role escalation that the profile doesn't declare.
_PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\belevat(?:e|ed|es|ing)\b[^.]{0,30}\b(?:privil|token|access|role|permission)",
        r"\bprivil(?:ege|eged)\b[^.]{0,30}\b(?:escalat|tier|level|elevat)",
        r"\brole\s+escalat",
        r"\badmin(?:istrat(?:or|ive))?\s+(?:access|token|privil|credential|role)",
        r"\btier(?:ed)?\s+(?:privil|access|permission|token)",
        r"\belevated\s+token",
        r"\bescalat(?:e|ed|es|ing)\b[^.]{0,40}\b(?:privil|role|access|permission)",
        # v17 — escapee variants from QA-v16
        r"\bemergency\s+admin(?:istrat(?:or|ive))?\b",
        r"\badmin(?:istrat(?:or|ive))?\s+debug(?:ging)?\s+mode\b",
        r"\bself[- ](?:permission|elevat|escalat|privilege)",
        r"\bdynamic\s+privilege\b",
    ]
]

# Credential exposure: LLM outputting HTTP headers, auth tokens, API keys,
# credentials being exposed by the system.
_CREDENTIAL_EXPOSURE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:output|expos|leak|reveal|disclos|return|display|emit|dump|print|render)(?:s|ed|es|ing)?\b[^.]{0,40}\b(?:auth(?:orization)?\s+header|api[- _]?key|credential|secret|bearer\s+token|access[- _]?token)",
        r"\bhttp\s+(?:auth(?:orization)?|header)[^.]{0,30}\b(?:expos|leak|reveal|output|disclos)",
        r"\b(?:auth(?:orization)?\s+header|bearer\s+token)\b[^.]{0,30}\b(?:visible|plain|clear|expos|leak|output)",
        r"\binfrastructure\s+credential",
        # v17 — escapee variant: error messages leaking tokens/credentials
        r"\b(?:error|exception|diagnostic|debug)\s+messages?\b[^.]{0,40}\b(?:session\s+)?(?:token|credential|secret|api[- _]?key)",
    ]
]

# Code execution: generating or executing code (Python scripts, shell
# commands, etc.) when the profile lacks KC6.2.2 or KC6.5.
_CODE_EXECUTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:generat|creat|writ|execut|run|invok)(?:e|ed|es|ing)?\b[^.]{0,30}\bpython\s+(?:script|code|program)",
        r"\b(?:generat|creat|writ|execut|run|invok)(?:e|ed|es|ing)?\b[^.]{0,30}\bshell\s+(?:script|command|code)",
        r"\bexecut(?:e|ed|es|ing)\b[^.]{0,30}\b(?:arbitrary|malicious|crafted)\s+(?:code|script|command)",
        r"\b(?:run|execut)(?:s|ed|es|ing)?\s+(?:the\s+)?(?:python|bash|shell|powershell)\b",
        r"\bgenerat(?:e|ed|es|ing)\b[^.]{0,30}\b(?:executable|payload|script|code)\b",
        r"\b(?:arbitrary|remote)\s+code\s+execution\b",
        # v17 — escapee variant: execute/distribute malicious payloads
        r"\b(?:execut|distribut|deploy)\w*\b[^.]{0,40}\bmalicious\b[^.]{0,20}\bpayload",
        # v18 — code generation phrasing: noun-phrase generation references
        # Bare "(code|script) + generation noun" — e.g. "script synthesis"
        r"\b(?:code|script)\s+(?:generation|synthesis|assembly)\b",
        # Qualified noun + generation noun — e.g. "exploit code assembly",
        # "Python script generation", "obfuscated script synthesis"
        r"\b(?:exploit|malicious|obfuscated|weaponized|python|bash|shell|automated)\s+(?:code|script)\s+(?:generat|synthes|assembl|creat|construct)\w*",
        # Broader creation verbs + code/script/payload:
        # produce/craft/assemble/synthesize
        r"\b(?:produc|craft|assembl|synthesi[zs])(?:e|ed|es|ing)?\b[^.]{0,30}\b(?:code|script|payload)\b",
        # write/craft + script (without requiring language qualifier)
        r"\b(?:writ|craft)(?:e|ed|es|ing)?\b[^.]{0,30}\bscript\b",
        # produce + exploit
        r"\bproduc(?:e|ed|es|ing)?\b[^.]{0,30}\bexploit\b",
        # Qualified noun phrases implying code artifacts:
        # exploit/malicious/obfuscated/weaponized + code/script
        r"\b(?:exploit|malicious|obfuscated|weaponized)\s+(?:code|script)\b",
        # Language-specific or automated script references
        r"\b(?:python|automated)\s+script\b",
    ]
]

# Mass broadcasting: references to proactive mass communication, pushing
# notifications to all users, bulk messaging — phantom when the system is
# reactive (single-session, no persistent memory, no multi-agent).
_MASS_BROADCASTING_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bbroadcast\b",
        r"\bproactively\s+reach\s+out\b",
        r"\bpush\s+to\s+all\s+(?:users|customers|clients|accounts)\b",
        r"\bmass\s+(?:notification|message|communication|email)\b",
        r"\bsend\s+to\s+thousands\b",
        r"\bbulk\s+messag(?:e|es|ing)\b",
        r"\bnotify\s+all\s+(?:customers|users|clients|accounts)\b",
        r"\bsend\s+(?:alerts?|messages?|notifications?)\s+to\s+(?:all|every)\b",
        # v17 — escapee variants: mass phishing / mass distribution
        r"\bmass\s+phishing\b",
        r"\bmass\b[^.]{0,30}\bdistribut(?:e|ed|es|ing|ion)\b",
    ]
]

# Cross-session / cross-user access: references to accessing data or sessions
# belonging to other users — phantom when the system operates within a single
# authenticated session with no persistent memory.
_CROSS_SESSION_ACCESS_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bother\s+user(?:'?s?)?\b",
        r"\bdifferent\s+account\b",
        r"\bcross[- ]user\b",
        r"\banother\s+customer(?:'?s?)?\b",
        r"\btarget\s+victim\b",
        r"\baccess\b[^.]{0,30}\bother\b[^.]{0,30}\bsession",
        r"\bprocess\b[^.]{0,30}\bunauthorized\b[^.]{0,30}\buser",
        r"\bwrite\b[^.]{0,30}\bas\b[^.]{0,30}\bexternal\b",
        r"\baccess\b[^.]{0,30}\bother\b[^.]{0,30}\b(?:user|customer|account)",
        # v17 — escapee variant: across multiple sessions
        r"\bacross\b[^.]{0,30}\bsessions\b",
    ]
]

# Audit / monitoring write access: references to modifying audit trails,
# tampering with logs, suppressing alerts — almost always phantom since
# agents read from monitoring but don't write to it.
_AUDIT_MONITORING_WRITE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bmodify\s+audit\s+trail\b",
        r"\balter\s+(?:the\s+)?logs?\b",
        r"\btamper\b[^.]{0,30}\blogging\b",
        r"\bwrite\s+to\s+monitoring\b",
        r"\bcontrol\b[^.]{0,30}\baudit\b",
        r"\bmanipulat(?:e|ed|es|ing)\b[^.]{0,30}\blog\s+entr(?:y|ies)\b",
        r"\bsuppress\b[^.]{0,30}\balerts?\b",
        r"\bdisable\b[^.]{0,30}\bmonitoring\b",
        r"\berase\b[^.]{0,30}\b(?:audit|log)\b",
        r"\btamper\b[^.]{0,30}\baudit\b",
        r"\bmodify\b[^.]{0,30}\b(?:audit|log)\s+(?:record|entr|data)\b",
        # v17 — escapee variants from QA-v16
        r"\b(?:session|chat|conversation)\s+history\s+(?:reset|clear|delet|wip|purg)",
        r"\b(?:reset|clear|delet|wip|purg)\w*\b[^.]{0,20}\b(?:session|chat)\s+history\b",
        r"\b(?:generat|creat|fabricat)(?:e|ed|es|ing)?\b[^.]{0,30}\b(?:deceptive|false|fake|fraudulent|misleading)\s+(?:\w+\s+){0,2}(?:report|record|alert)",
        r"\btransaction\s+(?:description|record|detail|log)\s+(?:modif|alter|chang|edit|tamper)",
        r"\b(?:modif|alter|chang|tamper)\w*\b[^.]{0,20}\btransaction\s+(?:description|record|detail|log)",
        r"\boverwrite\b[^.]{0,20}\b(?:audit|log|session\s+history)\b",
    ]
]


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _check_privilege_escalation(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references phantom privilege escalation.

    Privilege escalation is phantom when the profile's kc_subcodes and
    entry_points don't include any admin/role-management capabilities.
    """
    # If the profile explicitly declares admin-level entry points or
    # relevant KC subcodes, privilege references are legitimate.
    admin_entry = any(
        "admin" in ep.name.lower() or "role" in ep.name.lower()
        for ep in profile.entry_points
    )
    # KC6.4 = identity / auth management; KC6.3 = database (may include role tables)
    admin_kc = any(
        code.startswith("KC6.4") or code.startswith("KC6.3")
        for code in profile.kc_subcodes
    )
    if admin_entry or admin_kc:
        return None

    for pattern in _PRIVILEGE_ESCALATION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_credential_exposure(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references phantom credential exposure.

    Credential exposure is phantom when the profile doesn't include
    capabilities that handle raw HTTP credentials (KC6.1.2 = extensive
    API access with auth details, or entry points mentioning API/HTTP).
    """
    # If profile declares extensive API access that handles auth, or
    # entry points involving APIs/HTTP, credential references may be legit.
    api_kc = any(
        code.startswith("KC6.1.2") or code.startswith("KC6.1.3")
        for code in profile.kc_subcodes
    )
    api_entry = any(
        "api" in ep.name.lower() or "http" in ep.name.lower()
        for ep in profile.entry_points
    )
    if api_kc or api_entry:
        return None

    for pattern in _CREDENTIAL_EXPOSURE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_code_execution(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references phantom code execution.

    Code execution is phantom when the profile's kc_subcodes don't include
    KC6.2.2 (extensive code execution) or KC6.5 (PC/filesystem operations).
    """
    has_code_exec = any(
        code.startswith("KC6.2.2") or code.startswith("KC6.5")
        for code in profile.kc_subcodes
    )
    if has_code_exec:
        return None

    for pattern in _CODE_EXECUTION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_mass_broadcasting(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references phantom mass broadcasting.

    Mass broadcasting is phantom when the system is reactive (single-session,
    no persistent memory, no multi-agent coordination).  A system that lacks
    both persistent memory and multi-agent capabilities operates within
    individual user sessions and cannot proactively push to many users.
    """
    # If the profile declares persistent memory or multi-agent, the system
    # may have infrastructure for mass communication.
    if profile.has_persistent_memory or profile.multi_agent:
        return None

    for pattern in _MASS_BROADCASTING_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_cross_session_access(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references phantom cross-session access.

    Cross-session/cross-user access is phantom when the system operates
    within a single authenticated session.  The primary indicator is
    has_persistent_memory=False — without persistent state the system
    cannot reach across sessions or users.
    """
    if profile.has_persistent_memory:
        return None

    for pattern in _CROSS_SESSION_ACCESS_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_audit_monitoring_write(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references phantom audit/monitoring writes.

    Audit/monitoring write access is almost always phantom — agents read
    from monitoring systems but do not have write access to audit trails.
    No KC subcode in the current taxonomy grants audit-write capability,
    so this check always fires regardless of profile.
    """
    # No profile-based suppression — audit-write is always phantom in the
    # current KC taxonomy.  If a future KC subcode is added for audit-write,
    # add suppression logic here.

    for pattern in _AUDIT_MONITORING_WRITE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Phantom tool invocation — patterns and helpers
# ---------------------------------------------------------------------------

# Patterns to extract named tool/API/endpoint references from narrative text.
# Each pattern's group 1 captures the raw name preceding the keyword.
# The first three patterns require title-case words ([A-Z][a-z]+) to
# discriminate proper-noun tool names from generic references.
_PHANTOM_TOOL_EXTRACTORS = [
    # "<Title Case Name> tool" — e.g. "Policy Audit tool invocation"
    re.compile(
        r"\b((?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+){0,4})\s+tool\b"
    ),
    # "<Title Case Name> API" — e.g. "Payment Processing API"
    re.compile(
        r"\b((?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+){0,4})\s+API\b"
    ),
    # "<Title Case Name> endpoint" — e.g. "Admin Configuration endpoint"
    re.compile(
        r"\b((?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+){0,4})\s+endpoint\b"
    ),
    # "API calls to <action>" — e.g. "API calls to overwrite audit logs"
    re.compile(
        r"\bAPI\s+calls?\s+to\s+(\w+(?:\s+\w+){0,5})",
        re.IGNORECASE,
    ),
]

# Words stripped from the leading/trailing edges of extracted tool names.
_TOOL_NAME_NOISE = frozenset({
    "the", "a", "an", "this", "that", "its", "our", "their",
    "some", "each", "every", "my", "your",
})

# Stop words excluded from word-overlap comparisons.
_OVERLAP_STOP = _TOOL_NAME_NOISE | frozenset({
    "and", "or", "for", "to", "in", "on", "at", "by", "of", "with",
})


def _clean_tool_name(raw: str) -> str | None:
    """Strip leading/trailing noise words from an extracted tool name.

    Returns the cleaned name in lowercase, or ``None`` if the remaining
    name has fewer than 2 significant words (too generic to be a named
    tool reference).
    """
    words = raw.split()
    while words and words[0].lower() in _TOOL_NAME_NOISE:
        words.pop(0)
    while words and words[-1].lower() in _TOOL_NAME_NOISE:
        words.pop()
    if len(words) < 2:
        return None
    return " ".join(words).lower()


def _check_phantom_tool_invocation(
    text: str,
    profile: CapabilityProfile,
) -> str | None:
    """Return a match string if text references a tool/API/endpoint not in the profile.

    Extracts named tool, API, and endpoint references from the text and
    compares them against the profile's ``entry_points``.  A reference is
    phantom if no entry-point name contains the referenced name
    (case-insensitive substring match for named tools, word-overlap match
    for action-based API references).
    """
    ep_names = [ep.name.lower() for ep in profile.entry_points]

    for idx, pattern in enumerate(_PHANTOM_TOOL_EXTRACTORS):
        for m in pattern.finditer(text):
            raw_name = m.group(1).strip()
            name = _clean_tool_name(raw_name)
            if name is None:
                continue

            if idx < 3:
                # Named tool/API/endpoint — substring containment check
                found = any(
                    name in ep_name or ep_name in name
                    for ep_name in ep_names
                )
            else:
                # "API calls to <action>" — word-overlap check
                name_words = set(name.split()) - _OVERLAP_STOP
                found = False
                for ep_name in ep_names:
                    ep_words = set(ep_name.split()) - _OVERLAP_STOP
                    if name_words and ep_words and name_words & ep_words:
                        found = True
                        break

            if not found:
                return m.group(0)

    return None


# ---------------------------------------------------------------------------
# Main validation function
# ---------------------------------------------------------------------------

_CHECKERS = [
    (
        "privilege_escalation",
        _check_privilege_escalation,
        "Profile lacks admin entry points and KC6.3/KC6.4 subcodes — "
        "dynamic privilege escalation is a phantom capability.",
    ),
    (
        "credential_exposure",
        _check_credential_exposure,
        "Profile lacks KC6.1.2/KC6.1.3 (extensive API access) and no "
        "API/HTTP entry points — infrastructure credential exposure "
        "is a phantom capability.",
    ),
    (
        "code_execution",
        _check_code_execution,
        "Profile lacks KC6.2.2 (code execution) and KC6.5 (filesystem) "
        "— arbitrary code execution is a phantom capability.",
    ),
    (
        "mass_broadcasting",
        _check_mass_broadcasting,
        "Profile lacks persistent memory and multi-agent capabilities "
        "— the system is reactive (single-session) and cannot broadcast "
        "to multiple users.",
    ),
    (
        "cross_session_access",
        _check_cross_session_access,
        "Profile lacks persistent memory — the system operates within "
        "a single authenticated session and cannot access other users' "
        "sessions or data.",
    ),
    (
        "audit_monitoring_write",
        _check_audit_monitoring_write,
        "No KC subcode grants audit/monitoring write access — agents "
        "read from monitoring systems but cannot modify audit trails "
        "or suppress alerts.",
    ),
    (
        "phantom_tool_invocation",
        _check_phantom_tool_invocation,
        "Narrative references a tool, API, or endpoint not found in "
        "the profile's entry points — this capability is phantom.",
    ),
]


def validate_phantom_capabilities(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> ValidationResult:
    """Validate scenarios against the capability profile for phantom capabilities.

    Examines each scenario's narrative steps (action and effect fields) and
    the Gherkin behavior_spec text, flagging scenarios whose content
    references capabilities the system doesn't possess according to the
    profile.

    Returns a ``ValidationResult`` with valid and flagged scenarios.
    """
    result = ValidationResult()

    for scenario in scenarios:
        violations: list[PhantomViolation] = []

        for step in scenario.narrative.steps:
            for field_name in ("action", "effect"):
                text = getattr(step, field_name)
                for category, checker, reason in _CHECKERS:
                    matched = checker(text, profile)
                    if matched is not None:
                        violations.append(
                            PhantomViolation(
                                step_number=step.step_number,
                                field=field_name,
                                category=category,
                                matched_text=matched,
                                reason=reason,
                            )
                        )

        # Also check Gherkin behavior_spec text
        if scenario.behavior_spec and isinstance(scenario.behavior_spec, str):
            for category, checker, reason in _CHECKERS:
                matched = checker(scenario.behavior_spec, profile)
                if matched is not None:
                    violations.append(
                        PhantomViolation(
                            step_number=0,
                            field="behavior_spec",
                            category=category,
                            matched_text=matched,
                            reason=reason,
                        )
                    )

        if violations:
            result.flagged_scenarios.append((scenario, violations))
        else:
            result.valid_scenarios.append(scenario)

    return result


# ---------------------------------------------------------------------------
# Parsimony pruning — data structures
# ---------------------------------------------------------------------------


@dataclass
class PrunedNode:
    """Record of a single pruned leaf node."""

    node_id: str
    label: str
    parent_gate: str  # "AND" or "OR"
    reason: str  # why it was safe to prune


@dataclass
class ParsimonyResult:
    """Result of parsimony pruning across a batch of scenarios."""

    compliant_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    pruned_scenarios: list[tuple[ScenarioEnvelope, list[PrunedNode]]] = field(
        default_factory=list
    )
    unprunable_scenarios: list[tuple[ScenarioEnvelope, int, int]] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Parsimony pruning — helpers
# ---------------------------------------------------------------------------


def _collect_technique_ids(node: AttackTreeNode) -> set[str]:
    """Walk a tree and return the set of unique technique_ids."""
    ids: set[str] = set()
    if node.technique_id:
        ids.add(node.technique_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_technique_ids(child))
    return ids


def _collect_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes in the tree."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    if node.children:
        for child in node.children:
            leaves.extend(_collect_leaves(child))
    return leaves


def _find_parent(
    root: AttackTreeNode, target_id: str
) -> AttackTreeNode | None:
    """Find the parent of the node with the given id."""
    if root.children:
        for child in root.children:
            if child.id == target_id:
                return root
            result = _find_parent(child, target_id)
            if result is not None:
                return result
    return None


def _sibling_labels(parent: AttackTreeNode, node_id: str) -> list[str]:
    """Return labels of siblings (other children of the same parent)."""
    if not parent.children:
        return []
    return [c.label for c in parent.children if c.id != node_id]


def _token_overlap_ratio(label: str, siblings: list[str]) -> float:
    """Compute how much a label's tokens overlap with sibling labels.

    Higher ratio = more redundant = better pruning candidate.
    """
    if not siblings:
        return 0.0
    tokens = set(label.lower().split())
    if not tokens:
        return 0.0
    sibling_tokens: set[str] = set()
    for sib in siblings:
        sibling_tokens.update(sib.lower().split())
    overlap = tokens & sibling_tokens
    return len(overlap) / len(tokens)


def _pruning_priority(
    leaf: AttackTreeNode,
    parent: AttackTreeNode,
    siblings: list[str],
) -> tuple[int, float, int]:
    """Return a sort key for pruning priority.

    Lower values = prune first.
    Priority order:
      1. AND-gate children before OR-gate children (AND=0, OR=1)
      2. Higher token overlap with siblings (negate for ascending sort)
      3. Shorter labels (less semantic content)
    """
    gate_priority = 0 if parent.gate == GateType.AND else 1
    overlap = _token_overlap_ratio(leaf.label, siblings)
    return (gate_priority, -overlap, len(leaf.label))


def _remove_child(parent: AttackTreeNode, child_id: str) -> None:
    """Remove a child node from a parent's children list."""
    if parent.children:
        parent.children = [c for c in parent.children if c.id != child_id]


def _repair_tree_model(root_dict: dict[str, Any]) -> dict[str, Any]:
    """Apply _repair_node to collapse single-child gates after pruning."""
    return _repair_node(root_dict)


# ---------------------------------------------------------------------------
# Parsimony pruning — main function
# ---------------------------------------------------------------------------


def enforce_parsimony(
    scenarios: list[ScenarioEnvelope],
    max_leaf_factor: int = 2,
    max_leaf_offset: int = 1,
) -> ParsimonyResult:
    """Prune excess unannotated leaves from attack trees.

    For each scenario, computes a leaf budget based on the number of
    unique technique_ids in the tree:

        budget = max_leaf_factor * technique_count + max_leaf_offset

    If technique_count is 0, a fallback budget of 3 is used.

    Leaves without a technique_id are pruning candidates.  They are
    removed one at a time (most redundant first) until the leaf count
    is within budget, or no more safe candidates remain.

    After pruning, single-child AND/OR gates are collapsed via
    ``_repair_node`` and the resulting tree is re-validated with Pydantic.
    """
    result = ParsimonyResult()

    for scenario in scenarios:
        tree = scenario.attack_tree
        technique_ids = _collect_technique_ids(tree.root)
        technique_count = len(technique_ids)

        if technique_count == 0:
            budget = 3
        else:
            budget = max_leaf_factor * technique_count + max_leaf_offset

        leaves = _collect_leaves(tree.root)
        leaf_count = len(leaves)

        if leaf_count <= budget:
            result.compliant_scenarios.append(scenario)
            continue

        # Deep-copy so we don't mutate the original
        pruned_scenario = copy.deepcopy(scenario)
        pruned_root = pruned_scenario.attack_tree.root
        pruned_nodes: list[PrunedNode] = []

        while True:
            current_leaves = _collect_leaves(pruned_root)
            current_leaf_count = len(current_leaves)

            if current_leaf_count <= budget:
                break

            # Find pruning candidates: unannotated leaves
            candidates: list[
                tuple[AttackTreeNode, AttackTreeNode, list[str]]
            ] = []
            for leaf in current_leaves:
                if leaf.technique_id:
                    continue  # never prune annotated leaves
                parent = _find_parent(pruned_root, leaf.id)
                if parent is None:
                    continue  # root node, can't prune
                # Must not leave parent with fewer than 2 children
                # (we'll handle the collapse after removal, but we need
                # at least 2 children to remove one safely)
                if parent.children and len(parent.children) < 2:
                    continue  # already at minimum
                siblings = _sibling_labels(parent, leaf.id)
                candidates.append((leaf, parent, siblings))

            if not candidates:
                break  # no safe candidates remain

            # Sort by pruning priority
            candidates.sort(
                key=lambda x: _pruning_priority(x[0], x[1], x[2])
            )

            # Prune the best candidate
            leaf, parent, siblings = candidates[0]
            _remove_child(parent, leaf.id)
            pruned_nodes.append(
                PrunedNode(
                    node_id=leaf.id,
                    label=leaf.label,
                    parent_gate=parent.gate.value,
                    reason=(
                        f"Unannotated leaf under {parent.gate.value} gate; "
                        f"token overlap with siblings: "
                        f"{_token_overlap_ratio(leaf.label, siblings):.0%}"
                    ),
                )
            )

            # If parent now has exactly 1 child, collapse it
            if parent.children and len(parent.children) == 1:
                # Convert to dict, repair, convert back
                root_dict = pruned_root.model_dump()
                repaired_dict = _repair_tree_model(root_dict)
                pruned_root = AttackTreeNode.model_validate(repaired_dict)
                pruned_scenario.attack_tree = AttackTree(
                    id=pruned_scenario.attack_tree.id,
                    seed_id=pruned_scenario.attack_tree.seed_id,
                    goal=pruned_scenario.attack_tree.goal,
                    root=pruned_root,
                )

        # Re-validate the pruned tree
        final_leaves = _collect_leaves(pruned_root)
        final_leaf_count = len(final_leaves)

        if final_leaf_count <= budget:
            # Validate with Pydantic to ensure structural integrity
            try:
                pruned_scenario.attack_tree = AttackTree.model_validate(
                    pruned_scenario.attack_tree.model_dump()
                )
                result.pruned_scenarios.append(
                    (pruned_scenario, pruned_nodes)
                )
            except Exception as exc:
                logger.warning(
                    "Pruned tree for %s failed Pydantic validation: %s",
                    scenario.scenario_id,
                    exc,
                )
                result.unprunable_scenarios.append(
                    (scenario, leaf_count, budget)
                )
        else:
            result.unprunable_scenarios.append(
                (scenario, final_leaf_count, budget)
            )

    return result
