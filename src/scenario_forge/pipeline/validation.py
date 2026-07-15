"""Phantom capability validation for generated scenarios.

Checks each scenario's narrative steps against the declared capability
profile and flags scenarios that reference capabilities the system does
not actually possess ("phantom capabilities").

Detection is rule-based (keyword/pattern matching), not LLM-based.
Tuned for precision — false negatives are acceptable, false positives
are not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scenario_forge.models.capability_profile import CapabilityProfile
    from scenario_forge.models.scenario import ScenarioEnvelope


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
        r"\bgenerat(?:e|ed|es|ing)\b[^.]{0,30}\b(?:executable|payload|script|code\s+snippet)",
        r"\b(?:arbitrary|remote)\s+code\s+execution\b",
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
]


def validate_phantom_capabilities(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> ValidationResult:
    """Validate scenarios against the capability profile for phantom capabilities.

    Examines each scenario's narrative steps (action and effect fields) and
    flags scenarios whose steps reference capabilities the system doesn't
    possess according to the profile.

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

        if violations:
            result.flagged_scenarios.append((scenario, violations))
        else:
            result.valid_scenarios.append(scenario)

    return result
