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
        "admin" in ep.lower() or "role" in ep.lower() for ep in profile.entry_points
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
        "api" in ep.lower() or "http" in ep.lower() for ep in profile.entry_points
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
