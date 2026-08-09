"""Regression tests for the SP1 prompt bug fixes."""

from __future__ import annotations

import pytest

from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.system_model import PROMPTS_DIR


_REQUIRED_CONTENT = {
    "stage1a_system.j2": (
        "Every loss must be traceable to either a risk card or a specific feature "
        "described in the use-case text",
        "Every hazard must reference a concrete component, data flow, or capability "
        "from the use-case description",
    ),
    "stage1b_system.j2": (
        "Every tool in tool_inventory must be explicitly mentioned or directly implied "
        "by the use-case description",
        "Every entry point must correspond to an actual interface described in the use case",
    ),
    "stage2_call2_system.j2": (
        "Check the capability profile's active zones",
        "When `tool_execution` is active: require a responsibility governing tool "
        "parameter validation and action selection",
        "When `memory` is active: require a responsibility for context management and "
        "memory lifecycle",
        "When `hitl` is true: require a responsibility for escalation and human oversight",
        "When `inter_agent` is active: require a responsibility for inter-agent "
        "coordination and message validation",
        "This should be a hard requirement, not a suggestion",
        "Each control action must describe a single discrete action",
        "Split composite actions into separate CAs",
        "Approve or reject request",
        "CA-X-1 Approve request",
        "CA-X-2 Reject request",
        "Execute or deny command",
        "A control action that contains 'or', 'and', or similar conjunctions is likely "
        "composite and should be split",
    ),
    "stage2_call3_system.j2": (
        "Coordination links capture dependencies between responsibilities",
        "share state, data, or control flow",
        "inter-controller coordination",
        "Two responsibilities sharing a process model part not connected by a control action",
        "One responsibility's feedback channel updates a PM part that another responsibility controls",
        "Two responsibilities need to agree on a shared resource",
        "An empty coordination_links list is acceptable only when no two responsibilities "
        "share state, data, or control flow",
    ),
}


@pytest.mark.parametrize("template_name, fragments", _REQUIRED_CONTENT.items())
def test_sp1_prompt_bug_fix_content_is_in_template(
    template_name: str, fragments: tuple[str, ...]
) -> None:
    text = (PROMPTS_DIR / template_name).read_text()
    assert all(fragment in text for fragment in fragments)


@pytest.mark.parametrize("template_name, fragments", _REQUIRED_CONTENT.items())
def test_sp1_prompt_bug_fix_content_renders(
    template_name: str, fragments: tuple[str, ...]
) -> None:
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(template_name)
    assert all(fragment in rendered for fragment in fragments)


@pytest.mark.parametrize(
    "template_name, section",
    (
        ("stage1a_system.j2", "## Quality requirements"),
        ("stage1b_system.j2", "## Quality requirements"),
        ("stage2_call2_system.j2", "## ID conventions"),
        ("stage2_call3_system.j2", "## Structural requirements"),
    ),
)
def test_sp1_prompt_bug_fixes_preserve_existing_sections(
    template_name: str, section: str
) -> None:
    text = (PROMPTS_DIR / template_name).read_text()
    assert section in text
