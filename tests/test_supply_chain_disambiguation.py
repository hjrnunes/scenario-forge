"""Tests for supply-chain-actor vs adversarial-user disambiguation in call0 prompt.

Bead: scenario-forge-o8om
"""

from __future__ import annotations

from scenario_forge.prompts import render_prompt


class TestSupplyChainDisambiguation:
    """The call0 system prompt must contain supply-chain vs adversarial-user
    disambiguation guidance to prevent actor type mislabeling."""

    def test_disambiguation_entry_present(self):
        """Call 0 system prompt must have a supply-chain-actor vs adversarial-user entry."""
        prompt = render_prompt("call0_system.j2", tool_inventory=[])
        assert "supply-chain-actor vs adversarial-user" in prompt

    def test_write_access_criterion(self):
        """Disambiguation must mention write access to data sources as the key criterion."""
        prompt = render_prompt("call0_system.j2", tool_inventory=[])
        assert "write access" in prompt

    def test_data_source_examples(self):
        """Disambiguation must list concrete data source examples."""
        prompt = render_prompt("call0_system.j2", tool_inventory=[])
        assert "knowledge bases" in prompt
        assert "product catalogs" in prompt
        assert "configuration stores" in prompt

    def test_adversarial_user_boundary(self):
        """Disambiguation must clarify adversarial-user is limited to user-facing interface."""
        prompt = render_prompt("call0_system.j2", tool_inventory=[])
        assert "user-facing interface" in prompt

    def test_converse_rule(self):
        """Disambiguation must include the converse: user-facing-only interaction
        means adversarial-user even if data-poisoning concepts are present."""
        prompt_lower = render_prompt("call0_system.j2", tool_inventory=[]).lower()
        assert "conversely" in prompt_lower
        assert "data-poisoning" in prompt_lower or "data poisoning" in prompt_lower
