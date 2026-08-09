Feature: SP1 — Inject capability profile into Stage 2 Call 2 user prompt
  The system prompt stage2_call2_system.j2 instructs the LLM to "Check the
  capability profile active zones" with mandatory per-zone responsibilities.
  But _call_2_responsibilities() in control_structure.py renders
  stage2_call2_user.j2 with only use_case_text and requirements — the
  capability profile is never passed, so the LLM hallucinates zones. The fix
  passes the capability profile through derive_control_structure() and
  _call_2_responsibilities() into the Call 2 user prompt template, which
  renders a Capability Profile Context section with the actual profile data.

  Background:
    Given the STPA system model control_structure module is importable
    And a capability profile with zones_active input,reasoning,tool_execution and multi_agent false and hitl false and has_persistent_memory false
    And a use-case description is available
    And a loss analysis is available
    And a run directory for output and call logging

  # CapProfInject-01
  Scenario: CapProfInject-01 _call_2_responsibilities accepts a capability_profile parameter
    Given the _call_2_responsibilities function signature is inspected
    Then the function accepts a capability_profile parameter of type CapabilityProfile

  # CapProfInject-02
  Scenario: CapProfInject-02 derive_control_structure accepts a capability_profile parameter
    Given the derive_control_structure function signature is inspected
    Then the function accepts a capability_profile parameter of type CapabilityProfile

  # CapProfInject-03
  Scenario: CapProfInject-03 run_sp1 passes capability_profile to derive_control_structure
    Given an LLM that returns valid Stage 2 responses for all three calls
    When the SP1 pipeline is run with the capability profile
    Then derive_control_structure is called with the capability_profile argument

  # CapProfInject-04
  Scenario: CapProfInject-04 stage2_call2_user.j2 contains a Capability Profile Context section
    Given the template stage2_call2_user.j2 is loaded
    Then the template text contains "Capability Profile Context"
    And the template text contains "zones_active"
    And the template text contains "multi_agent"
    And the template text contains "hitl"
    And the template text contains "has_persistent_memory"

  # CapProfInject-05
  Scenario: CapProfInject-05 rendered Call 2 user prompt contains actual capability profile data
    Given a capability profile with zones_active input,reasoning,tool_execution and multi_agent true and hitl true
    When the Call 2 user prompt is rendered with the capability profile
    Then the rendered text contains "input, reasoning, tool_execution"
    And the rendered text contains "Multi-agent: True"
    And the rendered text contains "Human-in-the-loop: True"

  # CapProfInject-06
  Scenario: CapProfInject-06 rendered Call 2 user prompt reflects inactive zones
    Given a capability profile with zones_active input,reasoning and multi_agent false and hitl false and has_persistent_memory false
    When the Call 2 user prompt is rendered with the capability profile
    Then the rendered text contains "input, reasoning"
    And the rendered text contains "Multi-agent: False"
    And the rendered text contains "Human-in-the-loop: False"
    And the rendered text contains "Persistent memory: False"

  # CapProfInject-07
  Scenario Outline: CapProfInject-07 existing Call 2 user prompt sections remain present
    Given the template stage2_call2_user.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header       |
      | ## Use-Case Description |
      | ## Requirements        |
      | ## Your Task           |

  # CapProfInject-08
  Scenario: CapProfInject-08 stage2_call2_user.j2 renders without errors with capability profile
    Given the template stage2_call2_user.j2 is loaded
    When the template is rendered with use_case_text, requirements, and capability_profile
    Then the rendered text contains "Capability Profile Context"
    And the rendered text does not contain "{{ capability_profile"
