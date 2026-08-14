Feature: SP3 mechanism-context propagation
  Stage 5 and the Stage 6 narrative receive the deterministic technology
  context derived from the capability profile so the model has positive,
  architecture-grounded agentic mechanisms to select.

  Background:
    Given the SP3 prompt assembly modules are importable
    And a capability profile with zones input, tool_execution, memory, and inter_agent
    And the capability profile has KC subcode KC6.3.3
    And the deterministic technology context is built from the capability profile

  # SP3-MCP-01
  Scenario Outline: SP3-MCP-01 downstream prompts include positive mechanism guidance
    When the <stage> user prompt is built with the capability profile
    Then the user prompt contains the complete deterministic technology context
    And the user prompt technology context contains each positive mechanism:
      | mechanism                |
      | prompt injection          |
      | tool result fabrication   |
      | memory poisoning          |
      | agent impersonation       |
      | retrieval poisoning       |

    Examples:
      | stage              |
      | Stage 5 BDI        |
      | Stage 6 narrative  |

  # SP3-MCP-02
  Scenario: SP3-MCP-02 the full SP3 run propagates one capability taxonomy downstream
    Given a recording LLM that returns valid Stage 5 and Stage 6 results
    When SP3 runs with the capability profile
    Then every Stage 5 BDI request contains the deterministic technology context
    And every Stage 6 narrative request contains the same deterministic technology context
