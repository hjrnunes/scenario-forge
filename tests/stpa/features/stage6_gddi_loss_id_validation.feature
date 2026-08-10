Feature: Stage 6 Gherkin Loss/Hazard ID validation (gddi)
  The Gherkin generation must reference only valid Loss (L-*) and Hazard (H-*)
  IDs from the loss analysis. The Stage 6c user prompt receives the list of
  valid L-* and H-* IDs and instructs the LLM to reference only those. A
  post-generation validator checks all L-* and H-* references in the Gherkin
  text against the loss analysis and reports any hallucinated IDs.

  Background:
    Given the SP3 Gherkin module is importable
    And a ScenarioSpec with defender BDI for scenario SCN-001
    And a security constraint SC-1 related to hazard H-1
    And a loss analysis with losses L-1, L-2, L-3 and hazards H-1, H-2

  # GDDI-01
  Scenario Outline: GDDI-01 user prompt includes valid Loss and Hazard IDs
    When the Gherkin user prompt is built with the loss analysis
    Then the user prompt contains the valid <id_type> ID <valid_id>

    Examples:
      | id_type | valid_id |
      | loss    | L-1      |
      | loss    | L-2      |
      | loss    | L-3      |
      | hazard  | H-1      |
      | hazard  | H-2      |

  # GDDI-02
  Scenario: GDDI-02 user prompt instructs LLM to reference only valid IDs
    When the Gherkin user prompt is built with the loss analysis
    Then the user prompt contains an instruction to reference only the provided IDs
    And the user prompt contains an instruction not to invent new IDs

  # GDDI-03
  Scenario: GDDI-03 system prompt instructs LLM to reference only valid Loss and Hazard IDs
    When the Gherkin system prompt is rendered
    Then the system prompt instructs the LLM to use only provided L-* and H-* IDs

  # GDDI-04
  Scenario: GDDI-04 build_gherkin_prompts accepts loss analysis
    When build_gherkin_prompts is called with the scenario spec and loss analysis
    Then the user prompt contains valid Loss and Hazard IDs from the loss analysis

  # GDDI-05
  Scenario Outline: GDDI-05 validator catches hallucinated Loss or Hazard IDs
    Given a Gherkin text referencing <hallucinated_id> which is not in the loss analysis
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation fails with error containing <hallucinated_id>

    Examples:
      | hallucinated_id |
      | L-99            |
      | L-100           |
      | H-99            |
      | H-100           |

  # GDDI-06
  Scenario: GDDI-06 validator catches multiple hallucinated IDs simultaneously
    Given a Gherkin text referencing L-99 and H-88 which are not in the loss analysis
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation fails with error containing L-99
    And validation fails with error containing H-88

  # GDDI-07
  Scenario: GDDI-07 validator passes when all L-* and H-* references are valid
    Given a Gherkin text referencing L-1 and H-1 which are in the loss analysis
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation succeeds

  # GDDI-08
  Scenario: GDDI-08 validator passes when Gherkin has no L-* or H-* references
    Given a Gherkin text with no L-* or H-* references
    When Loss/Hazard ID validation is performed against the loss analysis
    Then validation succeeds

  # GDDI-09
  Scenario: GDDI-09 Loss/Hazard ID validation runs during Stage 6 artifact validation
    Given an LLM that returns Gherkin referencing hallucinated Loss ID L-99
    When the Stage 6 pipeline runs for the scenario
    Then a validation error is reported containing L-99

  # GDDI-10
  Scenario: GDDI-10 Loss/Hazard ID validation runs during Stage 7 envelope validation
    Given a ScenarioEnvelope with Gherkin referencing hallucinated Hazard ID H-99
    When Stage 7 envelope validation is performed
    Then validation fails with error containing H-99
