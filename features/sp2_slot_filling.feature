# mutation-stamp: sha256=58225feab0d309003d740a6eb0c4469075da6ae38c4abac9b4cd17922406f56c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T00:47:13.529274Z","feature_name":"SP2 Stage 3 Phase 2 \u2014 LLM slot-filling","feature_path":"features/sp2_slot_filling.feature","background_hash":"78c579d3454939fdd22b22277ab2b196f7ade85adce774d5d169e46b3d8bf14e","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP2 Stage 3 Phase 2 — LLM slot-filling
  Slot-filling is the LLM-driven phase where each responsibility's slots are
  filled with concrete ICAs or N/A justifications. One LLM call per
  responsibility. Calls are stateless (no conversation history). The system
  prompt defines four ICA types with AI-agent-specific examples. The user
  prompt includes the control structure, hazards and security constraints,
  technology context, and the responsibility's slots. ICAs must reference
  valid hazard and constraint IDs from the LossAnalysis.

  Background:
    Given the SP2 slot filling module is importable
    And a control structure with 2 responsibilities having 2 control actions each and 1 coordination link
    And a loss analysis with hazard H-1 and constraint SC-1
    And a technology context block with input zone failure modes
    And an LLM that returns valid slot fill results for each responsibility

  # SP2-FILL-01
  Scenario: SP2-FILL-01 one LLM call per responsibility
    When slots are filled for all responsibilities
    Then the number of LLM calls equals 2
    And each call is labeled with stage stage_3

  # SP2-FILL-02
  Scenario: SP2-FILL-02 system prompt defines four ICA types
    When slots are filled for all responsibilities
    Then the system prompt contains text for ICA type NOT_PROVIDED
    And the system prompt contains text for ICA type INCORRECT
    And the system prompt contains text for ICA type WRONG_TIMING
    And the system prompt contains text for ICA type WRONG_DURATION

  # SP2-FILL-03
  Scenario: SP2-FILL-03 user prompt includes control structure and technology context and slots
    When slots are filled for all responsibilities
    Then the user prompt contains the control structure
    And the user prompt contains hazards and security constraints
    And the user prompt contains the technology context block
    And the user prompt contains the responsibility slot IDs

  # SP2-FILL-04
  Scenario: SP2-FILL-04 filled non-N/A slot has concrete ICA text
    Given an LLM that returns a slot with is_na false and ICA text describing a concrete failure
    When slots are filled for all responsibilities
    Then at least one slot has is_na false
    And that slot has at least one ICA with non-empty ica_text

  # SP2-FILL-05
  Scenario: SP2-FILL-05 filled N/A slot has na_justification
    Given an LLM that returns a slot with is_na true and na_justification referencing a structural property
    When slots are filled for all responsibilities
    Then at least one slot has is_na true
    And that slot has a non-empty na_justification
    And that slot has an empty icas list

  # SP2-FILL-06
  Scenario: SP2-FILL-06 ICAs reference valid hazard IDs from the loss analysis
    Given an LLM that returns ICAs referencing hazard H-1
    When slots are filled for all responsibilities
    Then the ICA enumeration validates against the loss analysis and control structure

  # SP2-FILL-07
  Scenario: SP2-FILL-07 ICAs referencing invalid hazard IDs are rejected
    Given an LLM that returns ICAs referencing hazard H-99
    When slots are filled for all responsibilities
    Then validation fails with error containing related_hazards

  # SP2-FILL-08
  Scenario: SP2-FILL-08 calls are stateless with no conversation history
    When slots are filled for all responsibilities
    Then each LLM call receives the full control structure
    And no call receives conversation history from a prior call

  # SP2-FILL-09
  Scenario: SP2-FILL-09 slot-filling calls are parallelizable across responsibilities
    Given a max_workers value of 2
    When slots are filled for all responsibilities in parallel
    Then results are returned in the same order as the input responsibilities
    And the number of LLM calls equals 2

  # SP2-FILL-10
  Scenario: SP2-FILL-10 coordination link slots are filled separately from responsibility slots
    Given an LLM that returns valid slot fill results for coordination links
    When slots are filled for all responsibilities and coordination links
    Then coordination link slots have responsibility null
    And coordination link slots are filled with ICAs or N/A justifications

  # SP2-FILL-11
  Scenario: SP2-FILL-11 all LLM calls are logged to calls.jsonl
    Given a run directory for output
    When slots are filled for all responsibilities
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_3

  # SP2-FILL-12
  Scenario: SP2-FILL-12 ICA loss_scenario is present for non-N/A slots
    Given an LLM that returns a slot with is_na false and one ICA with a loss scenario
    When slots are filled for all responsibilities
    Then at least one ICA has a non-empty loss_scenario
