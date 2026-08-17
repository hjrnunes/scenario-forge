# mutation-stamp: sha256=5efb8ff744ffc2be3f1c083d9bfaf815338728000393ba2b6f2ceaf0b4b8aa05
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T19:57:45.125171Z","feature_name":"SP1 — Prevent RevisionDelta runaway output","feature_path":"../../../tests/stpa/features/sp1_revision_runaway_output.feature","background_hash":"d2c1bb399d1f338a359aea1d66186f71082f313642a60b85f65f7cf0ce4affd3","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 — Prevent RevisionDelta runaway output
  Gemma 4 generates 16384 tokens for revision runs despite the prompt saying
  "Do NOT restate the entire control structure". A valid delta is ~800
  tokens. Root causes: (1) the model puts existing responsibilities into
  modified_responsibilities; (2) the revision user prompt includes
  use_case_text which inflates context; (3) no per-step
  max_completion_tokens cap on the revision LLM call; (4) no post-parse
  validation rejecting duplicate resp_ids in new_responsibilities. The fix
  addresses all four causes.

  Background:
    Given the STPA system model revision module is importable
    And the STPA system model llm_helpers module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # RevRunaway-01
  Scenario: RevRunaway-01 revision_system.j2 instructs modified_responsibilities contains only changes
    Given the template revision_system.j2 is loaded
    Then the template text contains "modified_responsibilities list must contain ONLY responsibilities you are CHANGING"
    And the template text contains "Do not include unmodified responsibilities"
    And the template text contains "If a responsibility needs no changes, do not include it in the delta at all"

  # RevRunaway-02
  Scenario: RevRunaway-02 revision_user.j2 does not include use_case_text
    Given the template revision_user.j2 is loaded
    Then the template text does not contain "use_case_text"
    And the template text does not contain "{{ use_case_text }}"

  # RevRunaway-03
  Scenario: RevRunaway-03 revision_user.j2 still contains control structure listing
    Given the template revision_user.j2 is loaded
    Then the template text contains "Current Control Structure"
    And the template text contains "Responsibilities"
    And the template text contains "Critic Findings"

  # RevRunaway-04
  Scenario: RevRunaway-04 safe_llm_call accepts a max_completion_tokens parameter
    Given the safe_llm_call function signature is inspected
    Then the function accepts a max_completion_tokens parameter with default None

  # RevRunaway-05
  Scenario: RevRunaway-05 safe_llm_call passes max_completion_tokens to complete
    Given an LLM client with a mocked complete method
    When safe_llm_call is called with max_completion_tokens 4096
    Then the complete method is called with max_completion_tokens 4096

  # RevRunaway-06
  Scenario: RevRunaway-06 safe_llm_call without max_completion_tokens does not override client default
    Given an LLM client with a mocked complete method
    When safe_llm_call is called without max_completion_tokens
    Then the complete method is called with max_completion_tokens None

  # RevRunaway-07
  Scenario: RevRunaway-07 run_revision passes max_completion_tokens 4096
    Given an LLM that returns a valid RevisionDelta
    When the revision is run
    Then the LLM complete call is made with max_completion_tokens 4096

  # RevRunaway-08
  Scenario: RevRunaway-08 new_responsibilities with existing resp_id is rejected
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-1
    When the revision is run
    Then the final control structure does not contain a duplicate RESP-1
    And a warning is logged about the rejected duplicate resp_id RESP-1

  # RevRunaway-09
  Scenario: RevRunaway-09 new_responsibilities with genuinely new resp_id is accepted
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 with valid PM, CA, and FB elements
    When the revision is run
    Then the final control structure contains RESP-3

  # RevRunaway-10
  Scenario: RevRunaway-10 duplicate rejection does not affect modified_responsibilities replacement
    Given an LLM that returns a RevisionDelta with modified_responsibilities containing RESP-1 with an updated description
    And the RevisionDelta also has new_responsibilities containing RESP-2
    When the revision is run
    Then the final control structure contains RESP-1 with the updated description
    And a warning is logged about the rejected duplicate resp_id RESP-2
    And the final control structure does not contain a duplicate RESP-2

  # RevRunaway-11
  Scenario: RevRunaway-11 revision_system.j2 preserves existing delta and ID rules
    Given the template revision_system.j2 is loaded
    Then the template text contains "Do NOT restate the entire control structure"
    And the template text contains "ID format rules"
    And the template text contains "solution-neutrality"

  # RevRunaway-12
  Scenario: RevRunaway-12 revision_system.j2 renders successfully with the new instruction
    Given the template revision_system.j2 is loaded
    When the template is rendered with control_structure and next_ids
    Then the rendered text contains "modified_responsibilities list must contain ONLY"
    And the rendered text does not contain "{{"
