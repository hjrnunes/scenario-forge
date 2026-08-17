# mutation-stamp: sha256=47af4e0289b22ee91d5d9ee95f8aa292233fc252df507d1356eb313aa5f97411
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T22:07:09.027540Z","feature_name":"SP1 critic ID sanitization before revision","feature_path":"features/sp1_critic_id_sanitization.feature","background_hash":"48917530b22a6e97df9bfe29a88e3499d5782b99c9596768c5a6e221894c7f13","implementation_hash":"unknown","scenarios":[{"index":2,"name":"SP1-CRITIC-SAN-03 non-conforming IDs are stripped from suggested_remedy","scenario_hash":"b7bfe05128b7e25b91dfa263d9f488d0953d333813d2e95a6b24ddf8aa794846","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-09T22:07:09.027540Z"},{"index":3,"name":"SP1-CRITIC-SAN-04 conforming IDs are preserved in suggested_remedy","scenario_hash":"3c9b51dcd64e450d1682812ffc327222dfe290fa50e992845164b82bcbdee5ff","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-09T22:07:09.027540Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 critic ID sanitization before revision
  The completeness critic's suggested_remedy field is free-text and may
  contain non-conforming IDs (e.g., PM-0, RESP-0). These are passed
  verbatim into the revision user prompt, causing the revision LLM to
  use invalid IDs and trigger Pydantic ValidationError on the
  RevisionDelta output. The fix has two parts: (A) the critic system
  prompt instructs the LLM not to suggest specific IDs in remedies, and
  (B) a sanitize_critic_ids() function strips or rewrites non-conforming
  IDs from suggested_remedy strings before the findings reach the
  revision prompt.

  Background:
    Given the STPA system model critic module is importable
    And the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SP1-CRITIC-SAN-01
  Scenario: SP1-CRITIC-SAN-01 critic system prompt instructs not to suggest specific IDs
    Given the template critic_system.j2 is loaded
    Then the template text contains "Do NOT suggest specific IDs in remedies"
    And the template text contains "Describe WHAT should be added"
    And the template text contains "not what ID it should have"
    And the template text contains "Let the revision model assign IDs"

  # SP1-CRITIC-SAN-02
  Scenario: SP1-CRITIC-SAN-02 critic system prompt provides examples of what to avoid
    Given the template critic_system.j2 is loaded
    Then the template text contains "a responsibility for input validation"
    And the template text contains "not 'add RESP-5'"
    And the template text contains "not 'add PM-0-1'"

  # SP1-CRITIC-SAN-03
  Scenario Outline: SP1-CRITIC-SAN-03 non-conforming IDs are stripped from suggested_remedy
    Given a CriticFindings with a gap whose suggested_remedy contains "<bad_id>"
    When sanitize_critic_ids is called on the findings
    Then the suggested_remedy does not contain "<bad_id>"
    And the suggested_remedy contains a generic description

    Examples:
      | bad_id |
      | PM-0   |
      | CA-0   |
      | FB-0   |

  # SP1-CRITIC-SAN-04
  Scenario Outline: SP1-CRITIC-SAN-04 conforming IDs are preserved in suggested_remedy
    Given a CriticFindings with a gap whose suggested_remedy references existing element "<good_id>"
    When sanitize_critic_ids is called on the findings
    Then the suggested_remedy still contains "<good_id>"

    Examples:
      | good_id |
      | RESP-1  |
      | PM-1-2  |
      | CA-2-1  |
      | FB-3-1  |

  # SP1-CRITIC-SAN-05
  Scenario: SP1-CRITIC-SAN-05 suggested_remedy without any IDs is unchanged
    Given a CriticFindings with a gap whose suggested_remedy is "Add a responsibility for input validation"
    When sanitize_critic_ids is called on the findings
    Then the suggested_remedy is unchanged

  # SP1-CRITIC-SAN-06
  Scenario: SP1-CRITIC-SAN-06 multiple gaps with non-conforming IDs are all sanitized
    Given a CriticFindings with three gaps each containing a different non-conforming ID
    When sanitize_critic_ids is called on the findings
    Then none of the suggested_remedy strings contain non-conforming IDs
    And the findings still have three gaps

  # SP1-CRITIC-SAN-07
  Scenario: SP1-CRITIC-SAN-07 sanitize_critic_ids preserves checklist and taxonomy results
    Given a CriticFindings with gaps, checklist_results, and taxonomy_probe_results
    When sanitize_critic_ids is called on the findings
    Then the result is a CriticFindings model
    And the checklist_results are preserved
    And the taxonomy_probe_results are preserved

  # SP1-CRITIC-SAN-08
  Scenario: SP1-CRITIC-SAN-08 sanitized findings flow to revision without non-conforming IDs
    Given a CriticFindings with a non-conforming ID in a suggested_remedy
    When the findings are sanitized and passed to the revision prompt
    Then the revision user prompt does not contain the non-conforming ID

  # SP1-CRITIC-SAN-09
  Scenario: SP1-CRITIC-SAN-09 sanitization is called after critic and before revision
    Given a control structure and CriticFindings with unjustified gaps containing a non-conforming ID
    When the Stage 2 revision block runs
    Then sanitize_critic_ids is called after run_completeness_critic returns
    And sanitize_critic_ids is called before run_revision is called
