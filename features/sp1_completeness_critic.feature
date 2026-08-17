# mutation-stamp: sha256=c42812b01dc37523e8531224e1da8f44793aec77e226feeb24e222cb221119f6
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:52:02.610285Z","feature_name":"SP1 Stage 2 \u2014 Completeness critic","feature_path":"features/sp1_completeness_critic.feature","background_hash":"500d563aa17cede8b86bb381346e85e9022f2d56543037ae079a584800ed49e5","implementation_hash":"unknown","scenarios":[{"index":2,"name":"SP1-CRITIC-03 gap types are validated","scenario_hash":"61296f50b1974fa51c47e18a9a66a77697e53f7fc76a5f54fc7d7c66b24471e4","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-08T14:52:02.610285Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 2 — Completeness critic
  The completeness critic is a single LLM call that receives the derived
  ControlStructure, use-case text, and CapabilityProfile. It combines three
  probes: a generic responsibility checklist, taxonomy-derived probes tailored
  to the system's capabilities, and an adversarial probe for missing control
  elements. Output is a CriticFindings model with gaps, checklist results, and
  taxonomy probe results.

  Background:
    Given the STPA system model critic module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And a capability profile and use-case text are available

  # SP1-CRITIC-01
  Scenario: SP1-CRITIC-01 critic produces a valid CriticFindings model
    Given an LLM that returns a valid CriticFindings JSON with gaps and checklist results
    When the completeness critic is run
    Then a CriticFindings model is produced
    And the model has a gaps list, checklist_results dict, and taxonomy_probe_results dict

  # SP1-CRITIC-02
  Scenario: SP1-CRITIC-02 critic with no gaps produces empty gaps list
    Given an LLM that returns a CriticFindings JSON with an empty gaps list
    When the completeness critic is run
    Then the CriticFindings gaps list is empty

  # SP1-CRITIC-03
  Scenario Outline: SP1-CRITIC-03 gap types are validated
    Given an LLM that returns a CriticFindings JSON with a gap of type <gap_type>
    When the completeness critic is run
    Then the CriticFindings model contains a gap with gap_type <gap_type>

    Examples:
      | gap_type              |
      | missing_responsibility|
      | missing_feedback      |
      | missing_pm_part       |

  # SP1-CRITIC-04
  Scenario: SP1-CRITIC-04 gap with invalid type fails validation
    Given an LLM that returns a CriticFindings JSON with a gap of type missing_tool
    When the completeness critic is run
    Then validation fails with error containing gap_type

  # SP1-CRITIC-05
  Scenario: SP1-CRITIC-05 each gap has description, related_attack_path, and suggested_remedy
    Given an LLM that returns a CriticFindings JSON with a gap having all required fields
    When the completeness critic is run
    Then the gap has a description, related_attack_path, and suggested_remedy

  # SP1-CRITIC-06
  Scenario: SP1-CRITIC-06 checklist results map responsibility names to status
    Given an LLM that returns a CriticFindings JSON with checklist results
    When the completeness critic is run
    Then the checklist_results map responsibility names to present, absent_justified, or absent_unjustified

  # SP1-CRITIC-07
  Scenario: SP1-CRITIC-07 critic call is logged with stage stage_2 and step critic
    Given an LLM that returns a valid CriticFindings JSON
    And a run directory for call logging
    When the completeness critic is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is critic

  # SP1-CRITIC-08
  Scenario: SP1-CRITIC-08 critic receives control structure, capability profile, and use-case
    Given an LLM that returns a valid CriticFindings JSON
    When the completeness critic is run
    Then the user prompt contains the control structure
    And the user prompt contains the capability profile
    And the user prompt contains the use-case text

  # SP1-CRITIC-09
  Scenario: SP1-CRITIC-09 taxonomy probes are conditioned on capability profile
    Given a capability profile with KC sub-code KC6.3.3 indicating RAG
    And an LLM that returns a valid CriticFindings JSON
    When the completeness critic is run
    Then the user prompt contains taxonomy-derived probes for RAG retrieval integrity

  # SP1-CRITIC-10
  Scenario: SP1-CRITIC-10 unjustified gaps trigger revision
    Given an LLM that returns a CriticFindings JSON with an absent_unjustified checklist result
    When the completeness critic is run
    Then revision is triggered

  # SP1-CRITIC-11
  Scenario: SP1-CRITIC-11 only justified gaps do not trigger revision
    Given an LLM that returns a CriticFindings JSON with all checklist results as absent_justified or present
    When the completeness critic is run
    Then revision is not triggered

  # SP1-CRITIC-12
  Scenario: SP1-CRITIC-12 critic findings are recorded in the run manifest
    Given an LLM that returns a CriticFindings JSON with two gaps
    When the completeness critic is run
    Then the run manifest critic_findings contains two entries
