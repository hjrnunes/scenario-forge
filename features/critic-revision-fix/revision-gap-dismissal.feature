# mutation-stamp: sha256=1f12c88242c83d8c3cc830140bdf9dac2212b961dd8b709c75986ff742e28f3a
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-12T09:14:56.443875Z","feature_name":"SP1 Stage 2 \u2014 Revision may dismiss a critic finding instead of acting on it","feature_path":"features/critic-revision-fix/revision-gap-dismissal.feature","background_hash":"d056b6c03387aeb6b2873f3c0dcf87de2c88563b4e3df2c16c94cddd0306cfa0","implementation_hash":"sha256:ffc69b48b874059d48cc6aea9c37bd8c2df541fa5fe8f97b29d9027107c09780","scenarios":[{"index":2,"name":"CRDismiss-03 a dismissal-only revision leaves the control structure intact","scenario_hash":"7c6cee3a2e74d88a38634ce18b58f1b56ddc41d6be018cf96805487bdf8da30e","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:14:56.443875Z"},{"index":0,"name":"CRDismiss-01 RevisionDelta carries dismissed_gaps alongside the existing delta fields","scenario_hash":"ebfd6d41b3fa2acd4d421aaab07f789b6f4281cb8ed39625d70570170c4a59e9","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:41.727645Z"},{"index":6,"name":"CRDismiss-07 revision_user.j2 offers the add-or-dismiss choice","scenario_hash":"7d885ea06a51891a798e3b38ef09cc44c7faf9cdba4ab197e3e08e2ef317bc86","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:41.727645Z"},{"index":8,"name":"CRDismiss-09 revision_system.j2 documents the dismissal rule","scenario_hash":"fca8416891c0681e4a26af897ac03dabcdb5d5a9e80550252e9bcd34a878de4f","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-12T09:04:41.727645Z"}]}
# acceptance-mutation-manifest-end

# critic-revision-fix / revision-gap-dismissal
Feature: SP1 Stage 2 — Revision may dismiss a critic finding instead of acting on it
  revision_user.j2 currently orders the model to "add at least one
  element for EACH finding". Combined with the widened revision trigger,
  which now also fires on taxonomy probes and adversarial gaps, that
  forces the model to manufacture an element for every false positive
  the critic produced — inflating the delta and adding responsibilities
  the system does not need.

  The revision model may instead dismiss a finding, recording a
  one-sentence justification in a new RevisionDelta.dismissed_gaps
  field. Dismissals are visible in the revision's returned warnings so a
  run's report shows which findings were declined and why; a dismissal
  never silently disappears.

  Background:
    Given the STPA system model critic module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # CRDismiss-01
  Scenario Outline: CRDismiss-01 RevisionDelta carries dismissed_gaps alongside the existing delta fields
    Given the RevisionDelta Pydantic model is defined
    Then the model has a <delta_field> field of type list

    Examples:
      | delta_field               |
      | dismissed_gaps            |
      | new_responsibilities      |
      | new_controlled_processes  |
      | new_coordination_links    |
      | modified_responsibilities |

  # CRDismiss-02
  Scenario: CRDismiss-02 dismissed_gaps defaults to empty
    Given the RevisionDelta Pydantic model is defined
    When a RevisionDelta is constructed with no arguments
    Then the RevisionDelta dismissed_gaps list is empty

  # CRDismiss-03
  Scenario Outline: CRDismiss-03 a dismissal-only revision leaves the control structure intact
    Given an LLM that returns a RevisionDelta whose only content is <dismissal_count> dismissed gaps
    When the revision is run
    Then the final control structure contains RESP-1
    And the final control structure contains RESP-2
    And the final control structure responsibilities count is 2
    And the pipeline does not crash

    Examples:
      | dismissal_count |
      | 1               |
      | 2               |

  # CRDismiss-04
  Scenario: CRDismiss-04 each dismissal justification is reported in the warnings
    Given an LLM that returns a RevisionDelta dismissing a gap with the justification "the system has no multi-agent capability"
    When the revision is run
    Then the warnings list includes a warning that mentions "the system has no multi-agent capability"
    And the warnings list includes a dismissal warning

  # CRDismiss-05
  Scenario: CRDismiss-05 a revision with no dismissals reports no dismissal warning
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 with valid PM, CA, and FB elements
    When the revision is run
    Then the final control structure contains RESP-3
    And the warnings list does not include a dismissal warning

  # CRDismiss-06
  Scenario: CRDismiss-06 additions and dismissals can coexist in one delta
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 with valid PM, CA, and FB elements and one dismissed gap
    When the revision is run
    Then the final control structure contains RESP-3
    And the warnings list includes a dismissal warning

  # CRDismiss-07
  Scenario Outline: CRDismiss-07 revision_user.j2 offers the add-or-dismiss choice
    Given the template revision_user.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                     |
      | add the missing element(s)                   |
      | dismiss it with a one-sentence justification |
      | dismissed_gaps                               |
      | real behavioral deficiencies                 |
      | duplicate existing coverage                  |
      | target capabilities the system does not have |

  # CRDismiss-08
  Scenario: CRDismiss-08 revision_user.j2 no longer mandates an element per finding
    Given the template revision_user.j2 is loaded
    Then the template text does not contain "You MUST add at least one element for EACH finding"

  # CRDismiss-09
  Scenario Outline: CRDismiss-09 revision_system.j2 documents the dismissal rule
    Given the template revision_system.j2 is loaded
    Then the template text contains "<fragment>"

    Examples:
      | fragment                                                         |
      | You may DISMISS a finding if you judge it to be a false positive |
      | dismissed_gaps                                                   |
