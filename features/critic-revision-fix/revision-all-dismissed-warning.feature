# critic-revision-fix / revision-all-dismissed-warning
Feature: SP1 Stage 2 — Warn when revision dismisses all findings and produces no changes
  The critic reports findings that trigger a revision.  The revision
  model may dismiss each finding with a justification instead of adding
  or modifying elements.  If it dismisses every finding and produces no
  changes at all, the revision accomplished nothing — the control
  structure is unchanged and the run report should surface a single
  distinct, deterministic warning so a human can decide whether the
  dismissals were genuine false positives or the model avoided work.

  The warning fires only when all three conditions hold simultaneously:
  1. the critic findings set is non-empty (at least one gap, unjustified
     checklist result, or unjustified taxonomy probe result);
  2. dismissed_gaps has at least as many entries as there are findings;
     and
  3. new_responsibilities, new_controlled_processes,
     new_coordination_links, and modified_responsibilities are all empty.

  Existing per-dismissal warnings are preserved.  The all-dismissed
  warning is emitted at most once per revision call.

  Background:
    Given the STPA system model critic module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # AllDismissed-01
  Scenario: AllDismissed-01 all findings dismissed plus no additions or modifications emits a distinct warning
    Given an LLM that returns a RevisionDelta whose only content is 2 dismissed gaps
    When the revision is run
    Then the warnings list includes an all-dismissed warning
    And the warnings list includes a dismissal warning
    And the pipeline does not crash

  # AllDismissed-02
  Scenario: AllDismissed-02 partial dismissal emits per-dismissal warnings but not the all-dismissed warning
    Given an LLM that returns a RevisionDelta whose only content is 1 dismissed gaps
    When the revision is run
    Then the warnings list includes a dismissal warning
    And the warnings list does not include an all-dismissed warning

  # AllDismissed-03
  Scenario Outline: AllDismissed-03 all dismissed plus any change suppresses the all-dismissed warning
    Given an LLM that returns a RevisionDelta with <change_description> and 2 dismissed gaps
    When the revision is run
    Then the warnings list does not include an all-dismissed warning

    Examples:
      | change_description                                                              |
      | new_responsibilities containing RESP-3 with valid PM, CA, and FB elements       |
      | new_controlled_processes containing CP-2                                        |
      | new_coordination_links containing CL-1                                          |
      | modified_responsibilities containing RESP-1                                     |

  # AllDismissed-04
  Scenario: AllDismissed-04 empty findings does not emit the all-dismissed warning
    Given empty CriticFindings
    And an LLM that returns a RevisionDelta whose only content is 1 dismissed gaps
    When the revision is run
    Then the warnings list does not include an all-dismissed warning

  # AllDismissed-05
  Scenario: AllDismissed-05 no duplicate all-dismissed warnings are emitted
    Given an LLM that returns a RevisionDelta whose only content is 2 dismissed gaps
    When the revision is run
    Then the warnings list includes exactly one all-dismissed warning

  # AllDismissed-06
  Scenario Outline: AllDismissed-06 RevisionDelta fields remain unchanged
    Given the RevisionDelta Pydantic model is defined
    Then the model has a <delta_field> field of type list

    Examples:
      | delta_field               |
      | dismissed_gaps            |
      | new_responsibilities      |
      | new_controlled_processes  |
      | new_coordination_links    |
      | modified_responsibilities |
