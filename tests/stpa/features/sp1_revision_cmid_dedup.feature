Feature: SP1 Stage 2 — Duplicate cm_id handling in revision delta merge
  The revision-delta merge step in `_merge_revision_delta` deduplicates
  new coordination links only by `link_id`. When the revision LLM emits
  a new link with a unique `link_id` but whose nested
  `coordination_mechanism.cm_id` duplicates an existing one, the link
  passes the `link_id` check, is appended, and the `ControlStructure`
  constructor rejects the duplicate `cm_id` via
  `validate_references_and_duplicates`. Unlike the ConnectionSet merge
  path (`_merge_with_fallback`), the revision path has no try/except, so
  the `ValidationError` escapes `run_revision()` and aborts the entire
  SP1 run.

  The fix has two parts:
  (A) When a new coordination link's `cm_id` collides with an existing
  one, renumber the colliding `cm_id` to the next free `CM-N` (conforming
  to `^CM-\d+$`). This preserves the link and its analytical value — the
  source, target, shared_pm, mechanism description, and payload all
  survive — and is consistent with the system's existing
  next-available-ID guidance pattern (`_compute_next_ids`).
  (B) A degradation guard wraps the entire revision-delta merge in a
  try/except inside `run_revision()`. Any exception during merge falls
  back to the pre-revision `ControlStructure` with a warning appended to
  the returned warning list. The run continues. This mirrors the
  degradation contract of `_merge_with_fallback()`.

  Every renumber and every degradation emits a warning string naming the
  offending ID so the behavior is visible in run output.

  Background:
    Given the STPA system model critic module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And the control structure has coordination links CL-1 with CM-1 and CL-2 with CM-2
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # CmDedup-01
  Scenario: CmDedup-01 new link with duplicate cm_id is renumbered to next free CM-N
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the final control structure contains coordination link CL-3
    And the coordination link CL-3 has a cm_id that is not CM-1
    And the coordination link CL-3 has a cm_id matching the format CM-N
    And the final control structure passes foundation validation

  # CmDedup-02
  Scenario: CmDedup-02 renumbered cm_id does not collide with any existing cm_id
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the final control structure has no duplicate cm_id values
    And the final control structure passes foundation validation

  # CmDedup-03
  Scenario: CmDedup-03 renumbering preserves the link content
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1 and source RESP-1 and target RESP-2 and shared_pm PM-1-1 and description "shared validation" and payload "sync"
    When the revision is run
    Then the coordination link CL-3 has source RESP-1
    And the coordination link CL-3 has target RESP-2
    And the coordination link CL-3 has shared_pm PM-1-1
    And the coordination link CL-3 has description "shared validation"
    And the coordination link CL-3 has coordination_mechanism payload "sync"

  # CmDedup-04
  Scenario: CmDedup-04 renumbering emits a warning naming the colliding cm_id
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the warnings list includes a warning that mentions CM-1
    And the warnings list includes a warning that mentions CL-3

  # CmDedup-05
  Scenario: CmDedup-05 renumbered cm_id is the next free number
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the coordination link CL-3 has cm_id CM-3

  # CmDedup-06
  Scenario: CmDedup-06 multiple new links with duplicate cm_ids are each renumbered
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1 and CL-4 whose cm_id is CM-2
    When the revision is run
    Then the final control structure contains coordination link CL-3
    And the final control structure contains coordination link CL-4
    And the coordination link CL-3 has a cm_id that is not CM-1
    And the coordination link CL-4 has a cm_id that is not CM-2
    And the coordination link CL-3 has a cm_id different from CL-4 cm_id
    And the final control structure has no duplicate cm_id values

  # CmDedup-07
  Scenario: CmDedup-07 new link with unique cm_id is not renumbered
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-3
    When the revision is run
    Then the coordination link CL-3 has cm_id CM-3
    And the warnings list does not include a renumber warning for CM-3

  # CmDedup-08
  Scenario: CmDedup-08 renumbered cm_id conforms to the CM-N format regex
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the coordination link CL-3 has a cm_id matching the pattern ^CM-\d+$

  # CmDedup-09
  Scenario: CmDedup-09 degradation guard falls back to pre-revision ControlStructure on merge failure
    Given an LLM that returns a RevisionDelta that causes a ValidationError during merge
    When the revision is run
    Then the returned ControlStructure is the pre-revision control structure
    And the pipeline does not crash
    And the warnings list includes a degradation warning

  # CmDedup-10
  Scenario: CmDedup-10 degradation warning names the failing step and includes the error
    Given an LLM that returns a RevisionDelta that causes a ValidationError during merge
    When the revision is run
    Then the warnings list includes a warning mentioning revision delta merge
    And the warnings list includes a warning mentioning the error type

  # CmDedup-11
  Scenario: CmDedup-11 degradation guard preserves existing responsibilities after fallback
    Given an LLM that returns a RevisionDelta that causes a ValidationError during merge
    When the revision is run
    Then the returned ControlStructure contains RESP-1
    And the returned ControlStructure contains RESP-2
    And the returned ControlStructure contains coordination link CL-1
    And the returned ControlStructure contains coordination link CL-2

  # CmDedup-12
  Scenario: CmDedup-12 Airbnb regression shape — existing CL-1/CM-1 and CL-2/CM-2, revision adds CL-3 with CM-1
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-1
    When the revision is run
    Then the pipeline does not crash
    And the final control structure contains coordination link CL-1 with cm_id CM-1
    And the final control structure contains coordination link CL-2 with cm_id CM-2
    And the final control structure contains coordination link CL-3
    And the coordination link CL-3 has a cm_id that is not CM-1
    And the final control structure has no duplicate cm_id values
    And the final control structure passes foundation validation

  # CmDedup-13
  Scenario: CmDedup-13 degradation guard catches nested pm_id collision from new responsibility
    Given an LLM that returns a RevisionDelta with new_responsibilities containing RESP-3 whose PM part has pm_id PM-1-1 which duplicates an existing PM
    When the revision is run
    Then the pipeline does not crash
    And the returned ControlStructure is the pre-revision control structure
    And the warnings list includes a degradation warning

  # CmDedup-14
  Scenario: CmDedup-14 successful merge with no collisions produces no renumber or degradation warnings
    Given an LLM that returns a RevisionDelta with new_coordination_links containing CL-3 whose cm_id is CM-3
    When the revision is run
    Then the warnings list does not include a renumber warning
    And the warnings list does not include a degradation warning
    And the final control structure contains coordination link CL-3 with cm_id CM-3
