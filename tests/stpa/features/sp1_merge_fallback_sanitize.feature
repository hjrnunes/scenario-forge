# mutation-stamp: sha256=8417a533d509604f2df27ad4b6e06f5e9ad3deb85a11740fc6ec7ca0e9b21e98
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T17:44:52.224942Z","feature_name":"SP1 — Sanitize invalid ElementRefs in merge fallback path","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/sp1_merge_fallback_sanitize.feature","background_hash":"e49625a851f9d80ab3d4804bd5eb5fae48438f78dc69f92c30ff83ac2804cbc4","implementation_hash":"unknown","scenarios":[{"index":0,"name":"Sanitize-01 fallback nullifies unresolvable ElementRef in each ref field","scenario_hash":"7204f783cd5ce6874c2ca3b85568a1da894b54ae4d58ac607c78352ae23e1845","mutation_count":15,"result":{"Total":15,"Killed":15,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:44:52.224942Z"},{"index":1,"name":"Sanitize-04 valid ElementRefs are preserved during sanitization","scenario_hash":"42e462c4cb9adb56aa61bde96b259492609d7b6def70432d0459824316e0bcc1","mutation_count":9,"result":{"Total":9,"Killed":9,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:44:52.224942Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Sanitize invalid ElementRefs in merge fallback path
  The ResponsibilitySet from Call 2 has no model validator, so the LLM
  can produce ElementRef values (e.g. type controlled_process, id FB-1-1)
  that pass ResponsibilitySet parsing but fail ControlStructure validation.
  If the ConnectionSet merge fails and the fallback path constructs a
  ControlStructure from the ResponsibilitySet alone, these invalid
  ElementRefs crash the entire run. The fix adds a _sanitize_for_fallback()
  function that nullifies unresolvable ElementRefs, wraps the fallback
  construction in a try/except, and uses a further-degraded path that
  strips ALL ElementRefs if sanitization still fails. All stripped
  references are logged in the warnings list.

  Background:
    Given the STPA system model module is importable
    And a use-case description is available
    And a run directory for output and call logging

  # Sanitize-01
  Scenario Outline: Sanitize-01 fallback nullifies unresolvable ElementRef in each ref field
    Given a valid ResponsibilitySet from Call 2 with responsibility RESP-1
    And the ResponsibilitySet has a <element_type> <element_id> with <ref_field> {type: <ref_type>, id: <ref_id>}
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then a ControlStructure model is produced
    And the <element_type> <element_id> <ref_field> is None
    And the pipeline does not crash

    Examples:
      | element_type      | element_id | ref_field       | ref_type           | ref_id  |
      | ProcessModelPart  | PM-1-1     | feedback_source | controlled_process | FB-1-1  |
      | ControlAction     | CA-1-1     | target          | responsibility     | RESP-99 |
      | FeedbackChannel   | FB-1-1     | source          | controlled_process | CP-99   |

  # Sanitize-04
  Scenario Outline: Sanitize-04 valid ElementRefs are preserved during sanitization
    Given a valid ResponsibilitySet from Call 2 with responsibility RESP-1 and controlled process CP-1
    And the ResponsibilitySet has a <element_type> <element_id> with <ref_field> pointing to CP-1
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then the <element_type> <element_id> <ref_field> is preserved and not nullified

    Examples:
      | element_type      | element_id | ref_field       |
      | ProcessModelPart  | PM-1-1     | feedback_source |
      | ControlAction     | CA-1-1     | target          |
      | FeedbackChannel   | FB-1-1     | source          |

  # Sanitize-05
  Scenario: Sanitize-05 sanitized fallback ControlStructure passes foundation validation
    Given a valid ResponsibilitySet from Call 2 with responsibility RESP-1 and controlled process CP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: INVALID-1}
    And the ResponsibilitySet has a ControlAction CA-1-1 with target {type: controlled_process, id: INVALID-2}
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then the control structure passes foundation validation

  # Sanitize-06
  Scenario: Sanitize-06 stripped references are logged in warnings
    Given a valid ResponsibilitySet from Call 2 with responsibility RESP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: FB-1-1}
    And the ResponsibilitySet has a ControlAction CA-1-1 with target {type: responsibility, id: RESP-99}
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then the warnings list includes a warning about the stripped feedback_source for PM-1-1
    And the warnings list includes a warning about the stripped target for CA-1-1

  # Sanitize-07
  Scenario: Sanitize-07 fallback does not crash with completely invalid ElementRef values
    Given a valid ResponsibilitySet from Call 2 with responsibility RESP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: FB-1-1}
    And the ResponsibilitySet has a ControlAction CA-1-1 with target {type: controlled_process, id: CA-2-1}
    And the ResponsibilitySet has a FeedbackChannel FB-1-1 with source {type: responsibility, id: PM-3-1}
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then a ControlStructure model is produced
    And the pipeline does not crash

  # Sanitize-08
  Scenario: Sanitize-08 further-degraded path strips ALL ElementRefs when sanitization still fails
    Given a valid ResponsibilitySet from Call 2 with responsibility RESP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: FB-1-1}
    And the ResponsibilitySet has duplicate responsibility RESP-1 causing validation failure even after sanitization
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then a ControlStructure model is produced
    And all feedback_source fields are None
    And all control_action target fields are None
    And all feedback_channel source fields are None
    And the pipeline does not crash

  # Sanitize-09
  Scenario: Sanitize-09 sanitized fallback preserves responsibilities and controlled processes from Call 2
    Given a valid ResponsibilitySet from Call 2 with responsibilities RESP-1 and RESP-2 and controlled process CP-1
    And the ResponsibilitySet has a ProcessModelPart PM-1-1 with feedback_source {type: controlled_process, id: INVALID-1}
    And an LLM that returns a ConnectionSet that triggers merge failure
    When the merge with fallback is executed
    Then the ControlStructure contains responsibility RESP-1
    And the ControlStructure contains responsibility RESP-2
    And the ControlStructure contains controlled process CP-1

  # Sanitize-10
  Scenario: Sanitize-10 normal merge success path is unchanged
    Given a valid ResponsibilitySet from Call 2 with responsibilities RESP-1 and RESP-2
    And an LLM that returns a valid ConnectionSet with coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When the merge with fallback is executed
    Then the ControlStructure contains coordination link CL-1
    And the warnings list is empty
    And no sanitization warnings are present
