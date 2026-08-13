Feature: SP1 deterministic control-structure ID renumbering
  After an LLM response is decoded into a control-structure payload and before
  ControlStructure cross-reference validation, SP1 assigns canonical IDs from
  list positions and rewrites references to those IDs. LLM-selected IDs do not
  determine the published structure, while unresolved references still fail
  validation.

  Background:
    Given a syntactically parsed SP1 control-structure payload
    And the payload preserves responsibility, child, controlled-process, and coordination-link list order

  # SP1-ID-RENUMBERING-01
  Scenario Outline: SP1-ID-RENUMBERING-01 assigns every ID from structural position
    Given the payload contains at least two elements at <structural_scope>
    When the payload IDs are normalized
    Then the element at <structural_position> has ID <canonical_id>

    Examples:
      | structural_scope                    | structural_position                       | canonical_id |
      | responsibilities                    | responsibility 1                         | RESP-1       |
      | responsibilities                    | responsibility 2                         | RESP-2       |
      | responsibility constraints          | responsibility 2 child 2 responsibility constraint | RC-2-2 |
      | process model parts                 | responsibility 1 child 2 process model part         | PM-1-2 |
      | control actions                     | responsibility 2 child 1 control action             | CA-2-1 |
      | feedback channels                   | responsibility 1 child 2 feedback channel           | FB-1-2 |
      | controlled processes                | controlled process 2                     | CP-2         |
      | coordination links                  | coordination link 2                      | CL-2         |
      | coordination mechanisms             | coordination link 2 coordination mechanism | CM-2      |

  # SP1-ID-RENUMBERING-02
  Scenario: SP1-ID-RENUMBERING-02 produces the same IDs for the same ordered structure
    Given two payloads have identical ordered structures but different element IDs
    When both payloads are normalized
    Then both normalized payloads have the same element IDs
    And normalization preserves list order
    And normalization preserves every non-ID field

  # SP1-ID-RENUMBERING-03
  Scenario Outline: SP1-ID-RENUMBERING-03 records old-to-new mappings for unique source IDs
    Given the payload contains a unique source ID <old_id> at <structural_position>
    When the payload IDs are normalized
    Then the normalization mapping resolves <old_id> to <new_id>

    Examples:
      | old_id            | structural_position                       | new_id  |
      | controller-alpha  | responsibility 1                         | RESP-1  |
      | state-alpha       | responsibility 1 child 1 process model part | PM-1-1 |
      | process-alpha     | controlled process 1                     | CP-1    |
      | connection-alpha  | coordination link 1                      | CL-1    |
      | mechanism-alpha   | coordination link 1 coordination mechanism | CM-1  |

  # SP1-ID-RENUMBERING-04
  Scenario Outline: SP1-ID-RENUMBERING-04 separates duplicate IDs by position
    Given two elements in <element_scope> both use source ID <duplicate_id>
    When the payload IDs are normalized
    Then the first element in <element_scope> has ID <first_id>
    And the second element in <element_scope> has ID <second_id>

    Examples:
      | element_scope                                        | duplicate_id | first_id | second_id |
      | responsibility 1 responsibility constraints          | PM-9-9       | RC-1-1  | RC-1-2   |
      | responsibility 1 process model parts                 | repeated     | PM-1-1  | PM-1-2   |
      | responsibility 1 control actions                     | repeated     | CA-1-1  | CA-1-2   |
      | responsibility 1 feedback channels                   | repeated     | FB-1-1  | FB-1-2   |
      | coordination-link coordination mechanisms            | CM-1         | CM-1    | CM-2     |

  # SP1-ID-RENUMBERING-05
  Scenario Outline: SP1-ID-RENUMBERING-05 resolves feedback updates within its responsibility
    Given responsibility 1 and responsibility 2 each contain a process model part with source ID shared-state
    And each responsibility contains a feedback channel whose updates value is shared-state
    When the payload IDs are normalized
    Then responsibility <responsibility> feedback channel 1 updates <local_pm>

    Examples:
      | responsibility | local_pm |
      | 1              | PM-1-1   |
      | 2              | PM-2-1   |

  # SP1-ID-RENUMBERING-06
  Scenario Outline: SP1-ID-RENUMBERING-06 resolves typed element references globally
    Given the referenced element at <referenced_position> has source ID <old_reference>
    And <reference_owner> has <reference_field> ID <old_reference> with type <reference_type>
    When the payload IDs are normalized
    Then normalization changes <reference_owner> <reference_field> from <old_reference> to <new_reference>
    And the reference type remains <reference_type>

    Examples:
      | referenced_position   | old_reference    | reference_owner                    | reference_field  | reference_type      | new_reference |
      | responsibility 2      | controller-beta  | responsibility 1 process model part 1 | feedback_source | responsibility      | RESP-2       |
      | controlled process 2  | process-beta     | responsibility 1 control action 1     | target          | controlled_process  | CP-2         |
      | controlled process 1  | process-alpha    | responsibility 2 feedback channel 1   | source          | controlled_process  | CP-1         |

  # SP1-ID-RENUMBERING-07
  Scenario Outline: SP1-ID-RENUMBERING-07 resolves coordination-link references globally
    Given responsibility 1 has source ID controller-alpha and process model part source ID shared-state
    And responsibility 2 has source ID controller-beta
    And coordination link 1 has source controller-alpha, target controller-beta, and shared_pm shared-state
    When the payload IDs are normalized
    Then coordination link 1 has <reference_field> <new_reference>

    Examples:
      | reference_field | new_reference |
      | source          | RESP-1        |
      | target          | RESP-2        |
      | shared_pm       | PM-1-1        |

  # SP1-ID-RENUMBERING-08
  Scenario: SP1-ID-RENUMBERING-08 normalizes malformed and colliding IDs before validation
    Given the payload has duplicate nested IDs, nonconforming ID formats, and an RC value used as a PM ID
    When the parsed payload enters control-structure post-processing
    Then ID normalization completes before ControlStructure validation
    And every element ID matches the format for its element type
    And no element type contains duplicate IDs
    And no ID occurs in more than one element-type namespace
    And ControlStructure validation succeeds

  # SP1-ID-RENUMBERING-09
  Scenario Outline: SP1-ID-RENUMBERING-09 validates unresolved references after renumbering
    Given the payload contains an unresolved <reference_field> value <missing_id>
    When the payload IDs are normalized
    And the normalized payload is validated
    Then validation fails with an error identifying <reference_field>

    Examples:
      | reference_field         | missing_id          |
      | feedback updates        | absent-pm           |
      | process feedback_source | absent-controller   |
      | control action target   | absent-process      |
      | feedback source         | absent-process      |
      | coordination source     | absent-controller   |
      | coordination target     | absent-controller   |
      | coordination shared_pm  | absent-pm           |
