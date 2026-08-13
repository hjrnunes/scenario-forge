# SP1 revision-delta ID normalization
Feature: SP1 revision-delta ID normalization
  SP1 stitches a decoded revision delta into the current control structure
  before assigning canonical IDs from the final list positions and validating
  the result. This preserves modification matching, repairs LLM-selected IDs,
  and rewrites resolvable references without accepting dangling references.

  Background:
    Given a canonical control structure with two responsibilities, one controlled process, and one coordination link
    And critic findings trigger one revision attempt

  # SP1-REVISION-ID-NORMALIZATION-01 repairs malformed delta IDs after stitching
  Scenario Outline: SP1-REVISION-ID-NORMALIZATION-01 repairs malformed delta IDs after stitching
    Given a decodable revision response adds complete elements whose IDs are nonconforming strings
    And every revision reference resolves by a source ID in the combined structure
    When the revision is run
    Then the added <element> has ID <canonical_id>
    And the revised control structure contains the added content
    And the revision warnings do not report a failed or degraded revision

    Examples:
      | element                   | canonical_id |
      | responsibility            | RESP-3       |
      | responsibility constraint | RC-3-1       |
      | process model part        | PM-3-1       |
      | control action            | CA-3-1       |
      | feedback channel          | FB-3-1       |
      | controlled process        | CP-2         |
      | coordination link         | CL-2         |
      | coordination mechanism    | CM-2         |

  # SP1-REVISION-ID-NORMALIZATION-02 separates duplicate nested IDs by final position
  Scenario Outline: SP1-REVISION-ID-NORMALIZATION-02 separates duplicate nested IDs by final position
    Given the revision replaces responsibility RESP-2 and adds one responsibility
    And both revision responsibilities use the same source ID for each corresponding nested element
    When the revision is run
    Then the nested <element> IDs under RESP-2 and RESP-3 are <modified_id> and <added_id>
    And the revised control structure has no duplicate <element> IDs

    Examples:
      | element                   | modified_id | added_id |
      | responsibility constraint | RC-2-1     | RC-3-1   |
      | process model part        | PM-2-1     | PM-3-1   |
      | control action            | CA-2-1     | CA-3-1   |
      | feedback channel          | FB-2-1     | FB-3-1   |

  # SP1-REVISION-ID-NORMALIZATION-03 rewrites delta references to final canonical IDs
  Scenario Outline: SP1-REVISION-ID-NORMALIZATION-03 rewrites delta references to final canonical IDs
    Given the revision replaces RESP-2 and adds elements with source IDs revised-state, revised-process, and revised-controller
    And revision references use those source IDs before normalization
    When the revision is run
    Then <reference_owner> has <reference_field> <canonical_reference>
    And <canonical_reference> identifies an element in the revised control structure

    Examples:
      | reference_owner                       | reference_field  | canonical_reference |
      | RESP-2 process model part PM-2-1      | feedback_source  | RESP-3              |
      | RESP-2 control action CA-2-1          | target           | CP-2                 |
      | RESP-2 feedback channel FB-2-1        | source           | CP-2                 |
      | RESP-2 feedback channel FB-2-1        | updates          | PM-2-1               |
      | coordination link CL-2                | source           | RESP-3               |
      | coordination link CL-2                | target           | RESP-1               |
      | coordination link CL-2                | shared_pm        | PM-2-1               |

  # SP1-REVISION-ID-NORMALIZATION-04 preserves modification matching and canonical positions
  Scenario: SP1-REVISION-ID-NORMALIZATION-04 preserves modification matching and canonical positions
    Given the revision replaces RESP-2 by its canonical ID with an updated description
    And the revision adds a responsibility, controlled process, and coordination link with misleading conforming IDs
    When the revision is run
    Then RESP-1 retains its original description, RESP-2 has the updated description, and RESP-3 contains the addition
    And child IDs of RESP-1, RESP-2, and RESP-3 are rooted at 1, 2, and 3 respectively
    And the controlled processes are CP-1 and CP-2 in final list order
    And the coordination links are CL-1 and CL-2 with mechanisms CM-1 and CM-2 in final list order
    And all pre-revision references still identify the same elements

  # SP1-REVISION-ID-NORMALIZATION-05 rejects unresolved delta references after normalization
  Scenario Outline: SP1-REVISION-ID-NORMALIZATION-05 rejects unresolved delta references after normalization
    Given the revision contains an unresolved <reference_field> value <missing_id>
    When the revision is run
    Then merged control-structure validation fails for <reference_field> and <missing_id>
    And the returned control structure equals the pre-revision control structure
    And the revision warnings report a degraded revision with the unresolved reference
    And no published control-structure reference contains <missing_id>

    Examples:
      | reference_field         | missing_id          |
      | feedback updates        | missing-state       |
      | process feedback_source | missing-controller  |
      | control action target   | missing-process     |
      | feedback source         | missing-process     |
      | coordination source     | missing-controller  |
      | coordination target     | missing-controller  |
      | coordination shared_pm  | missing-state       |
