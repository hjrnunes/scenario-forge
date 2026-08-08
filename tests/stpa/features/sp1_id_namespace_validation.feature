Feature: SP1 RC/PM ID namespace validation
  Control structure ID fields must enforce their prefix conventions via
  regex field validators. A three-layer defense prevents ID namespace
  collisions: (1) regex validators on each ID field enforce the correct
  prefix and format at Pydantic parse time, (2) a model validator adds
  RC IDs to the global dedup check and detects cross-namespace collisions,
  and (3) the Stage 2 Call 2 system prompt contains a negative constraint
  instructing the LLM not to copy PM entries as RCs.

  Background:
    Given the control structure module is importable
    And a valid responsibility set with RESP-1, PM-1-1, CA-1-1, FB-1-1, and RC-1-1

  # IDNS-01
  Scenario Outline: IDNS-01 rc_id with correct prefix and format passes validation
    Given a ResponsibilityConstraint with rc_id <rc_id>
    When the control structure is validated
    Then validation succeeds

    Examples:
      | rc_id   |
      | RC-1-1  |
      | RC-2-3  |

  # IDNS-02
  Scenario Outline: IDNS-02 rc_id with wrong prefix or malformed format fails validation
    Given a ResponsibilityConstraint with rc_id <rc_id>
    When the control structure is validated
    Then validation fails with error containing rc_id

    Examples:
      | rc_id    |
      | PM-1-1   |
      | SC-1     |
      | RC-1     |
      | RC-A-B   |
      | RC-1-1-1 |

  # IDNS-03
  Scenario Outline: IDNS-03 non-rc ID fields with wrong prefix or format fail validation
    Given a <model_name> with <field_name> <bad_value>
    When the control structure is validated
    Then validation fails with error containing <field_name>

    Examples:
      | model_name              | field_name | bad_value |
      | ProcessModelPart        | pm_id      | RC-1-1    |
      | ProcessModelPart        | pm_id      | PM-1      |
      | ControlAction           | ca_id      | PM-1-1    |
      | ControlAction           | ca_id      | CA-1      |
      | FeedbackChannel         | fb_id      | PM-1-1    |
      | FeedbackChannel         | fb_id      | FB-1      |
      | ControlledProcess       | cp_id      | CP-1-1    |
      | ControlledProcess       | cp_id      | PM-1      |
      | Responsibility          | resp_id    | RESP-1-1  |
      | Responsibility          | resp_id    | PM-1      |
      | CoordinationLink        | link_id    | CL-1-1    |
      | CoordinationLink        | link_id    | PM-1      |
      | CoordinationMechanism   | cm_id      | CM-1-1    |
      | CoordinationMechanism   | cm_id      | PM-1      |

  # IDNS-04
  Scenario: IDNS-04 duplicate RC IDs within the same responsibility fail validation
    Given a responsibility with two ResponsibilityConstraints both having rc_id RC-1-1
    When the control structure is validated
    Then validation fails with error containing Duplicate

  # IDNS-05
  Scenario: IDNS-05 cross-namespace collision detected by model validator
    Given a control structure constructed with rc_id RC-1-1 and pm_id RC-1-1 bypassing field validators
    Then validation fails with error containing namespace or collision

  # IDNS-06
  Scenario: IDNS-06 valid control structure with all correct prefixes passes validation
    When the control structure is validated
    Then validation succeeds

  # IDNS-07
  Scenario: IDNS-07 stage2_call2_system prompt contains negative RC vs PM constraint
    Given the stage2_call2_system.j2 prompt template is loaded
    Then the prompt text contains the constraint that rc_id must start with RC
    And the prompt text contains a warning not to copy PM entries as RCs
