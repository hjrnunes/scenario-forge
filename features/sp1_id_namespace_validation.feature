# mutation-stamp: sha256=d6e55e523b83b3b0903676ff7b0bc3859133010bd48b7fd4d3ef443e0d73463f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:36:41.345085Z","feature_name":"SP1 RC/PM ID namespace validation","feature_path":"features/sp1_id_namespace_validation.feature","background_hash":"9d099c93440d04546adb2d743cd0bdacf1e6f907941c0b0ab5637aa0e734f904","implementation_hash":"sha256:35066b7375271cbbb5c741457681fd16de3624253c03f5d062cd28535ef40482","scenarios":[{"index":6,"name":"IDNS-07 stage2_call2a_system prompt contains negative RC vs PM constraint","scenario_hash":"ab0cdec29ea5a9f087f56bf240dd8334133f8fbcc5791c26316b715fc13b4f11","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:36:41.345085Z"},{"index":0,"name":"IDNS-01 rc_id with correct prefix and format passes validation","scenario_hash":"9d94dec79779a05df4858943d0b386adbeb6205b909890609fc6d347fd00d3be","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:34:43.611002Z"},{"index":1,"name":"IDNS-02 rc_id with wrong prefix or malformed format fails validation","scenario_hash":"b9dd9612e3472ce9311580b37d4d437c28b0539f8d104f029d55dfe434576a7b","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:34:43.611002Z"},{"index":2,"name":"IDNS-03 non-rc ID fields with wrong prefix or format fail validation","scenario_hash":"4fad99bfbc746def8c3140437e7d0e5495a80ad1638150089a3fc1ac4fdffc49","mutation_count":42,"result":{"Total":42,"Killed":42,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:34:43.611002Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 RC/PM ID namespace validation
  Control structure ID fields must enforce their prefix conventions via
  regex field validators. A three-layer defense prevents ID namespace
  collisions: (1) regex validators on each ID field enforce the correct
  prefix and format at Pydantic parse time, (2) a model validator adds
  RC IDs to the global dedup check and detects cross-namespace collisions,
  and (3) the Stage 2 Call 2a system prompt contains a negative constraint
  instructing the LLM not to copy PM entries as RCs. Call 2a is the call
  that emits responsibility constraints and process model parts, so the
  constraint belongs in stage2_call2a_system.j2.

  Background:
    Given the control structure module is importable
    And the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory
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
  Scenario Outline: IDNS-07 stage2_call2a_system prompt contains negative RC vs PM constraint
    Given the template stage2_call2a_system.j2 is loaded
    Then the template text contains "<constraint_text>"

    Examples:
      | constraint_text                                    |
      | Every rc_id MUST start with "RC-", never "PM-".    |
      | Do NOT copy PM entries as RCs                      |

  # IDNS-08
  Scenario: IDNS-08 the retired stage2_call2 system prompt is absent
    Then the prompts directory does not contain `stage2_call2_system.j2`
