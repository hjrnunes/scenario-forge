Feature: Tolerant LLM decoding of omitted required fields
  Tolerant decoding creates an attribute-safe model graph so deterministic
  post-processing can repair malformed LLM output before validation. Omitted
  required scalar and collection fields receive type-appropriate sentinels,
  declared defaults remain authoritative, and required nested models are not
  fabricated.

  Background:
    Given a JSON-shaped LLM result
    And the result is decoded without field validation

  # TOLERANT-LLM-DECODE-01 supplies a type-appropriate sentinel for an omitted required field
  Scenario Outline: TOLERANT-LLM-DECODE-01 supplies a type-appropriate sentinel for an omitted required field
    Given the response model declares an omitted required field with annotation <annotation>
    When the LLM result is tolerantly decoded
    Then the required field can be accessed without AttributeError
    And the required field value is <expected_value>

    Examples:
      | annotation    | expected_value |
      | str           | ""             |
      | int           | 0              |
      | float         | 0.0            |
      | bool          | false          |
      | list[str]     | []             |
      | tuple[str]    | ()             |
      | set[str]      | set()          |
      | dict[str,int] | {}             |

  # TOLERANT-LLM-DECODE-02 preserves declared defaults for omitted fields
  Scenario Outline: TOLERANT-LLM-DECODE-02 preserves declared defaults for omitted fields
    Given <model> declares omitted field <field> with declared default <expected_value>
    When the LLM result is tolerantly decoded
    Then the required field can be accessed without AttributeError
    And the required field value is <expected_value>

    Examples:
      | model             | field           | expected_value |
      | ControlAction     | target          | None           |
      | ControlElementSet | control_actions | []             |

  # TOLERANT-LLM-DECODE-03 does not fabricate an omitted required nested model
  Scenario Outline: TOLERANT-LLM-DECODE-03 does not fabricate an omitted required nested model
    Given a coordination link omits required CoordinationMechanism field coordination_mechanism
    When the LLM result is tolerantly decoded
    Then the required field can be accessed without AttributeError
    And the required field value is <expected_value>
    When the decoded result is post-processed and validated
    Then validation fails with an error identifying coordination_mechanism

    Examples:
      | expected_value |
      | None           |

  # TOLERANT-LLM-DECODE-04 preserves explicitly null optional fields
  Scenario: TOLERANT-LLM-DECODE-04 preserves explicitly null optional fields
    Given a Pydantic LLM result explicitly sets optional field unused to null
    When the LLM result is tolerantly decoded
    Then field unused remains null
