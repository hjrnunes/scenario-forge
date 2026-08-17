Feature: SP1 tolerant decode ID alias
  LLM control-structure responses commonly use the generic key id for element
  identifiers. During tolerant decoding, id supplies a required model field
  ending in _id only when that model-specific field is absent. This preserves
  source IDs for deterministic reference rewriting without changing unrelated
  fields or overriding an explicit model-specific ID.

  Background:
    Given an SP1 LLM response is decoded in tolerant mode
    And every field not varied by the scenario is valid

  # SP1-TOLERANT-DECODE-ID-ALIAS-01 decodes generic element IDs into model-specific fields
  Scenario Outline: SP1-TOLERANT-DECODE-ID-ALIAS-01 decodes generic element IDs into model-specific fields
    Given a <element> response has id <input_id>
    And the response omits <model_id_field>
    When the response is decoded
    Then the decoded <element> has <model_id_field> <expected_id>

    Examples:
      | element                   | input_id | expected_id | model_id_field |
      | responsibility            | RESP-9   | RESP-9      | resp_id        |
      | responsibility constraint | RC-9-8   | RC-9-8      | rc_id          |
      | process model part        | PM-9-7   | PM-9-7      | pm_id          |
      | control action            | CA-9-6   | CA-9-6      | ca_id          |
      | feedback channel          | FB-9-5   | FB-9-5      | fb_id          |
      | controlled process        | CP-4     | CP-4        | cp_id          |
      | coordination link         | CL-3     | CL-3        | link_id        |
      | coordination mechanism    | CM-2     | CM-2        | cm_id          |

  # SP1-TOLERANT-DECODE-ID-ALIAS-02 gives an explicit model-specific ID precedence
  Scenario Outline: SP1-TOLERANT-DECODE-ID-ALIAS-02 gives an explicit model-specific ID precedence
    Given a <element> response has id ignored-source-id
    And the response has <model_id_field> <input_id>
    When the response is decoded
    Then the decoded <element> has <model_id_field> <expected_id>

    Examples:
      | element            | model_id_field | input_id | expected_id |
      | responsibility     | resp_id        | RESP-7   | RESP-7      |
      | feedback channel   | fb_id          | FB-7-2   | FB-7-2      |
      | controlled process | cp_id          | CP-6     | CP-6        |

  # SP1-TOLERANT-DECODE-ID-ALIAS-03 does not use id for unrelated required fields
  Scenario: SP1-TOLERANT-DECODE-ID-ALIAS-03 does not use id for unrelated required fields
    Given a control action response has id CA-4-3
    And the response omits description
    When the response is decoded
    Then the decoded control action has ca_id CA-4-3
    And the decoded control action has an empty description
