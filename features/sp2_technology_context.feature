# mutation-stamp: sha256=bb6dda7200703b92d461c9201a7dbab8bdb0e5db193d9776b72f615940d4c1e6
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T07:32:43.112123Z","feature_name":"SP2 Stage 3 \u2014 Technology context block","feature_path":"features/sp2_technology_context.feature","background_hash":"767c6f3282d92270bee5fbd1778a0e37ceddc0cf76c0cb61e141ab10a5ba7807","implementation_hash":"unknown","scenarios":[{"index":0,"name":"SP2-TECH-01 zone-based failure modes are emitted","scenario_hash":"39e25f0b3ea41a38972fe1206467d673ef51bbcde95234654a6fa7ceb7bbf28e","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-10T00:47:13.389384Z"},{"index":1,"name":"SP2-TECH-02 KC sub-code specific failure modes are emitted","scenario_hash":"ba97828bcdf083935ea6bf50fa94a7a20cc9e7f9a3e7342107977eb5c6a49def","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-10T00:47:13.389384Z"}]}
# acceptance-mutation-manifest-end

Feature: SP2 Stage 3 — Technology context block
  The technology context block is a deterministic mapping from a CapabilityProfile
  to implementation-specific failure mode text. It is the mechanism by which
  AI-specific threats enter the enumeration without compromising the control
  structure's solution-neutrality. No LLM calls. Same CapabilityProfile always
  produces the same technology context block.

  Background:
    Given the SP2 technology context module is importable
    And a capability profile with no zones, no KC subcodes, no entry points, and no tools

  # SP2-TECH-01
  Scenario Outline: SP2-TECH-01 zone-based failure modes are emitted
    Given a capability profile with zone <zone> active
    When the technology context block is built
    Then the block contains text containing <expected_text>

    Examples:
      | zone            | expected_text            |
      | input           | prompt injection         |
      | tool_execution  | parameter injection      |
      | memory          | memory poisoning         |
      | inter_agent     | agent impersonation      |

  # SP2-TECH-02
  Scenario Outline: SP2-TECH-02 KC sub-code specific failure modes are emitted
    Given a capability profile with KC subcode <kc_subcode>
    When the technology context block is built
    Then the block contains text containing <expected_text>

    Examples:
      | kc_subcode  | expected_text           |
      | KC6.3.3     | retrieval poisoning     |
      | KCX-HITL    | alert fatigue           |
      | KC2.3       | multi-agent             |

  # SP2-TECH-03
  Scenario: SP2-TECH-03 KC sub-code prefix matching for KC4.3 cross-session memory
    Given a capability profile with KC subcode KC4.3.1
    When the technology context block is built
    Then the block contains text containing cross-session

  # SP2-TECH-04
  Scenario: SP2-TECH-04 KC sub-code prefix matching for KC6.2 code execution
    Given a capability profile with KC subcode KC6.2.1
    When the technology context block is built
    Then the block contains text containing code execution

  # SP2-TECH-05
  Scenario: SP2-TECH-05 entry point with indirect controllability emits supply chain text
    Given a capability profile with entry point RAG-knowledge-base having controllability indirect
    When the technology context block is built
    Then the block contains text containing supply chain

  # SP2-TECH-06
  Scenario: SP2-TECH-06 entry point with bidirectional direction emits exfiltration text
    Given a capability profile with entry point file-upload having direction bidirectional
    When the technology context block is built
    Then the block contains text containing exfiltration

  # SP2-TECH-07
  Scenario: SP2-TECH-07 tool inventory emits per-tool failure mode text
    Given a capability profile with tool refund-api having description processes refunds
    When the technology context block is built
    Then the block contains text containing refund-api
    And the block contains text containing parameter manipulation

  # SP2-TECH-08
  Scenario: SP2-TECH-08 no relevant capabilities produces default text
    When the technology context block is built
    Then the block contains text containing No specific technology context

  # SP2-TECH-09
  Scenario: SP2-TECH-09 technology context is deterministic
    Given a capability profile with zone input and KC subcode KC6.3.3
    When the technology context block is built twice
    Then both runs produce identical text

  # SP2-TECH-10
  Scenario: SP2-TECH-10 technology context makes no LLM calls
    Given a capability profile with zone input and zone tool_execution
    When the technology context block is built
    Then no LLM calls are made

  # SP2-TECH-11
  Scenario: SP2-TECH-11 multiple zones produce multiple failure mode lines
    Given a capability profile with zones input and tool_execution and memory
    When the technology context block is built
    Then the block contains text containing prompt injection
    And the block contains text containing parameter injection
    And the block contains text containing memory poisoning
