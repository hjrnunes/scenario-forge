# mutation-stamp: sha256=13f7ac8af3ef7cdebc82396a540040039871c133f9aaf5abd0b8c21500f233d9
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T20:48:59.184076Z","feature_name":"SP1 Stage 2 Call 3 ConnectionSet merge","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/sp1_connection_set_merge.feature","background_hash":"096166f5b6ee6ca3e8647b722119b4ca2834bea98cb8fa1545bdbd5b2c2a8b21","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 2 Call 3 ConnectionSet merge
  Stage 2 Call 3 uses a slim ConnectionSet response schema that captures only
  new outputs: coordination links, controlled processes, and connection
  assignments.  A merge function combines the ResponsibilitySet from Call 2
  with the ConnectionSet from Call 3 to produce the final ControlStructure.
  Call 1 and Call 2 behavior is unchanged.  Revision still uses the full
  ControlStructure as its response format.

  Background:
    Given the STPA system model module is importable
    And a loss analysis with security constraints SC-1 and SC-2 is available
    And a use-case description is available
    And a valid ResponsibilitySet from Call 2 with responsibilities RESP-1 and RESP-2

  # ConnSet-01
  Scenario: ConnSet-01 Call 3 produces a ConnectionSet
    Given an LLM that returns a valid ConnectionSet JSON with coordination links
    When Stage 2 Call 3 connections derivation is run
    Then a ConnectionSet is produced from Call 3

  # ConnSet-02
  Scenario: ConnSet-02 ConnectionSet contains coordination links, controlled processes, and connection assignments
    Given an LLM that returns a ConnectionSet with coordination link CL-1, controlled process CP-1, and connection assignment for element FB-1-1
    When Stage 2 Call 3 connections derivation is run
    Then the ConnectionSet contains coordination link CL-1
    And the ConnectionSet contains controlled process CP-1
    And the ConnectionSet contains connection assignment for element FB-1-1

  # ConnSet-03
  Scenario: ConnSet-03 merge produces a valid ControlStructure
    Given an LLM that returns a valid ConnectionSet JSON with coordination links
    When Stage 2 control structure derivation is run
    Then a ControlStructure model is produced
    And the control structure passes foundation validation

  # ConnSet-04
  Scenario: ConnSet-04 connection assignment updates feedback source by element ID
    Given a ResponsibilitySet where FB-1-1 has no feedback source
    And an LLM that returns a ConnectionSet with assignment for FB-1-1 setting source to controlled process CP-1
    When Stage 2 control structure derivation is run
    Then the final ControlStructure has feedback channel FB-1-1 with source CP-1

  # ConnSet-05
  Scenario: ConnSet-05 connection assignment updates control action target by element ID
    Given a ResponsibilitySet where CA-1-1 has no target
    And an LLM that returns a ConnectionSet with assignment for CA-1-1 setting target to controlled process CP-1
    When Stage 2 control structure derivation is run
    Then the final ControlStructure has control action CA-1-1 with target CP-1

  # ConnSet-06
  Scenario: ConnSet-06 coordination links appear in the final ControlStructure
    Given an LLM that returns a ConnectionSet with coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains coordination link CL-1
    And CL-1 has source RESP-1 and target RESP-2

  # ConnSet-07
  Scenario: ConnSet-07 controlled processes appear in the final ControlStructure
    Given an LLM that returns a ConnectionSet with controlled process CP-1
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains controlled process CP-1

  # ConnSet-08
  Scenario: ConnSet-08 Call 3 is logged with stage stage_2 and step call_3_connections
    Given an LLM that returns a valid ConnectionSet JSON with coordination links
    And a run directory for call logging
    When Stage 2 control structure derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is call_3_connections

  # ConnSet-09
  Scenario: ConnSet-09 control structure is written to control-structure.yaml
    Given an LLM that returns valid responses for all three Stage 2 calls
    And a run directory for output
    When Stage 2 control structure derivation is run
    Then a file control-structure.yaml exists in the run directory
    And the file contains a valid ControlStructure model when read back

  # ConnSet-10
  Scenario: ConnSet-10 Call 3 user prompt contains responsibilities from Call 2
    Given an LLM that returns a valid RequirementSet for Call 1
    And an LLM that returns a valid ResponsibilitySet for Call 2
    And an LLM that returns a valid ConnectionSet for Call 3
    When Stage 2 calls 1 through 3 are run in sequence
    Then the Call 3 user prompt contains responsibilities and controlled processes from Call 2

  # ConnSet-11
  Scenario: ConnSet-11 revision still uses ControlStructure as response format
    Given a valid ControlStructure from Stage 2
    And critic findings with unjustified gaps
    And an LLM that returns a valid revised ControlStructure JSON
    When Stage 2 revision is run
    Then a ControlStructure model is produced
    And the control structure passes foundation validation
