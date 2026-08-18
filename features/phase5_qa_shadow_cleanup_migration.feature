Feature: Phase 5 QA shadow-cleanup migration
  The shadow-cleanup QA command may adopt the shared QA harness without
  changing its characterized command-line modes, check outcomes, process
  isolation, shadow-cleanup acceptance behavior, or repository scope.

  Background:
    Given the Phase 5 migration baseline is commit "5a79d55b35"
    And live endpoint opt-in is unset for shadow-cleanup QA

  # Phase 5 QA shadow-cleanup migration P5QSCM-01 preserves the documented CLI
  Scenario Outline: Phase 5 QA shadow-cleanup migration P5QSCM-01 preserves the documented CLI
    When shadow-cleanup QA help is requested
    Then shadow-cleanup QA exits with status 0
    And help advertises shadow-cleanup option "<option>"
    And help identifies "--static", "--dynamic", "--pipeline", and "--all" as independently selectable modes

    Examples:
      | option            |
      | --help            |
      | --static          |
      | --dynamic         |
      | --pipeline        |
      | --all             |
      | --run-dir RUN_DIR |

  # Phase 5 QA shadow-cleanup migration P5QSCM-02 preserves deterministic mode results
  Scenario Outline: Phase 5 QA shadow-cleanup migration P5QSCM-02 preserves deterministic mode results
    When shadow-cleanup QA invocation "<arguments>" is run twice
    Then both shadow-cleanup runs exit with status <exit_status>
    And each shadow-cleanup check is emitted once in recording order
    And both runs have identical ordered shadow-cleanup results
    And each run reports "<summary>"
    And each run emits <passed> PASS, <failed> FAIL, and <skipped> SKIP results
    And the endpoint contact count remains 0

    Examples:
      | arguments          | passed | failed | skipped | summary                           | exit_status |
      | --static           | 50     | 1      | 0       | QA suite: 50 passed, 1 failed    | 1           |
      | --dynamic          | 58     | 0      | 0       | QA suite: 58 passed, 0 failed    | 0           |
      | --pipeline         | 0      | 0      | 2       | QA suite: 0 passed, 0 failed     | 0           |
      | --static --dynamic | 108    | 1      | 0       | QA suite: 108 passed, 1 failed   | 1           |
      | --all              | 108    | 1      | 2       | QA suite: 108 passed, 1 failed   | 1           |
      | none               | 108    | 1      | 2       | QA suite: 108 passed, 1 failed   | 1           |

  # Phase 5 QA shadow-cleanup migration P5QSCM-03 preserves invalid invocation outcomes
  Scenario Outline: Phase 5 QA shadow-cleanup migration P5QSCM-03 preserves invalid invocation outcomes
    When shadow-cleanup QA is invoked with invalid arguments "<arguments>"
    Then shadow-cleanup QA exits with status 2
    And shadow-cleanup output contains "<message>"
    And no shadow-cleanup check or child process is started

    Examples:
      | arguments       | message                                         |
      | --not-an-option | unrecognized arguments: --not-an-option         |
      | --run-dir       | argument --run-dir: expected one argument       |

  # Phase 5 QA shadow-cleanup migration P5QSCM-04 isolates the property-test subprocess
  Scenario: Phase 5 QA shadow-cleanup migration P5QSCM-04 isolates the property-test subprocess
    Given a local property-test stand-in emits distinct standard output and standard error and exits with status 7
    And the parent environment and working directory are recorded for shadow-cleanup QA
    When shadow-cleanup QA is run in "--dynamic" mode with the property-test stand-in
    Then the property-test child receives the two characterized no-shadowing test node identifiers
    And the property-test child runs once from the repository root
    And its exit status, standard output, and standard error remain separately observable
    And shadow-cleanup QA reports "QA suite: 57 passed, 1 failed"
    And shadow-cleanup QA exits with status 1
    And the parent environment and working directory remain unchanged
    And the endpoint contact count remains 0

  # Phase 5 QA shadow-cleanup migration P5QSCM-05 supports nested working-directory invocation
  Scenario: Phase 5 QA shadow-cleanup migration P5QSCM-05 supports nested working-directory invocation
    Given shadow-cleanup QA is invoked by absolute path from a nested temporary directory
    When shadow-cleanup "--static" mode is run twice
    Then both shadow-cleanup runs discover the repository root
    And both shadow-cleanup runs exit with status 1
    And both runs emit the same ordered results and "QA suite: 50 passed, 1 failed"
    And neither run changes the caller working directory

  # Phase 5 QA shadow-cleanup migration P5QSCM-06 preserves generated shadow-cleanup scenarios
  Scenario: Phase 5 QA shadow-cleanup migration P5QSCM-06 preserves generated shadow-cleanup scenarios
    Given the source feature "shadow-cleanup/no-shadowing-invariant.feature" is generated
    And endpoint URLs target a local contact sentinel
    When its generated acceptance test is run twice with live opt-in unset
    Then each run reports exactly 5 distinct shadow-cleanup scenarios as PASS
    And neither run reports a shadow-cleanup scenario as FAIL or SKIP
    And both runs report the same ordered shadow-cleanup scenario outcomes
    And the endpoint contact count remains 0

  # Phase 5 QA shadow-cleanup migration P5QSCM-07 migrates exactly one suite without changing shadow-cleanup registration
  Scenario: Phase 5 QA shadow-cleanup migration P5QSCM-07 migrates exactly one suite without changing shadow-cleanup registration
    Given the migration change set is compared with the Phase 5 migration baseline
    Then "acceptance/qa/shadow-cleanup/qa_suite.py" is the only existing QA suite changed
    And every other existing QA suite is byte-for-byte unchanged
    And the pre-existing shadow-cleanup runtime feature is byte-for-byte unchanged
    And the shadow-cleanup feature identity, handler patterns, priorities, and scopes are unchanged
    And no production path beneath "src/" is added, modified, or deleted
    And acceptance configuration and generation commands are byte-for-byte unchanged

  # Phase 5 QA shadow-cleanup migration P5QSCM-08 preserves generated-output and worktree hygiene
  Scenario: Phase 5 QA shadow-cleanup migration P5QSCM-08 preserves generated-output and worktree hygiene
    Given the complete unrelated worktree status and content are recorded for Phase 5
    When the migrated shadow-cleanup suite and generated Phase 5 acceptance test are run
    Then IR, dry reports, generated tests, metadata, coverage, mutation, and QA capture artifacts remain untracked
    And generated artifacts remain within their configured generated-output paths
    And generated metadata contains no absolute checkout path
    And no source-analysis or generated-output scope changes
    And every unrelated worktree path retains its original status and content
