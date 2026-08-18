Feature: Phase 4 QA refresh migration
  The acceptance-refresh QA command may adopt the shared QA harness without
  changing its command-line contract, acceptance-refresh behavior, process
  isolation, or repository scope.

  Background:
    Given the Phase 4 migration baseline is commit "9e112ea23a"
    And live endpoint opt-in is unset

  # Phase 4 QA refresh migration P4QRM-01 preserves the documented CLI
  Scenario Outline: Phase 4 QA refresh migration P4QRM-01 preserves the documented CLI
    When acceptance-refresh QA help is requested
    Then acceptance-refresh QA exits with status 0
    And help advertises option "<option>"
    And help identifies "--static", "--pipeline", and "--all" as required mutually exclusive modes

    Examples:
      | option                       |
      | --help                       |
      | --static                     |
      | --pipeline                   |
      | --all                        |
      | --use-case USE_CASE          |
      | --risk-extraction RISK_EXTRACTION |
      | --capability-profile CAPABILITY_PROFILE |

  # Phase 4 QA refresh migration P4QRM-02 reports successful modes deterministically
  Scenario Outline: Phase 4 QA refresh migration P4QRM-02 reports successful modes deterministically
    Given a successful local pipeline stand-in supplies the characterized acceptance-refresh artifacts
    When acceptance-refresh QA mode "<mode>" is run twice with all input options
    Then both runs exit with status 0
    And each recorded check is emitted once in recording order
    And both runs have identical ordered check results
    And each run reports "<summary>"
    And the pipeline stand-in is invoked <pipeline_runs> time per run
    And the endpoint contact count remains 0

    Examples:
      | mode       | summary                           | pipeline_runs |
      | --static   | QA suite: 519 passed, 0 failed    | 0             |
      | --pipeline | QA suite: 18 passed, 0 failed     | 1             |
      | --all      | QA suite: 537 passed, 0 failed    | 1             |

  # Phase 4 QA refresh migration P4QRM-03 preserves invalid invocation outcomes
  Scenario Outline: Phase 4 QA refresh migration P4QRM-03 preserves invalid invocation outcomes
    When acceptance-refresh QA is invoked with "<arguments>"
    Then acceptance-refresh QA exits with status <exit_status>
    And output contains "<message>"
    And no pipeline child is started

    Examples:
      | arguments  | exit_status | message                                                                 |
      | none       | 2           | one of the arguments --static --pipeline --all is required              |
      | --pipeline | 1           | ERROR: --use-case and --risk-extraction required for pipeline checks    |
      | --all      | 1           | ERROR: --use-case and --risk-extraction required for pipeline checks    |

  # Phase 4 QA refresh migration P4QRM-04 isolates pipeline subprocess observations
  Scenario: Phase 4 QA refresh migration P4QRM-04 isolates pipeline subprocess observations
    Given a local pipeline stand-in emits distinct standard output and standard error and exits with status 7
    And the parent environment and working directory are recorded
    When acceptance-refresh QA is run in "--pipeline" mode with all input options
    Then the pipeline child receives the documented stpa-run arguments
    And the pipeline child runs from the repository root
    And its exit status, standard output, and standard error remain separately observable
    And the QA command reports "QA suite: 0 passed, 2 failed"
    And acceptance-refresh QA exits with status 1
    And the parent environment and working directory remain unchanged
    And temporary pipeline output is removed after the run

  # Phase 4 QA refresh migration P4QRM-05 supports nested working-directory invocation
  Scenario: Phase 4 QA refresh migration P4QRM-05 supports nested working-directory invocation
    Given acceptance-refresh QA is invoked by absolute path from a nested temporary directory
    When "--static" mode is run twice
    Then both runs discover the repository root
    And both runs exit with status 0
    And both runs emit the same ordered checks and "QA suite: 519 passed, 0 failed"
    And neither run changes the caller working directory

  # Phase 4 QA refresh migration P4QRM-06 preserves generated acceptance-refresh scenarios
  Scenario Outline: Phase 4 QA refresh migration P4QRM-06 preserves generated acceptance-refresh scenarios
    Given the acceptance-refresh source feature "<source_feature>" is generated
    And endpoint URLs target a local contact sentinel
    When its generated acceptance test is run twice with live opt-in unset
    Then each run reports exactly <scenario_count> distinct scenarios as PASS
    And neither run reports an acceptance-refresh scenario as FAIL or SKIP
    And both runs report the same ordered scenario outcomes
    And the endpoint contact count remains 0

    Examples:
      | source_feature                                            | scenario_count |
      | acceptance-refresh/stage1b-entry-point-guidance.feature  | 8              |
      | acceptance-refresh/stage1b-grounding.feature             | 7              |
      | acceptance-refresh/stage2-coordination-analysis.feature  | 12             |
      | acceptance-refresh/stage2-assembly-fallback.feature      | 8              |

  # Phase 4 QA refresh migration P4QRM-07 migrates exactly one existing suite
  Scenario: Phase 4 QA refresh migration P4QRM-07 migrates exactly one existing suite
    Given the migration change set is compared with the Phase 4 migration baseline
    Then "acceptance/qa/acceptance-refresh/qa_suite.py" is the only existing QA suite changed
    And every other existing QA suite is byte-for-byte unchanged
    And the shared QA harness is byte-for-byte unchanged
    And acceptance-refresh runtime registration is byte-for-byte unchanged
    And no production path beneath "src/" is added, modified, or deleted
    And acceptance configuration and generation commands are byte-for-byte unchanged

  # Phase 4 QA refresh migration P4QRM-08 preserves generated-output and worktree hygiene
  Scenario: Phase 4 QA refresh migration P4QRM-08 preserves generated-output and worktree hygiene
    Given the complete unrelated worktree status and content are recorded
    When the migrated suite and generated Phase 4 acceptance test are run
    Then IR, dry reports, generated tests, metadata, coverage, mutation, and QA capture artifacts remain untracked
    And generated artifacts remain within their configured generated-output paths
    And generated metadata contains no absolute checkout path
    And no source-analysis or generated-output scope changes
    And every unrelated worktree path retains its original status and content
