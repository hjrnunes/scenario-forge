Feature: Acceptance QA runtime cleanup
  Acceptance QA infrastructure and the acceptance-refresh runtime feature may
  be reorganized without changing their command-line results, process
  isolation, runtime registration, generated-output policy, or existing
  acceptance behavior.

  Background:
    Given the repository acceptance commands and generated-output policy are available

  # Acceptance QA runtime cleanup AQRC-01 reports checks deterministically
  Scenario Outline: Acceptance QA runtime cleanup AQRC-01 reports checks deterministically
    Given a QA run records a passing check followed by a <second_result> check
    When the QA run reports its results
    Then the two check results are emitted once in recording order
    And the second result is labeled "<status>"
    And the summary is "QA suite: <passed> passed, <failed> failed"
    And the QA run exits with status <exit_status>

    Examples:
      | second_result | status | passed | failed | exit_status |
      | passing       | PASS   | 2      | 0      | 0           |
      | failing       | FAIL   | 1      | 1      | 1           |

  # Acceptance QA runtime cleanup AQRC-02 isolates child execution and captures
  Scenario: Acceptance QA runtime cleanup AQRC-02 isolates child execution and captures
    Given a QA child command writes distinct standard output and standard error and exits with status 7
    And the parent process has a recorded environment and working directory
    When the QA child command runs with one environment variable removed
    Then the child result preserves exit status 7 without raising for that status
    And standard output, standard error, and exit status are captured separately
    And the command defaults to the repository root working directory
    And the parent environment and working directory remain unchanged

  # Acceptance QA runtime cleanup AQRC-03 preserves the migrated suite interface
  Scenario: Acceptance QA runtime cleanup AQRC-03 preserves the migrated suite interface
    Given the acceptance-framework-refactor QA suite is the only suite migrated to shared QA infrastructure
    When the suite is invoked with "--skip-generate"
    Then the invocation exits with the same status as its characterization baseline
    And QA-AFR-01 is reported once as skipped by the command-line option
    And QA-AFR-02 through QA-AFR-06 execute once in order
    And captures remain under "tmp/qa-acceptance-framework/captures"
    And the suite retains its existing command-line options and result text

  # Acceptance QA runtime cleanup AQRC-04 preserves acceptance-refresh registration
  Scenario: Acceptance QA runtime cleanup AQRC-04 preserves acceptance-refresh registration
    Given the runtime manifest declares one feature identity named "acceptance_refresh"
    When the complete runtime manifest is registered
    Then the acceptance-refresh feature registers exactly 38 handlers once
    And 13 handlers retain feature scope "acceptance_refresh" and source priorities 21826 through 21838
    And 25 handlers retain global scope and source priorities 21916 through 21940
    And their pattern text, relative priority, scope, and observable handler results match the characterization baseline
    And registration restores the active feature scope to no feature

  # Acceptance QA runtime cleanup AQRC-05 preserves acceptance-refresh feature behavior
  Scenario Outline: Acceptance QA runtime cleanup AQRC-05 preserves acceptance-refresh feature behavior
    Given the acceptance-refresh source feature "<source_feature>" is generated
    When its generated acceptance test is run with live opt-in unset
    Then exactly <scenario_count> scenarios report PASS
    And no scenario in that source feature reports FAIL or SKIP

    Examples:
      | source_feature                                            | scenario_count |
      | acceptance-refresh/stage1b-entry-point-guidance.feature  | 8              |
      | acceptance-refresh/stage1b-grounding.feature             | 7              |
      | acceptance-refresh/stage2-coordination-analysis.feature  | 12             |
      | acceptance-refresh/stage2-assembly-fallback.feature      | 8              |

  # Acceptance QA runtime cleanup AQRC-06 preserves default acceptance execution
  Scenario: Acceptance QA runtime cleanup AQRC-06 preserves default acceptance execution
    Given "SCENARIO_FORGE_QA_PIPELINE" is unset in the acceptance child process
    When the default generated acceptance suite is executed
    Then every Acceptance QA runtime cleanup scenario reports PASS
    And every existing deterministic acceptance-refresh scenario reports PASS
    And exact live-LLM-marked scenarios report SKIP rather than PASS or FAIL
    And no additional failure is introduced relative to the recorded acceptance baseline

  # Acceptance QA runtime cleanup AQRC-07 keeps repository scope and generated output stable
  Scenario: Acceptance QA runtime cleanup AQRC-07 keeps repository scope and generated output stable
    Given the cleanup change set and acceptance configuration are inspected
    Then no production path beneath "src/" is added, modified, or deleted
    And permanent CRAP, DRY, and language-mutation commands remain scoped to "src/"
    And acceptance quality checks remain scoped to "src" and "acceptance"
    And IR, dry reports, generated tests, metadata, mutation workspaces, coverage files, and QA captures remain untracked generated output
    And no pre-existing unrelated worktree change is altered
