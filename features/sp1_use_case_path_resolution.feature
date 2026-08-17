# mutation-stamp: sha256=de39709266515d43578e0a1f97795be3086d826e34de269ec276c5ae47e82845
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T19:57:53.598549Z","feature_name":"SP1 \u2014 Runner script resolves path references in use-case files","feature_path":"features/sp1_use_case_path_resolution.feature","background_hash":"bf1f14fd5a8d310fa5dfa4ed20beb3442162cd90020c1e4fa28264f9da9117a1","implementation_hash":"unknown","scenarios":[{"index":5,"name":"PathResolve-06 read_use_case resolves path references with supported extensions","scenario_hash":"005c217afbab2efbc9899de66b7a58d8c5cc03e093b532f65a7b3c52fc71e5c9","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-09T19:57:53.598549Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Runner script resolves path references in use-case files
  The read_use_case() function in scripts/run_sp1.py reads a file directly
  with Path.read_text(). If the file contains a path reference (e.g.
  "output/occiAI-guy-nhs-v14/use-case.txt") instead of actual content, the
  path string is passed as use-case text and the LLM receives garbage input.
  The fix detects when the loaded content looks like a file path (short,
  no newlines, ends with .txt or .md) and resolves the reference
  recursively, logging the first 100 chars so operators can spot issues.

  Background:
    Given the run_sp1 runner script is importable
    And the read_use_case function is available

  # PathResolve-01
  Scenario: PathResolve-01 read_use_case strips @ prefix
    Given a use-case file at path tmp/test_usecase.txt with content "This is a real use case description."
    When read_use_case is called with "@tmp/test_usecase.txt"
    Then the returned text is "This is a real use case description."

  # PathResolve-02
  Scenario: PathResolve-02 read_use_case reads a normal file without @ prefix
    Given a use-case file at path tmp/test_usecase.txt with content "This is a real use case description."
    When read_use_case is called with "tmp/test_usecase.txt"
    Then the returned text is "This is a real use case description."

  # PathResolve-03
  Scenario: PathResolve-03 read_use_case resolves a nested path reference
    Given a use-case file at path tmp/outer.txt with content "tmp/inner.txt"
    And a use-case file at path tmp/inner.txt with content "This is the actual use case content."
    When read_use_case is called with "tmp/outer.txt"
    Then the returned text is "This is the actual use case content."

  # PathResolve-04
  Scenario: PathResolve-04 read_use_case does not resolve content that looks like prose
    Given a use-case file at path tmp/prose.txt with content "This is a long use case description with multiple sentences and newlines.\nIt describes a healthcare AI system.\nThe system uses RAG retrieval."
    When read_use_case is called with "tmp/prose.txt"
    Then the returned text is the original file content without further resolution

  # PathResolve-05
  Scenario: PathResolve-05 read_use_case raises FileNotFoundError for missing file
    When read_use_case is called with "tmp/nonexistent_usecase.txt"
    Then a FileNotFoundError is raised

  # PathResolve-06
  Scenario Outline: PathResolve-06 read_use_case resolves path references with supported extensions
    Given a use-case file at path tmp/outer.<outer_ext> with content "tmp/inner.<inner_ext>"
    And a use-case file at path tmp/inner.<inner_ext> with content "This is the resolved content."
    When read_use_case is called with "tmp/outer.<outer_ext>"
    Then the returned text is "This is the resolved content."

    Examples:
      | outer_ext | inner_ext |
      | txt       | txt       |
      | txt       | md        |
      | md        | txt       |
      | md        | md        |

  # PathResolve-07
  Scenario: PathResolve-07 read_use_case raises clear error for unresolvable nested path
    Given a use-case file at path tmp/outer.txt with content "tmp/missing_ref.txt"
    When read_use_case is called with "tmp/outer.txt"
    Then a FileNotFoundError is raised
    And the error message references the unresolved path "tmp/missing_ref.txt"

  # PathResolve-08
  Scenario: PathResolve-08 read_use_case logs the first 100 characters of loaded text
    Given a use-case file at path tmp/test_usecase.txt with content "This is a real use case description that is long enough to be meaningful."
    When read_use_case is called with "tmp/test_usecase.txt"
    Then a log entry is produced containing the first 100 characters of the loaded text
