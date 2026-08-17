# technology-context-classification
Feature: SP2 Stage 3 technology context capability-aware tool classification
  The technology context builder classifies tools from the capability
  profile's tool inventory into read-only/retrieval, write/execute, or
  unknown categories and emits category-specific failure-mode suffixes.
  Categories must not collapse to one generic suffix.

  Background:
    Given the SP2 technology context builder is importable

  # SP2-PR-30
  Scenario: SP2-PR-30 read-only/retrieval tool emits output fabrication and exfiltration failure mode
    Given a capability profile with tool <tool_name> having description <description>
    When the technology context block is built
    Then the block contains text containing <tool_name>
    And the block contains text containing output fabrication
    And the block contains text containing exfiltration
    Examples:
      | tool_name      | description                          |
      | search-index   | Reads and retrieves documents        |
      | rag-query      | Queries the knowledge base           |
      | data-lookup    | Fetches records from the database    |
      | get-config     | Reads configuration values           |

  # SP2-PR-31
  Scenario: SP2-PR-31 write/execute tool emits parameter manipulation and unauthorized state change failure mode
    Given a capability profile with tool <tool_name> having description <description>
    When the technology context block is built
    Then the block contains text containing <tool_name>
    And the block contains text containing parameter manipulation
    And the block contains text containing unauthorized state change
    Examples:
      | tool_name      | description                          |
      | send-email     | Sends notification emails            |
      | execute-code   | Runs Python code in a sandbox        |
      | update-record  | Modifies database records            |
      | file-write     | Writes files to disk                 |

  # SP2-PR-32
  Scenario: SP2-PR-32 unknown tool emits conservative fallback failure mode
    Given a capability profile with tool <tool_name> having description <description>
    When the technology context block is built
    Then the block contains text containing <tool_name>
    And the block contains a conservative fallback failure mode
    Examples:
      | tool_name      | description                          |
      | mystery-tool   | Does something unspecified           |
      | api-bridge     | Connects two systems                 |

  # SP2-PR-33
  Scenario: SP2-PR-33 read-only and write tools produce distinct suffixes
    Given a capability profile with tool read-query having description Reads data
    And a capability profile with tool write-action having description Writes data
    When the technology context block is built
    Then the block contains text containing read-query
    And the block contains text containing write-action
    And the suffix for read-query is not identical to the suffix for write-action

  # SP2-PR-34
  Scenario: SP2-PR-34 empty tool inventory produces no tool failure mode lines
    Given a capability profile with no tool inventory
    When the technology context block is built
    Then the block does not contain the word susceptible in any tool line

  # SP2-PR-35
  Scenario: SP2-PR-35 tool descriptions with overlapping verbs are classified by dominant intent
    Given a capability profile with tool <tool_name> having description <description>
    When the technology context block is built
    Then the block classifies the tool as <expected_category>
    Examples:
      | tool_name            | description                                  | expected_category |
      | read-and-write-log   | Reads logs and writes audit entries          | write             |
      | query-and-store      | Queries the API and stores results           | write             |
      | retrieve-and-format  | Retrieves documents and formats output       | read              |
