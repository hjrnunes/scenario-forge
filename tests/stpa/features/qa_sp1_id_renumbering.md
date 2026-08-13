# End-to-End QA Suite: SP1 Deterministic ID Renumbering

## Scope and interface

QA exercises only the `scenario-forge stpa-run` command and its published
artifacts. A deterministic OpenAI-compatible fixture endpoint supplies the LLM
responses, and a QA model-profiles file points the CLI at that endpoint. QA
does not import or call project modules.

The fixture provides valid responses for the full run while varying the IDs in
the Stage 2 and revision responses. Each case uses a fresh output directory.

## QA-SP1-ID-01: Canonical IDs for every element type

**Fixture response:** Two responsibilities, each with two RCs, PMs, CAs, and
FBs; two controlled processes; and two coordination links. All source IDs are
noncanonical strings.

**Workflow:**
1. Run `uv run scenario-forge stpa-run` with the fixture model profile, valid
   use-case and risk-extraction files, and a fresh output directory.
2. Verify exit code `0`.
3. Inspect `control-structure.yaml`.

**Expected:** Responsibilities are `RESP-1`, `RESP-2`. Children of each
responsibility are numbered by their parent and one-based child position:
`RC-X-Y`, `PM-X-Y`, `CA-X-Y`, and `FB-X-Y`. Controlled processes are `CP-1`,
`CP-2`. Links are `CL-1`, `CL-2`, and their mechanisms are `CM-1`, `CM-2`.

## QA-SP1-ID-02: Local and global references follow renumbering

**Fixture response:** Both responsibilities use the same old PM ID
`shared-state`; each FB updates its local PM. PM feedback sources, CA targets,
and FB sources reference old responsibility or controlled-process IDs. A
coordination link references unique old responsibility and PM IDs.

**Workflow:**
1. Run the CLI with the fixture response.
2. Inspect all reference fields in `control-structure.yaml`.

**Expected:** Each FB `updates` points to a PM under the same responsibility
(`PM-1-1` or `PM-2-1`). Typed element references point to the corresponding
`RESP-N` or `CP-N` while retaining their `type`. Coordination `source`,
`target`, and `shared_pm` point to existing canonical IDs. No old referenced ID
remains.

## QA-SP1-ID-03: Duplicate, malformed, and cross-namespace IDs are repaired

**Fixture response:** Duplicate CA and FB IDs, duplicate CM IDs, malformed IDs
for every element type, and the same `RC-9-9` value used as both an RC ID and a
PM ID. All references are otherwise resolvable.

**Workflow:**
1. Run the CLI with the fixture response.
2. Verify exit code `0`.
3. Inspect `control-structure.yaml` and `run-manifest.yaml`.

**Expected:** The output contains every source element in original list order.
IDs are unique within each type, match their type formats, and do not collide
across namespaces. The manifest has no SP1 stage error for duplicate IDs, ID
format, or namespace collision.

## QA-SP1-ID-04: Renumbering is deterministic

**Fixture response:** Two responses with identical ordered structures and
non-ID content but completely different source IDs.

**Workflow:**
1. Run the CLI twice, once for each response, using separate output
   directories.
2. Extract the IDs and cross-reference fields from both
   `control-structure.yaml` files.
3. Compare descriptions, payloads, security-constraint references, and list
   order.

**Expected:** Both runs have identical IDs and reference fields. Non-ID content
and list order match the fixture in both runs.

## QA-SP1-ID-05: Structural positions, not numeric source IDs, control numbering

**Fixture response:** Ordered elements whose source IDs contain misleading
numbers, including responsibility IDs `RESP-90` then `RESP-3`, child IDs ending
in `99` then `1`, and links `CL-20` then `CL-4`.

**Workflow:**
1. Run the CLI with the fixture response.
2. Inspect `control-structure.yaml`.

**Expected:** The first and second elements are numbered `1` and `2`
respectively in every applicable scope. Source-ID numbers do not affect output
numbering.

## QA-SP1-ID-06: Unresolved references still fail validation

Run one fixture case for each field: FB `updates`, PM `feedback_source`, CA
`target`, FB `source`, CL `source`, CL `target`, and CL `shared_pm`.

**Workflow:**
1. Configure the selected field to reference an ID absent from the fixture.
2. Run the CLI into a fresh output directory.
3. Inspect stderr, `calls.jsonl`, `run-manifest.yaml`, and any emitted
   `control-structure.yaml`.

**Expected:** The absent ID is not converted to an unrelated canonical ID and
is not present in any published control-structure reference. The user-visible
diagnostics identify the affected field and missing ID. Any control structure
that is published remains valid under the existing SP1 graceful-degradation
policy.

## QA-SP1-ID-07: Published artifact passes independent schema loading

**Fixture response:** The mixed failure-class response from QA-SP1-ID-03.

**Workflow:**
1. Run the CLI successfully.
2. Run
   `uv run scenario-forge stpa-report --output-dir <output-dir> --output <report-path>`.

**Expected:** The report command exits with code `0`, creates the requested
report, and reports no duplicate-ID, ID-format, namespace-collision, or
cross-reference error.

## QA-SP1-ID-08: Normal conforming input remains structurally unchanged

**Fixture response:** A fully conforming structure already numbered in
structural order with valid references.

**Workflow:**
1. Run the CLI.
2. Compare the fixture's Stage 2 structure with `control-structure.yaml`.

**Expected:** IDs and references retain the same canonical values. Non-ID
fields and list order are unchanged. No renumbering-related SP1 error appears
in the manifest.
