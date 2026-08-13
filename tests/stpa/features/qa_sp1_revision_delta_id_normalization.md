# End-to-End QA Suite: SP1 Revision-Delta ID Normalization

## Scope and interface

QA uses only the `scenario-forge stpa-run` command and its published files.
An OpenAI-compatible deterministic fixture endpoint supplies complete LLM
responses, including critic findings that trigger revision. A QA model-profile
file selects that endpoint. QA does not import project modules or call a
project API. Every case uses a fresh output directory.

The pre-revision Stage 2 fixture publishes two canonical responsibilities,
one controlled process, and one coordination link. Unless a case says
otherwise, all elements are complete and all references are resolvable.

## QA-SP1-REV-ID-01: Malformed revision IDs are accepted and normalized

**Revision response:** Decodable JSON adding one complete responsibility, one
controlled process, and one coordination link. Every added ID is a
nonconforming descriptive string, including all nested IDs and the
coordination mechanism ID. References use those source IDs.

**Workflow:**
1. Run `uv run scenario-forge stpa-run` with the fixture model profile, valid
   inputs, and a fresh output directory.
2. Verify exit code `0`.
3. Inspect `control-structure.yaml` and `run-manifest.yaml`.

**Expected:** The added elements and their descriptions are present. Their IDs
are `RESP-3`, `RC-3-1`, `PM-3-1`, `CA-3-1`, `FB-3-1`, `CP-2`, `CL-2`, and
`CM-2`. The manifest marks revision as attempted and contains no revision
failure or merge-degradation warning.

## QA-SP1-REV-ID-02: Duplicate nested IDs are separated

**Revision response:** Replace `RESP-2` and add one responsibility. The
replacement and addition reuse the same source IDs for their RC, PM, CA, and
FB children. Each FB updates its local PM.

**Workflow:**
1. Run the CLI with the fixture response.
2. Inspect both revised responsibilities in `control-structure.yaml`.

**Expected:** The replacement children are `RC-2-1`, `PM-2-1`, `CA-2-1`, and
`FB-2-1`; the addition children are `RC-3-1`, `PM-3-1`, `CA-3-1`, and
`FB-3-1`. Every nested ID is globally unique, and each FB updates the PM under
its own responsibility.

## QA-SP1-REV-ID-03: Revision references resolve after final renumbering

**Revision response:** Replace `RESP-2` with a PM source ID `revised-state`;
add a process `revised-process`, a responsibility `revised-controller`, and a
coordination link. Use those source IDs in PM `feedback_source`, CA `target`,
FB `source` and `updates`, and link `source`, `target`, and `shared_pm`.

**Workflow:**
1. Run the CLI.
2. Inspect every reference field in `control-structure.yaml`.

**Expected:** The PM feedback source is `RESP-3`; CA target and FB source are
`CP-2`; FB updates is `PM-2-1`; and `CL-2` source, target, and shared PM are
`RESP-3`, `RESP-1`, and `PM-2-1`. No `revised-*` source ID remains in an ID or
reference field.

## QA-SP1-REV-ID-04: Modification matching precedes final normalization

**Revision response:** Modify `RESP-2` by canonical ID and add elements whose
conforming IDs contain misleading numbers such as `RESP-90`, `CP-70`,
`CL-80`, and `CM-60`.

**Workflow:**
1. Run the CLI.
2. Compare pre-revision fixture content with `control-structure.yaml`.

**Expected:** The updated description belongs to `RESP-2`, not `RESP-1`.
`RESP-1` is unchanged. The addition is `RESP-3`; processes are `CP-1`,
`CP-2`; links are `CL-1`, `CL-2`; and mechanisms are `CM-1`, `CM-2`, all in
final list order. Existing references retain their semantic targets.

## QA-SP1-REV-ID-05: Canonical input remains stable

**Revision response:** Modify `RESP-2` and add already canonical
`RESP-3`/`CP-2`/`CL-2`/`CM-2` elements with canonical nested IDs and valid
references.

**Workflow:**
1. Run the CLI.
2. Compare IDs, references, descriptions, and list order with the expected
   merged fixture.

**Expected:** All already canonical IDs and references remain unchanged.
`RESP-2` contains the modification, all additions are present, non-ID content
is preserved, and no normalization-related warning appears.

## QA-SP1-REV-ID-06: Unresolved revision references degrade safely

Run one fixture variant for each field: FB `updates`, PM `feedback_source`, CA
`target`, FB `source`, coordination-link `source`, link `target`, and link
`shared_pm`. Set the selected reference to an absent descriptive ID.

**Workflow:**
1. Run each variant into a fresh output directory.
2. Verify the command completes under the existing graceful-degradation
   policy.
3. Inspect `control-structure.yaml`, `run-manifest.yaml`, and `calls.jsonl`.

**Expected:** The published control structure equals the valid pre-revision
structure and contains no absent ID. Post-revision warnings identify merge
degradation, the affected reference field, and the absent ID. The revision
call remains logged, proving the response was received rather than skipped.

## QA-SP1-REV-ID-07: Revision normalization is deterministic

**Revision responses:** Two responses with identical ordered additions,
modification targets, references, and non-ID content but different
LLM-selected IDs. Each response remains internally referentially consistent.

**Workflow:**
1. Run the CLI once per response in separate output directories.
2. Compare the resulting `control-structure.yaml` files.

**Expected:** IDs and rewritten references are identical across runs. Ordered
content and non-ID fields match the respective fixture. Neither run reports a
failed or degraded revision.

## QA-SP1-REV-ID-08: Published revised structure supports report generation

**Revision response:** Use the malformed-ID and duplicate-child shape from
QA-SP1-REV-ID-01 and QA-SP1-REV-ID-02 with all references resolvable.

**Workflow:**
1. Run `scenario-forge stpa-run` successfully.
2. Run the public STPA report command against the output directory.
3. Inspect the command result and generated report.

**Expected:** Report generation exits `0` and produces the requested report.
No duplicate-ID, ID-format, cross-namespace, or unresolved-reference error is
reported.
