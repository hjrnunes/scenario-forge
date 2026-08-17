# End-to-End QA Suite: Revision Delta cm_id Dedup and Degradation Guard

## Overview

This QA suite verifies the SP1 Stage 2 revision-delta merge fix for
duplicate `cm_id` collisions and the degradation guard that prevents a
bad revision delta from aborting a run. All verification is done through
user-visible workflows: running the revision step with mock LLM
responses, inspecting the output control-structure YAML, inspecting the
returned warnings list, and running the full SP1 pipeline to verify
non-crash behavior. No project-internal APIs are used beyond the public
module interfaces and file I/O that a user or test harness would
perform.

---

## QA-CMID-DEDUP: Duplicate cm_id Renumbering

### QA-CMID-DEDUP-01: New link with duplicate cm_id is renumbered

**Preconditions**: A valid pre-revision ControlStructure with two
coordination links: CL-1 (cm_id CM-1) and CL-2 (cm_id CM-2), plus at
least two responsibilities (RESP-1, RESP-2) each with PM parts, CAs, and
FB channels. A mock LLM client that returns a RevisionDelta JSON with
one new coordination link CL-3 whose `coordination_mechanism.cm_id` is
`CM-1` (duplicating CL-1's cm_id), source `RESP-1`, target `RESP-2`,
shared_pm `PM-1-1`.

**Steps**:
1. Construct a mock LLM client that returns the RevisionDelta JSON
   described above.
2. Call `run_revision` with the mock client, the pre-revision
   ControlStructure, and CriticFindings with unjustified gaps.
3. Inspect the returned ControlStructure's `coordination_links`.

**Expected**: The returned ControlStructure contains three coordination
links: CL-1 (cm_id CM-1), CL-2 (cm_id CM-2), and CL-3 (cm_id CM-3). The
cm_id of CL-3 is NOT CM-1. The ControlStructure passes foundation
validation (no ValidationError raised).

### QA-CMID-DEDUP-02: Renumbered cm_id is the next free number

**Preconditions**: Same as QA-CMID-DEDUP-01.

**Steps**:
1. Run `run_revision` as in QA-CMID-DEDUP-01.
2. Inspect the cm_id of CL-3 in the returned ControlStructure.

**Expected**: CL-3 has cm_id `CM-3` (the next free number after CM-1 and
CM-2).

### QA-CMID-DEDUP-03: Renumbered cm_id conforms to CM-N format

**Preconditions**: Same as QA-CMID-DEDUP-01.

**Steps**:
1. Run `run_revision` as in QA-CMID-DEDUP-01.
2. Inspect the cm_id of CL-3.

**Expected**: The cm_id matches the regex `^CM-\d+$`. No suffixed or
mangled IDs (e.g., `CM-1_2`, `CM-1-dup`) are present.

### QA-CMID-DEDUP-04: Link content is preserved after renumbering

**Preconditions**: A mock LLM client that returns a RevisionDelta with
CL-3 whose cm_id is CM-1, source RESP-1, target RESP-2, shared_pm
PM-1-1, description "shared validation gate", and coordination_mechanism
payload "sync-message".

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect CL-3 in the returned ControlStructure.

**Expected**: CL-3 has source RESP-1, target RESP-2, shared_pm PM-1-1,
description "shared validation gate", and coordination_mechanism payload
"sync-message". Only the cm_id was changed; all other fields are
preserved.

### QA-CMID-DEDUP-05: Renumber warning is emitted

**Preconditions**: Same as QA-CMID-DEDUP-01.

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the returned warnings list.

**Expected**: The warnings list contains at least one entry that mentions
both the original colliding cm_id (`CM-1`) and the link_id (`CL-3`).

### QA-CMID-DEDUP-06: Multiple new links with duplicate cm_ids are each renumbered

**Preconditions**: A mock LLM client that returns a RevisionDelta with
two new coordination links: CL-3 (cm_id CM-1, duplicating CL-1) and
CL-4 (cm_id CM-2, duplicating CL-2). Both links reference valid
responsibilities and PM parts.

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the returned ControlStructure's coordination_links.

**Expected**: The ControlStructure contains CL-3 and CL-4. CL-3's cm_id
is not CM-1 and CL-4's cm_id is not CM-2. CL-3's cm_id differs from
CL-4's cm_id. No duplicate cm_id values exist in the final structure.

### QA-CMID-DEDUP-07: New link with unique cm_id is not renumbered

**Preconditions**: A mock LLM client that returns a RevisionDelta with
CL-3 whose cm_id is CM-3 (does not collide with existing CM-1, CM-2).

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect CL-3 and the warnings list.

**Expected**: CL-3 has cm_id CM-3 (unchanged). The warnings list does not
contain any renumber warning mentioning CM-3.

### QA-CMID-DEDUP-08: No duplicate cm_id values in final structure

**Preconditions**: Same as QA-CMID-DEDUP-01.

**Steps**:
1. Call `run_revision` with the mock client.
2. Collect all cm_id values from the returned ControlStructure's
   coordination_links.
3. Check for duplicates.

**Expected**: All cm_id values are unique. No duplicate cm_id exists.

---

## QA-CMID-DEGRADE: Degradation Guard

### QA-CMID-DEGRADE-01: Merge failure falls back to pre-revision ControlStructure

**Preconditions**: A valid pre-revision ControlStructure with RESP-1,
RESP-2, CL-1 (CM-1), CL-2 (CM-2). A mock LLM client that returns a
RevisionDelta whose merge causes a ValidationError (e.g., new
responsibility RESP-3 with a PM part pm_id PM-1-1 that duplicates an
existing PM, producing a duplicate pm_id ValidationError in the
ControlStructure constructor).

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the returned ControlStructure.
3. Verify no exception was raised.

**Expected**: No exception is raised. The returned ControlStructure is
the pre-revision ControlStructure (contains RESP-1, RESP-2, CL-1, CL-2
but NOT RESP-3 or any new elements from the delta).

### QA-CMID-DEGRADE-02: Degradation warning is emitted

**Preconditions**: Same as QA-CMID-DEGRADE-01.

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the returned warnings list.

**Expected**: The warnings list contains at least one entry mentioning
the revision delta merge failure. The warning includes the error type
(e.g., "ValidationError" or "ValueError").

### QA-CMID-DEGRADE-03: Degradation preserves existing responsibilities and links

**Preconditions**: Same as QA-CMID-DEGRADE-01.

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the returned ControlStructure.

**Expected**: The ControlStructure contains RESP-1, RESP-2, CL-1
(cm_id CM-1), and CL-2 (cm_id CM-2). All pre-revision elements are
intact.

### QA-CMID-DEGRADE-04: Full SP1 run does not crash on revision merge failure

**Preconditions**: A full SP1 pipeline run with a mock LLM that produces
valid responses for Stage 1, Call 1, Call 2, Call 3, and the critic, but
returns a RevisionDelta that causes a merge ValidationError.

**Steps**:
1. Run the full SP1 pipeline (or `_run_stage_2_block`) with the mock LLM.
2. Check that the pipeline completes without crashing.
3. Read `control-structure.yaml` from the output directory.

**Expected**: The pipeline completes. The `control-structure.yaml` file
exists and contains a valid ControlStructure. The structure is the
pre-revision one (the revision delta was discarded).

### QA-CMID-DEGRADE-05: Degradation guard catches nested pm_id collision

**Preconditions**: A valid pre-revision ControlStructure with RESP-1
(having PM-1-1) and RESP-2. A mock LLM that returns a RevisionDelta with
new_responsibilities containing RESP-3 with a PM part pm_id PM-1-1
(duplicating RESP-1's PM).

**Steps**:
1. Call `run_revision` with the mock client.
2. Verify no exception was raised.
3. Inspect the returned ControlStructure.

**Expected**: No exception is raised. The returned ControlStructure is
the pre-revision structure (RESP-3 is not present). A degradation
warning is in the warnings list.

---

## QA-CMID-AIRBNB: Airbnb Regression Shape

### QA-CMID-AIRBNB-01: Airbnb failure shape does not crash

**Preconditions**: A pre-revision ControlStructure matching the Airbnb
failure: two coordination links CL-1 (cm_id CM-1) and CL-2 (cm_id CM-2),
plus responsibilities RESP-1 and RESP-2. A mock LLM that returns a
RevisionDelta with new_coordination_links containing CL-3 whose
coordination_mechanism.cm_id is CM-1 (the exact collision shape from the
Airbnb failure).

**Steps**:
1. Call `run_revision` with the mock client.
2. Verify no exception was raised.
3. Inspect the returned ControlStructure.

**Expected**: No exception. The ControlStructure contains CL-1 (cm_id
CM-1), CL-2 (cm_id CM-2), and CL-3 (cm_id CM-3, renumbered). All cm_id
values are unique. The structure passes foundation validation.

### QA-CMID-AIRBNB-02: Airbnb shape — warning emitted for the collision

**Preconditions**: Same as QA-CMID-AIRBNB-01.

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the returned warnings list.

**Expected**: The warnings list contains an entry mentioning CM-1 and
CL-3.

### QA-CMID-AIRBNB-03: Full SP1 run with Airbnb shape completes

**Preconditions**: A full SP1 pipeline run with a mock LLM that produces
the Airbnb failure shape during revision: valid responses through Call 3,
critic finds gaps, revision returns CL-3 with cm_id CM-1.

**Steps**:
1. Run the full SP1 pipeline with the mock LLM.
2. Check that the pipeline completes without crashing.
3. Read `control-structure.yaml` from the output directory.

**Expected**: The pipeline completes. `control-structure.yaml` contains
a valid ControlStructure with three coordination links, all with unique
cm_id values. No crash, no abort.

---

## QA-CMID-NORMAL: Normal Path Unchanged

### QA-CMID-NORMAL-01: Successful merge with no collisions produces no extra warnings

**Preconditions**: A mock LLM that returns a RevisionDelta with
new_coordination_links containing CL-3 whose cm_id is CM-3 (no
collision).

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the warnings list.

**Expected**: The warnings list does not contain any renumber warning or
degradation warning. CL-3 has cm_id CM-3 (unchanged).

### QA-CMID-NORMAL-02: Empty revision delta produces no warnings

**Preconditions**: A mock LLM that returns an empty RevisionDelta (no
new or modified elements).

**Steps**:
1. Call `run_revision` with the mock client.
2. Inspect the warnings list.

**Expected**: The warnings list does not contain any renumber or
degradation warning. The ControlStructure is unchanged from the
pre-revision state.
