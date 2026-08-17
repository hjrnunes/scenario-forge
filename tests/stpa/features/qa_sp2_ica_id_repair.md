# End-to-End QA Suite: SP2 ICA Identifier Repair

## Scope and interface

QA exercises only the `scripts/run_sp2.py` command and its published YAML
artifacts. A deterministic OpenAI-compatible fixture endpoint supplies Stage 3
responses through the CLI's model-profile flags. QA does not import or call
project modules. Each case uses a fresh output directory.

## QA-SP2-ICA-ID-01: Full enumeration repairs mixed malformed identifiers

**Fixture response:** A complete slot-fill response containing:

- a correct `RESP-1:CA-1-1:NOT_PROVIDED:1`;
- `RESP-3`, `RESP-4`, and `RESP-7` ICA identifiers missing their UCA type;
- one ICA with another slot's prefix;
- one ICA with the wrong numeric suffix; and
- otherwise valid ICA content and references.

**Workflow:**
1. Run `uv run python scripts/run_sp2.py` with valid control-structure,
   capability-profile, and loss-analysis inputs, the fixture model profile, and
   a fresh output directory.
2. Verify exit code `0` and inspect `ica-enumeration.yaml`.
3. For every non-N/A slot, compare each ICA identifier with the enclosing
   `slot_id` and its one-based list position using a YAML reader that does not
   import Scenario Forge.

**Expected:** Every identifier is exactly `<slot_id>:<position>`. The artifact
contains every returned ICA in its original slot and order, with all
non-identifier fields unchanged.

## QA-SP2-ICA-ID-02: Missing UCA types no longer collide

**Fixture response:** The `NOT_PROVIDED`, `INCORRECT`, and `WRONG_TIMING` slots
for `RESP-3:CA-3-1` each return the duplicate identifier
`RESP-3:CA-3-1:1`.

**Workflow:**
1. Run the SP2 CLI with the fixture response.
2. Inspect the three slots in `ica-enumeration.yaml`.
3. Collect all ICA identifiers from the artifact and compare their count with
   the count of distinct values.

**Expected:** The three identifiers are respectively
`RESP-3:CA-3-1:NOT_PROVIDED:1`,
`RESP-3:CA-3-1:INCORRECT:1`, and
`RESP-3:CA-3-1:WRONG_TIMING:1`. No duplicate ICA identifier exists anywhere
in the enumeration.

## QA-SP2-ICA-ID-03: Multiple ICAs receive positional suffixes

**Fixture response:** One slot returns three ICAs with missing, duplicate, or
out-of-order numeric suffixes.

**Workflow:**
1. Run the SP2 CLI with the fixture response.
2. Inspect the selected slot in `ica-enumeration.yaml`.

**Expected:** The three identifiers end in `:1`, `:2`, and `:3` in list order,
and each begins with the complete enclosing `slot_id`. ICA text, hazardous
context, loss scenario, hazard references, and constraint references retain
their fixture values.

## QA-SP2-ICA-ID-04: Conforming identifiers do not regress

**Fixture response:** Every ICA already has the expected complete slot prefix
and one-based suffix.

**Workflow:**
1. Run the SP2 CLI with the conforming fixture response.
2. Compare the fixture's slot and ICA payloads with `ica-enumeration.yaml`.

**Expected:** Every ICA identifier has the same value as the fixture.
Identifiers are unique, list order is unchanged, and no non-identifier field
changes.

## QA-SP2-ICA-ID-05: Repaired enumeration remains consumable

**Fixture response:** The mixed malformed response from QA-SP2-ICA-ID-01.

**Workflow:**
1. Run the SP2 CLI successfully.
2. Verify `ica-enumeration.yaml` and `enriched-threats.yaml` are produced.
3. Inspect `run-manifest.yaml` and the command's stderr.

**Expected:** SP2 completes without a duplicate-ICA-ID or ICA-ID-format error,
publishes the repaired enumeration, and produces downstream enriched threats
from that enumeration. The manifest records successful completion under the
existing SP2 run contract.
