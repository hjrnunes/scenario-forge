# End-to-End QA Suite: SP1 ID Normalization Repairs

## Scope and interface

QA drives only the published `scenario-forge stpa-run` command and inspects
console output and published artifacts. A deterministic OpenAI-compatible
fixture endpoint supplies all LLM responses through QA model profiles. QA does
not import or call project modules.

Each case uses valid use-case, risk-extraction, and capability-profile files
and a fresh output directory:

```bash
uv run scenario-forge stpa-run \
  --use-case <use-case.txt> \
  --risk-extraction <risk-extraction.json> \
  --output-dir <fresh-output-dir> \
  --capability-profile <capability-profile.yaml> \
  --sp1-profile <fixture-sp1-profile> \
  --sp2-profile <fixture-sp2-profile> \
  --sp3-profile <fixture-sp3-profile> \
  --profiles-file <qa-model-profiles.yaml>
```

All fixture content not varied by a case is valid. In every successful case,
verify exit code `0`; inspect `control-structure.yaml`, `calls.jsonl`, and
`run-manifest.yaml`; and confirm no `assemble_control_structure` validation
failure or fallback-stripping warning is reported.

## QA-SP1-ID-REPAIR-01: Production-shaped response is repaired

**Fixture:** Call 2a and Call 2b use `id` rather than every model-specific ID
field. Feedback channels omit `description`. PM feedback sources, CA targets,
and FB sources copy their referenced `RESP-*` or `CP-*` ID into both
ElementRef `type` and `id`. Use misleading source IDs and list positions, such
as a second responsibility `RESP-9` and second controlled process `CP-8`, so
successful validation cannot result from source IDs already matching
canonical positions.

**Workflow:**
1. Run the CLI with the production-shaped fixture.
2. Inspect every element and cross-reference in `control-structure.yaml`.
3. Inspect assembly diagnostics in `calls.jsonl` and `run-manifest.yaml`.

**Expected:** Every element is present in source order and has a canonical ID
from its final position. Generic source IDs remain available long enough for
all resolvable references to be rewritten. ElementRef types are
`responsibility` or `controlled_process`, their IDs identify the intended
canonical elements, and all descriptions are non-empty. Assembly succeeds
without fallback or validation errors.

## QA-SP1-ID-REPAIR-02: Both inferred reference types are published

**Fixture:** Call 2a returns `RESP-3` then `RESP-9`. Call 2b returns `CP-4`
then `CP-8`. A PM references `RESP-9` with `{type: RESP-9, id: RESP-9}`. A CA
and FB reference `CP-8` with `{type: CP-8, id: CP-8}`. Generic `id` keys are
used for the referenced responsibility and controlled process.

**Workflow:**
1. Run the CLI.
2. Inspect the PM `feedback_source`, CA `target`, and FB `source`.

**Expected:** The PM reference is `{type: responsibility, id: RESP-2}`. The CA
and FB references are `{type: controlled_process, id: CP-2}`. No malformed
source type or stale source ID is published.

## QA-SP1-ID-REPAIR-03: Valid reference types remain unchanged

**Fixture:** Use the same misleading IDs and positions as
QA-SP1-ID-REPAIR-02, but supply valid ElementRef types `responsibility` and
`controlled_process`.

**Workflow:**
1. Run the CLI.
2. Inspect all ElementRefs in `control-structure.yaml`.

**Expected:** Each supplied type is unchanged, while its source ID is
rewritten to the intended canonical ID. No reference is stripped and no
normalization warning is emitted.

## QA-SP1-ID-REPAIR-04: Empty descriptions are human-readable

**Fixture:** Supply `description: ""` once for each description-bearing
element type across the Stage 2 and coordination responses: responsibility,
responsibility constraint, process model part, control action, feedback
channel, controlled process, coordination link, and coordination mechanism.
Keep all references resolvable.

**Workflow:**
1. Run the CLI.
2. Inspect every repaired description in `control-structure.yaml`.
3. Generate a report with
   `uv run scenario-forge stpa-report --output-dir <output-dir> --output <report-path>`.

**Expected:** The run and report commands succeed. The repaired descriptions
are `Responsibility RESP-1`, `Responsibility constraint RC-1-1`,
`Process model part PM-1-1`, `Control action CA-1-1`,
`Controlled process CP-1`, `Coordination link CL-1`, and
`Coordination mechanism CM-1` for elements in those positions. The feedback
description is `Feedback from controlled process <CP-N> updating process model
part <PM-X-Y>` using its canonical source and updated PM.

## QA-SP1-ID-REPAIR-05: Supplied descriptions are preserved

**Fixture:** Give every description-bearing element a distinct non-empty
description, including punctuation and mixed case, while also requiring ID
and reference normalization.

**Workflow:**
1. Run the CLI.
2. Compare fixture descriptions with `control-structure.yaml`.

**Expected:** Every non-empty supplied description is byte-for-byte unchanged.
Only recoverable blank descriptions are generated.

## QA-SP1-ID-REPAIR-06: Explicit model-specific IDs take precedence

**Fixture:** For representative responsibility, FB, and CP elements, provide
both a generic `id` and a different valid model-specific field (`resp_id`,
`fb_id`, or `cp_id`). Make references use the model-specific source values.

**Workflow:**
1. Run the CLI.
2. Inspect element placement and rewritten references.

**Expected:** References resolve from the model-specific source values, not
the generic `id` values. Final IDs still come from structural position. No
generic `id` overrides an explicit model-specific field.

## QA-SP1-ID-REPAIR-07: Uninferable reference types still fail safely

**Fixture:** A CA target uses `{type: process-alpha, id: process-alpha}` and a
controlled process has source ID `process-alpha`. No recognized `RESP-*` or
`CP-*` prefix is available for type inference.

**Workflow:**
1. Run the CLI into a fresh output directory.
2. Inspect stderr, `calls.jsonl`, `run-manifest.yaml`, and any published
   `control-structure.yaml`.

**Expected:** Diagnostics identify the invalid target type. The normalizer
does not guess a type from namespace membership alone. Any structure published
under the existing graceful-degradation policy is valid and does not contain
the malformed target.

## QA-SP1-ID-REPAIR-08: Revision responses receive the same repairs

**Fixture:** Make critic findings trigger revision. The revision delta adds a
responsibility and controlled process using generic `id` keys, an FB with an
empty description, and a CA or FB ElementRef whose `type` repeats a `CP-*`
source ID. Choose source IDs that differ from final positions.

**Workflow:**
1. Run the CLI.
2. Inspect revision diagnostics and the final `control-structure.yaml`.

**Expected:** The revised artifact contains the added elements at canonical
positions. The ElementRef has type `controlled_process` and the intended
canonical CP ID. The FB has a human-readable generated description. No
`Revision delta merge degraded` warning appears.

## QA-SP1-ID-REPAIR-09: Bare controlled-process strings are preserved

**Fixture:** Call 2b supplies a PM `feedback_source`, CA `target`, and FB
`source` as the bare string `CP-9`. The referenced controlled process is
second in its list, so its published ID is `CP-2`. Keep all other fields valid.

**Workflow:**
1. Run the CLI.
2. Inspect the three fields in `control-structure.yaml`.
3. Inspect assembly diagnostics in `calls.jsonl` and `run-manifest.yaml`.

**Expected:** Each field is published as
`{type: controlled_process, id: CP-2}`. All three references remain present,
the control structure validates, and no fallback-stripping warning appears.

## QA-SP1-ID-REPAIR-10: Bare responsibility strings are preserved

**Fixture:** Call 2b supplies a PM `feedback_source`, CA `target`, and FB
`source` as the bare string `RESP-9`. The referenced responsibility is second
in its list, so its published ID is `RESP-2`. Keep all other fields valid.

**Workflow:**
1. Run the CLI.
2. Inspect the three fields in `control-structure.yaml`.
3. Inspect assembly diagnostics in `calls.jsonl` and `run-manifest.yaml`.

**Expected:** Each field is published as
`{type: responsibility, id: RESP-2}`. All three references remain present,
the control structure validates, and no fallback-stripping warning appears.

## QA-SP1-ID-REPAIR-11: Production-sized bare-string response does not degrade

**Fixture:** Model Call 2b on the observed production shape: return 11 control
actions whose `target` values are bare `CP-*` or `RESP-*` strings and 16
feedback channels whose `source` values are bare `CP-*` or `RESP-*` strings.
Every source ID uniquely identifies an element, and several source IDs differ
from their final list-position IDs.

**Workflow:**
1. Run the CLI.
2. Count CA targets and FB sources in `control-structure.yaml`.
3. Verify each reference against the intended responsibility or controlled
   process from the fixture.
4. Inspect stderr, `calls.jsonl`, and `run-manifest.yaml`.

**Expected:** The artifact contains all 11 CA targets and all 16 FB sources as
ElementRef objects with the correct type and canonical ID. No cross-reference
is null or omitted, validation succeeds, and diagnostics contain neither an
assembly degradation nor a cross-reference stripping warning.

## QA-SP1-ID-REPAIR-12: Unrecognized bare strings still fail safely

**Fixture:** A CA target is the bare string `process-alpha`. The payload does
not provide a recognized `RESP-*` or `CP-*` prefix for that value.

**Workflow:**
1. Run the CLI into a fresh output directory.
2. Inspect stderr, `calls.jsonl`, `run-manifest.yaml`, and any published
   `control-structure.yaml`.

**Expected:** Diagnostics identify the target as an invalid ElementRef. The
normalizer does not invent a reference type. Any artifact published under the
existing graceful-degradation policy is schema-valid and does not contain the
malformed target.

## QA-SP1-ID-REPAIR-13: Correct objects and nulls do not regress

**Fixture:** Across PM `feedback_source`, CA `target`, and FB `source`, include
correct ElementRef objects for both supported types and explicit null values.
Use source IDs that require canonical rewriting for the non-null references.

**Workflow:**
1. Run the CLI.
2. Compare every affected field in `control-structure.yaml` with its fixture
   value and intended canonical element.

**Expected:** Correct objects retain their supplied `responsibility` or
`controlled_process` type and receive only the required canonical ID rewrite.
Null fields remain null. No field is spuriously wrapped, stripped, or warned
about, and the artifact validates successfully.
