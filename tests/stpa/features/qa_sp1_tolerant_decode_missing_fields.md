# End-to-End QA Suite: SP1 Tolerant Decode of Missing Fields

## Scope and interface

QA drives only the published `scenario-forge stpa-run` command and inspects
its console output and published artifacts. A deterministic OpenAI-compatible
fixture endpoint supplies ordered LLM responses through a QA model profile.
All responses not varied below are valid. QA does not import or call project
modules.

Each case uses valid use-case, risk-extraction, and capability-profile files
and a fresh output directory. Search stderr, `calls.jsonl`, and
`run-manifest.yaml` for `AttributeError` and `has no attribute`; neither text
may occur.

Use this command shape for every case:

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

## QA-SP1-TOLERANT-01: Omitted `ca_id` is repaired

**Fixture:** Call 2a returns responsibilities `RESP-8` and `RESP-4`. Call 2b
returns one control action without `ca_id`, followed by one with `ca_id:
CA-4-9`. Both actions have valid descriptions and references.

**Workflow:**
1. Run `uv run scenario-forge stpa-run` with the fixture profiles and inputs.
2. Verify exit code `0`.
3. Inspect `control-structure.yaml` and user-visible diagnostics.

**Expected:** The first responsibility contains `CA-1-1`; the second contains
`CA-2-1`. Descriptions and list order are preserved. No missing-attribute
diagnostic occurs.

## QA-SP1-TOLERANT-02: Missing and blank Call 2b IDs use position

**Fixture:** Call 2b returns, in order, control actions with omitted and blank
`ca_id`, feedback channels with omitted and blank `fb_id`, and controlled
processes with omitted and blank `cp_id`. Required non-ID fields and
cross-references are valid.

**Workflow:**
1. Run the CLI into a fresh output directory.
2. Verify exit code `0`.
3. Inspect `control-structure.yaml`.

**Expected:** The published elements retain their source order and have
canonical IDs from their one-based structural positions: `CA-X-Y`, `FB-X-Y`,
and `CP-N`. No blank ID remains, and no missing-attribute diagnostic occurs.

## QA-SP1-TOLERANT-03: Missing description becomes a validation diagnostic

**Fixture:** Call 2b returns a control action with source ID `source-action`
but omits its required `description`. The remaining response is valid.

**Workflow:**
1. Run the CLI into a fresh output directory.
2. Verify the command exits with controlled failure code `1`.
3. Inspect stderr and `calls.jsonl`.

**Expected:** The user-visible error identifies the control action
`description` as invalid after the ID repair boundary. It does not report
`ca_id`, `AttributeError`, `has no attribute`, or a Python traceback. No
invalid `control-structure.yaml` is published.

## QA-SP1-TOLERANT-04: Fallback does not re-crash

**Fixture:** Call 2a returns one responsibility. Call 2b returns a control
action without `ca_id` whose target is absent controlled process `CP-99`.
This invalid reference forces assembly fallback.

**Workflow:**
1. Run the CLI into a fresh output directory.
2. Verify exit code `0` under the existing graceful-degradation policy.
3. Inspect `control-structure.yaml`, `calls.jsonl`, and `run-manifest.yaml`.

**Expected:** The artifact contains `RESP-1` with control action `CA-1-1`;
the action target is absent. Diagnostics identify the stripped target and the
original unresolved reference. The fallback completes once without a
missing-attribute failure.

## QA-SP1-TOLERANT-05: Defaults remain defaults

**Fixture:** Call 2b omits optional `target` and all defaulted Call 2b
collections not needed by the case.

**Workflow:**
1. Run the CLI with an otherwise valid response.
2. Verify exit code `0`.
3. Inspect `control-structure.yaml`.

**Expected:** The omitted target is absent and omitted collections behave as
empty collections. They are not replaced with incompatible sentinels.

## QA-SP1-TOLERANT-06: Required nested models are not fabricated

**Fixture:** Call 3 returns a coordination link that omits required
`coordination_mechanism`; all prior calls are valid.

**Workflow:**
1. Run the CLI into a fresh output directory.
2. Inspect the final control structure and degradation diagnostics.

**Expected:** The malformed coordination link is not published. The base
control structure remains valid, and diagnostics identify
`coordination_mechanism` validation. No invented mechanism and no
missing-attribute diagnostic appears.
