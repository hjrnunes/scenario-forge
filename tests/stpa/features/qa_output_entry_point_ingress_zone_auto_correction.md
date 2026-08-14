# End-to-End QA Suite: Output Entry Point Ingress Zone Auto-correction

This suite verifies the feature through the `scenario-forge generate` command
and its generated capability-profile artifact. It does not import or invoke a
project API.

## Prerequisites

- Run `uv sync`.
- Ensure `/opt/homebrew/bin` is on `PATH`.
- Use only paths below `tmp/qa-output-ingress-zone/` for QA artifacts.

## QA-OIZ-01: Generate with a contradictory pre-built profile

1. Create `tmp/qa-output-ingress-zone/use-case.txt` containing:

   ```text
   An AI assistant emits audit records and accepts user prompts.
   ```

2. Create `tmp/qa-output-ingress-zone/risk-extraction.json` containing `[]`.
3. Create an empty file at `tmp/qa-output-ingress-zone/mappings.sssom.tsv`.
4. Create `tmp/qa-output-ingress-zone/capability-profile.yaml`:

   ```yaml
   zones_active:
     - input
     - reasoning
   entry_points:
     - name: Audit Logs
       direction: output
       ingress_zone: reasoning
     - name: Notifications
       direction: output
       ingress_zone: null
     - name: User Prompt
       direction: input
       ingress_zone: reasoning
     - name: Admin Console
       direction: bidirectional
       ingress_zone: input
   confidence: high
   kc_subcodes:
     - KC1.1
   ```

5. Run:

   ```bash
   PATH="/opt/homebrew/bin:$PATH" uv run scenario-forge generate \
     --use-case '@tmp/qa-output-ingress-zone/use-case.txt' \
     --risk-extraction tmp/qa-output-ingress-zone/risk-extraction.json \
     --sssom tmp/qa-output-ingress-zone/mappings.sssom.tsv \
     --output-dir tmp/qa-output-ingress-zone/output \
     --profile tmp/qa-output-ingress-zone/capability-profile.yaml \
     --base-url http://127.0.0.1:1/v1 \
     --api-key qa-unused \
     --model qa-no-network \
     --no-eval
   ```

6. Verify that the command exits with status `0`, prints `Pipeline complete.`,
   and does not print an entry-point validation error.
7. From the printed `Run directory`, open `capability-profile.yaml`.
8. Parse that YAML using a general-purpose YAML reader, not a Scenario Forge
   model or helper.
9. Verify these observable artifact values:
   - `Audit Logs` has `direction: output` and `ingress_zone: null`.
   - `Notifications` still has `direction: output` and `ingress_zone: null`.
   - `User Prompt` still has `direction: input` and
     `ingress_zone: reasoning`.
   - `Admin Console` still has `direction: bidirectional` and
     `ingress_zone: input`.

**Expected:** The CLI accepts the profile, nullifies only the contradictory
output ingress zone, preserves all other declared values, and completes the
zero-risk run without contacting an LLM.

## QA-OIZ-02: Reuse the normalized generated profile

1. Run the same command again with a fresh output collection, using the
   `capability-profile.yaml` produced by QA-OIZ-01 as `--profile`.
2. Verify that the command exits with status `0` and prints
   `Pipeline complete.`.
3. Inspect the second generated `capability-profile.yaml` with a
   general-purpose YAML reader.
4. Verify that all four entry points have the same directions and ingress-zone
   values observed in QA-OIZ-01.

**Expected:** Loading already-normalized profile data is idempotent and does
not introduce a validation failure or alter non-output ingress zones.

All generated QA artifacts remain isolated under the gitignored
`tmp/qa-output-ingress-zone/` directory.
