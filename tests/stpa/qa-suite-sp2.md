# SP2 Threat Enumeration — End-to-End QA Suite

This document specifies the user-visible workflows that QA verifies for SP2
(Threat Enumeration: Stages 3 and 4 of the STPA-Sec pipeline). All
verification is done through the CLI (`scripts/run_sp2.py`), Python import
checks, pytest execution, and filesystem inspection — no project-internal
APIs are used.

## 1. Module Structure Verification

### QA-SP2-STRUCT-01: Module layout matches spec

**Steps:**
1. Verify the SP2 threat enumeration package exists and is importable.
2. Verify all modules listed in the spec exist and are importable.
3. Verify the prompt templates directory exists with both Jinja2 templates.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.threat_enum import slot_creation, technology_context, slot_filling, na_quality, catalog_enrichment, catalog_data, coverage, run
print('All SP2 modules importable')
"
```

**Command:**
```bash
ls src/scenario_forge/stpa/threat_enum/prompts/stage3_system.j2 src/scenario_forge/stpa/threat_enum/prompts/stage3_user.j2
```

### QA-SP2-STRUCT-02: CLI script exists and accepts arguments

**Steps:**
1. Verify `scripts/run_sp2.py` exists.
2. Run `scripts/run_sp2.py --help` and verify it accepts `--control-structure`, `--capability-profile`, `--loss-analysis`, `--output-dir`, `--max-workers`, and `--profile` arguments.

**Command:**
```bash
uv run python scripts/run_sp2.py --help
```

## 2. Slot Creation Verification (Deterministic)

### QA-SP2-SLOT-01: Slot count formula via unit tests

**Steps:**
1. Run the slot creation unit tests.
2. Verify tests cover the slot count formula for various control structure dimensions, UCA type coverage, slot_id format, initial slot state, determinism, and uniqueness.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp2_slot" -v
```

### QA-SP2-SLOT-02: Slot creation on Klarna fixture

**Steps:**
1. Load the Klarna control structure fixture.
2. Run `create_slots` and verify the total slot count matches the formula.
3. Verify the Klarna control structure has 4 responsibilities with 2 control actions each and 2 coordination links, producing 40 total slots.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.threat_enum.slot_creation import create_slots
cs = read_yaml('src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
slots = create_slots(cs)
print(f'Total slots: {len(slots)}')
assert len(slots) == 40, f'Expected 40, got {len(slots)}'
resp_slots = [s for s in slots if s.responsibility]
link_slots = [s for s in slots if s.coordination_link]
assert len(resp_slots) == 32, f'Expected 32 resp slots, got {len(resp_slots)}'
assert len(link_slots) == 8, f'Expected 8 link slots, got {len(link_slots)}'
print('Slot count formula verified')
"
```

## 3. Technology Context Verification (Deterministic)

### QA-SP2-TECH-01: Technology context on Klarna fixture

**Steps:**
1. Load the Klarna capability profile fixture.
2. Run `build_technology_context` and verify the output contains zone-based, KC-based, entry-point-based, and tool-based failure mode text.
3. Verify the Klarna profile has zones input, reasoning, tool_execution, KC subcode KC6.3.3 (RAG), and tool inventory entries.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.threat_enum.technology_context import build_technology_context
profile = read_yaml('src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml', CapabilityProfile)
ctx = build_technology_context(profile)
assert 'prompt injection' in ctx.lower(), 'Missing input zone failure mode'
assert 'parameter injection' in ctx.lower(), 'Missing tool_execution zone failure mode'
assert 'retrieval poisoning' in ctx.lower(), 'Missing KC6.3.3 failure mode'
assert 'refund' in ctx.lower() or 'payment' in ctx.lower(), 'Missing tool inventory entry'
print('Technology context verified')
print(ctx[:500])
"
```

### QA-SP2-TECH-02: Technology context determinism

**Steps:**
1. Run `build_technology_context` twice on the same profile.
2. Verify both outputs are identical.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.threat_enum.technology_context import build_technology_context
profile = read_yaml('src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml', CapabilityProfile)
ctx1 = build_technology_context(profile)
ctx2 = build_technology_context(profile)
assert ctx1 == ctx2, 'Technology context is not deterministic'
print('Determinism verified')
"
```

## 4. N/A Quality Gates Verification (Deterministic)

### QA-SP2-NA-01: N/A quality gate unit tests

**Steps:**
1. Run the N/A quality unit tests.
2. Verify tests cover structural keyword check (pass and flag cases), ratio monitoring (above, at, and below threshold), coordination link exclusion, and empty slot list.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp2_na" -v
```

## 5. Catalog Enrichment Verification (Deterministic)

### QA-SP2-CAT-01: Catalog enrichment unit tests

**Steps:**
1. Run the catalog enrichment unit tests.
2. Verify tests cover keyword matching (mapped and unmapped), confidence levels, N/A reconciliation, coverage analysis three-way partition, by-ICA-type, by-controller, structural consideration metric, N/A quality metric, uncovered OWASP threats, and no LLM calls.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp2_catalog or sp2_coverage" -v
```

### QA-SP2-CAT-02: Catalog enrichment on Klarna ICA fixture

**Steps:**
1. Load the Klarna ICA enumeration fixture and control structure fixture.
2. Run catalog enrichment on the ICA enumeration.
3. Verify the enriched threat set validates against the EnrichedThreatSet schema.
4. Verify at least one structural threat has a catalog mapping.
5. Verify at least one structural threat is unmapped.
6. Verify coverage analysis has structural_coverage, by_ica_type, by_controller, and catalog_correspondence fields.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.threat_enum.catalog_enrichment import enrich_threats
ica = read_yaml('src/scenario_forge/stpa/fixtures/ica_enumeration_klarna.yaml', ICAEnumeration)
cs = read_yaml('src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml', ControlStructure)
enriched = enrich_threats(ica, cs)
# Validate schema
EnrichedThreatSet.model_validate(enriched.model_dump())
mapped = [t for t in enriched.structural_threats if t.catalog_mappings]
unmapped = [t for t in enriched.structural_threats if not t.catalog_mappings]
assert len(mapped) >= 1, 'Expected at least one mapped threat'
assert len(unmapped) >= 1, 'Expected at least one unmapped threat'
assert enriched.coverage_analysis.structural_coverage['total_slots'] > 0
assert len(enriched.coverage_analysis.by_ica_type) > 0
assert len(enriched.coverage_analysis.by_controller) > 0
print(f'Structural threats: {len(enriched.structural_threats)}')
print(f'Mapped: {len(mapped)}, Unmapped: {len(unmapped)}')
print('Catalog enrichment verified')
"
```

## 6. Run Orchestration (End-to-End CLI Run)

### QA-SP2-RUN-01: Full SP2 run with LLM produces output artifacts

**Prerequisites:**
- LLM endpoint configured (via `--profile` or environment variables).
- SP1 fixtures available for Klarna use case.

**Steps:**
1. Run `scripts/run_sp2.py` with the Klarna fixtures as input.
2. Verify the output directory contains `ica-enumeration.yaml`, `enriched-threats.yaml`, `calls.jsonl`, and a run manifest.
3. Verify `ica-enumeration.yaml` loads as a valid `ICAEnumeration`.
4. Verify `enriched-threats.yaml` loads as a valid `EnrichedThreatSet`.
5. Verify `calls.jsonl` contains entries with stage `stage_3`.
6. Verify no `calls.jsonl` entries have stage `stage_4` (Stage 4 is deterministic, no LLM).

**Command:**
```bash
uv run python scripts/run_sp2.py \
  --control-structure src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml \
  --capability-profile src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml \
  --loss-analysis src/scenario_forge/stpa/fixtures/loss_analysis_klarna.yaml \
  --output-dir tmp/sp2-qa-run \
  --profile <profile-name>
```

**Verification:**
```bash
ls tmp/sp2-qa-run/ica-enumeration.yaml tmp/sp2-qa-run/enriched-threats.yaml tmp/sp2-qa-run/calls.jsonl
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
ica = read_yaml('tmp/sp2-qa-run/ica-enumeration.yaml', ICAEnumeration)
enriched = read_yaml('tmp/sp2-qa-run/enriched-threats.yaml', EnrichedThreatSet)
print(f'ICA slots: {len(ica.slots)}')
print(f'Structural threats: {len(enriched.structural_threats)}')
print(f'Coverage rate: {enriched.coverage_analysis.structural_coverage[\"coverage_rate\"]}')
"
grep -c 'stage_3' tmp/sp2-qa-run/calls.jsonl
grep -c 'stage_4' tmp/sp2-qa-run/calls.jsonl || true  # should be 0
```

### QA-SP2-RUN-02: Run manifest records stage summary and metadata

**Steps:**
1. After running QA-SP2-RUN-01, inspect the run manifest.
2. Verify the manifest has `stage_summary` with call counts for `stage_3`.
3. Verify the manifest records `input_hashes` for the control structure, capability profile, and loss analysis.
4. Verify the manifest records `prompt_hashes` for `stage3_system.j2` and `stage3_user.j2`.
5. Verify the manifest records N/A quality flags and coverage analysis.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from pathlib import Path
manifest = read_yaml('tmp/sp2-qa-run/run-manifest.yaml', dict)
assert 'stage_summary' in manifest, 'Missing stage_summary'
assert 'stage_3' in str(manifest['stage_summary']), 'Missing stage_3 in stage_summary'
assert 'input_hashes' in manifest, 'Missing input_hashes'
assert 'prompt_hashes' in manifest, 'Missing prompt_hashes'
print('Run manifest verified')
print(f'Stage summary: {manifest[\"stage_summary\"]}')
"
```

### QA-SP2-RUN-03: Stage 4 makes no LLM calls

**Steps:**
1. After running QA-SP2-RUN-01, verify that `calls.jsonl` contains no entries with stage `stage_4`.
2. This confirms catalog enrichment is fully deterministic.

**Command:**
```bash
! grep 'stage_4' tmp/sp2-qa-run/calls.jsonl && echo 'Stage 4 made no LLM calls — verified'
```

### QA-SP2-RUN-04: --max-workers flag controls parallelism

**Steps:**
1. Run `scripts/run_sp2.py` with `--max-workers 2`.
2. Verify the run completes successfully and produces the same output artifacts.

**Command:**
```bash
uv run python scripts/run_sp2.py \
  --control-structure src/scenario_forge/stpa/fixtures/control_structure_klarna.yaml \
  --capability-profile src/scenario_forge/stpa/fixtures/capability_profile_klarna.yaml \
  --loss-analysis src/scenario_forge/stpa/fixtures/loss_analysis_klarna.yaml \
  --output-dir tmp/sp2-qa-run-parallel \
  --profile <profile-name> \
  --max-workers 2
ls tmp/sp2-qa-run-parallel/ica-enumeration.yaml tmp/sp2-qa-run-parallel/enriched-threats.yaml
```

## 7. Fixture Validation

### QA-SP2-FIX-01: SP2 fixtures load and validate

**Steps:**
1. Load `ica_enumeration_klarna.yaml` and verify it validates as `ICAEnumeration`.
2. Load `enriched_threats_klarna.yaml` and verify it validates as `EnrichedThreatSet`.
3. Verify the ICA enumeration fixture has N/A exclusivity (is_na XOR icas) on every slot.
4. Verify the enriched threat set fixture has coverage analysis with structural_consideration and na_quality metrics.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.ica_enumeration import ICAEnumeration
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
ica = read_yaml('src/scenario_forge/stpa/fixtures/ica_enumeration_klarna.yaml', ICAEnumeration)
enriched = read_yaml('src/scenario_forge/stpa/fixtures/enriched_threats_klarna.yaml', EnrichedThreatSet)
for slot in ica.slots:
    if slot.is_na:
        assert not slot.icas, f'{slot.slot_id}: N/A slot has ICAs'
        assert slot.na_justification, f'{slot.slot_id}: N/A slot missing justification'
    else:
        assert slot.icas, f'{slot.slot_id}: non-N/A slot has no ICAs'
        assert slot.na_justification is None, f'{slot.slot_id}: non-N/A slot has justification'
assert enriched.coverage_analysis.structural_consideration, 'Missing structural_consideration'
assert enriched.coverage_analysis.na_quality, 'Missing na_quality'
print(f'ICA slots: {len(ica.slots)}')
print(f'Structural threats: {len(enriched.structural_threats)}')
print('All SP2 fixtures validated')
"
```

### QA-SP2-FIX-02: SP2 fixtures have provenance headers

**Steps:**
1. For each SP2 fixture file, verify the file begins with a YAML comment documenting provenance.

**Command:**
```bash
for f in src/scenario_forge/stpa/fixtures/ica_enumeration_klarna.yaml src/scenario_forge/stpa/fixtures/enriched_threats_klarna.yaml; do
  echo "=== $f ==="
  head -5 "$f"
done
```

## 8. Acceptance Tests

### QA-SP2-ACCEPT-01: SP2 Gherkin acceptance tests pass

**Steps:**
1. Run the SP2 acceptance tests generated from the Gherkin feature files.
2. Verify all scenarios pass.

**Command:**
```bash
uv run pytest tmp/acceptance/generated/sp2_*_acceptance_test.py -v
```

## 9. Full Test Suite Execution

### QA-SP2-FULL-01: All SP2 tests pass

**Steps:**
1. Run the complete SP2 test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -k "sp2 or threat_enum" -v
```

### QA-SP2-FULL-02: Existing tests unaffected

**Steps:**
1. Run the existing test suite excluding SP2 tests to verify no regressions.
2. Verify the SP2 implementation does not modify existing source files.

**Command:**
```bash
uv run pytest tests/ -x --ignore=tests/stpa/ -q
```

### QA-SP2-FULL-03: Linting passes

**Steps:**
1. Run ruff on the new SP2 source and test files.
2. Verify no lint errors.

**Command:**
```bash
ruff check src/scenario_forge/stpa/threat_enum/ tests/stpa/
```
