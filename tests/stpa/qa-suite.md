# STPA-Sec Foundation — End-to-End QA Suite

This document specifies the user-visible workflows that QA verifies for the
STPA-Sec Pipeline Shared Foundation (Phase 0). All verification is done
through the Python import API, pytest execution, and filesystem inspection —
no project-internal APIs are used.

## 1. Module Structure Verification

### QA-STRUCT-01: Module layout matches spec

**Steps:**
1. Verify `src/scenario_forge/stpa/__init__.py` exists and is importable.
2. Verify `src/scenario_forge/stpa/infra/__init__.py` exists and is importable.
3. Verify `src/scenario_forge/stpa/models/__init__.py` exists and is importable.
4. Verify the following infra modules exist and are importable:
   - `src/scenario_forge/stpa/infra/llm.py`
   - `src/scenario_forge/stpa/infra/call_log.py`
   - `src/scenario_forge/stpa/infra/yaml_io.py`
   - `src/scenario_forge/stpa/infra/templates.py`
   - `src/scenario_forge/stpa/infra/manifest.py`
5. Verify the following model modules exist and are importable:
   - `src/scenario_forge/stpa/models/loss_analysis.py`
   - `src/scenario_forge/stpa/models/control_structure.py`
   - `src/scenario_forge/stpa/models/ica_enumeration.py`
   - `src/scenario_forge/stpa/models/enriched_threat_set.py`
   - `src/scenario_forge/stpa/models/scenario_spec.py`
   - `src/scenario_forge/stpa/models/scenario_envelope.py`
6. Verify `src/scenario_forge/stpa/fixtures/` directory exists.

**Command:**
```bash
uv run python -c "
from scenario_forge.stpa.models import loss_analysis, control_structure, ica_enumeration, enriched_threat_set, scenario_spec, scenario_envelope
from scenario_forge.stpa.infra import llm, call_log, yaml_io, templates, manifest
print('All STPA modules importable')
"
```

### QA-STRUCT-02: No coupling to existing pipeline infrastructure

**Steps:**
1. Grep `src/scenario_forge/stpa/infra/` for imports of `scenario_forge.pipeline.io`, `scenario_forge.manifest`, `scenario_forge.prompts`.
2. Verify none of those imports exist.

**Command:**
```bash
grep -r "scenario_forge.pipeline.io\|scenario_forge.manifest\|scenario_forge.prompts" src/scenario_forge/stpa/infra/ || echo "No coupling found"
```

### QA-STRUCT-03: Models imported from existing codebase, not copied

**Steps:**
1. Verify `src/scenario_forge/stpa/` does not contain a `capability_profile.py` or `risk_card.py` model definition.
2. Verify the stpa models import `CapabilityProfile` and `RiskCard` from `scenario_forge.models.capability_profile` and `scenario_forge.models.risk_card`.

**Command:**
```bash
grep -r "from scenario_forge.models.capability_profile import\|from scenario_forge.models.risk_card import" src/scenario_forge/stpa/
```

## 2. Schema Validation Verification

### QA-SCHEMA-01: LossAnalysis validation rules

**Steps:**
1. Run the test suite for LossAnalysis model validation.
2. Verify tests cover: valid input, hazard→loss cross-ref, constraint→hazard cross-ref, provenance consistency (risk_card/use_case/critic_derived), duplicate ID rejection.

**Command:**
```bash
uv run pytest tests/stpa/ -k loss_analysis -v
```

### QA-SCHEMA-02: ControlStructure validation rules

**Steps:**
1. Run the test suite for ControlStructure model validation.
2. Verify tests cover: feedback_source refs, target refs, updates refs (same responsibility), coordination link refs, shared_pm refs, duplicate ID rejection, structural heuristics (≥1 PM/CA/FB, orphan PM warnings, CP referenced).

**Command:**
```bash
uv run pytest tests/stpa/ -k control_structure -v
```

### QA-SCHEMA-03: ICAEnumeration validation rules

**Steps:**
1. Run the test suite for ICAEnumeration model validation.
2. Verify tests cover: is_na/icas mutual exclusivity, na_justification requirement, hazard/constraint ref validation, duplicate slot_id rejection, all UCA types accepted.

**Command:**
```bash
uv run pytest tests/stpa/ -k ica_enumeration -v
```

### QA-SCHEMA-04: EnrichedThreatSet validation rules

**Steps:**
1. Run the test suite for EnrichedThreatSet model validation.
2. Verify tests cover: structural threat fields, catalog mapping confidence levels, coverage analysis metrics, na_reconciliation_flag, catalog_correspondence.

**Command:**
```bash
uv run pytest tests/stpa/ -k enriched_threat -v
```

### QA-SCHEMA-05: ScenarioSpec validation rules

**Steps:**
1. Run the test suite for ScenarioSpec model validation.
2. Verify tests cover: defender BDI refs (PM/RESP/CA), target_controller ref, target_control_action ref and belonging, threat source provenance, attacker BDI free-form, catalog context.

**Command:**
```bash
uv run pytest tests/stpa/ -k scenario_spec -v
```

### QA-SCHEMA-06: ScenarioEnvelope validation

**Steps:**
1. Run the test suite for ScenarioEnvelope model validation.
2. Verify tests cover: wrapping with all artifacts, scenario_id consistency, faceting metadata derivation, catalog mappings.

**Command:**
```bash
uv run pytest tests/stpa/ -k scenario_envelope -v
```

## 3. Fixture Validation

### QA-FIX-01: All fixtures load and validate

**Steps:**
1. Run the fixture validation test.
2. Verify all five fixture files load without errors and validate against their schemas.

**Command:**
```bash
uv run pytest tests/stpa/test_fixtures.py -v
```

### QA-FIX-02: Fixture files have provenance headers

**Steps:**
1. For each fixture file in `src/scenario_forge/stpa/fixtures/*.yaml`, check that the file begins with a YAML comment (line starting with `#`) documenting provenance.

**Command:**
```bash
for f in src/scenario_forge/stpa/fixtures/*.yaml; do
  echo "=== $f ==="
  head -3 "$f"
done
```

### QA-FIX-03: All five required fixtures are present

**Steps:**
1. List the fixtures directory and verify all five required files exist:
   - `loss_analysis_klarna.yaml`
   - `capability_profile_klarna.yaml`
   - `control_structure_klarna.yaml`
   - `ica_enumeration_klarna.yaml`
   - `enriched_threats_klarna.yaml`

**Command:**
```bash
ls src/scenario_forge/stpa/fixtures/*.yaml
```

## 4. Infrastructure Verification

### QA-INFRA-01: LLM client clean copy

**Steps:**
1. Verify `LLMClient` and `LLMResult` are importable from `scenario_forge.stpa.infra.llm`.
2. Verify environment variable resolution works (base_url, model, temperature).
3. Verify explicit constructor args override environment variables.
4. Verify ValueError when no base_url is configured.
5. Verify OpenRouter header auto-injection.

**Command:**
```bash
uv run pytest tests/stpa/ -k "infra_llm or InfraLLM" -v
```

### QA-INFRA-02: Call log JSONL format

**Steps:**
1. Write call log entries to a temporary `calls.jsonl` file.
2. Verify each entry is valid JSON with required fields (stage, step, slot_id, scenario_id, model, prompt_tokens, completion_tokens, duration_ms, timestamp, success).
3. Verify entries are appended (not overwritten).
4. Verify empty entry list does not create a file.

**Command:**
```bash
uv run pytest tests/stpa/ -k "call_log or InfraCallLog" -v
```

### QA-INFRA-03: YAML I/O round-trip

**Steps:**
1. Create a Pydantic model instance (e.g., LossAnalysis).
2. Write it to a YAML file using `write_yaml`.
3. Read it back using `read_yaml` with the same model class.
4. Verify the read-back model matches the original.
5. Verify `read_yaml` on invalid data raises a validation error.

**Command:**
```bash
uv run pytest tests/stpa/ -k "yaml_io or InfraYAML" -v
```

### QA-INFRA-04: Template loader parameterized

**Steps:**
1. Create a temporary prompts directory with a Jinja2 template.
2. Create a template loader with the directory path.
3. Render a template and verify the output.
4. Verify `hash_prompt_templates` returns SHA-256 hashes for all `.j2` files.
5. Verify undefined variables raise `StrictUndefined` errors.
6. Verify the loader does not reference the existing pipeline's `data/prompts` directory.

**Command:**
```bash
uv run pytest tests/stpa/ -k "templates or InfraTemplates" -v
```

### QA-INFRA-05: Run manifest simplified

**Steps:**
1. Verify `STPARunManifest` is importable from `scenario_forge.stpa.infra.manifest`.
2. Construct a manifest with all fields populated and verify validation succeeds.
3. Verify the manifest module does not import the existing pipeline's manifest module.

**Command:**
```bash
uv run pytest tests/stpa/ -k "manifest or InfraManifest" -v
```

## 5. Full Test Suite Execution

### QA-FULL-01: All STPA tests pass

**Steps:**
1. Run the complete STPA test suite.
2. Verify all tests pass with zero failures.

**Command:**
```bash
uv run pytest tests/stpa/ -v
```

### QA-FULL-02: Existing tests unaffected

**Steps:**
1. Run the existing test suite to verify no regressions.
2. Verify the STPA foundation does not modify existing source files.

**Command:**
```bash
uv run pytest tests/ -x --ignore=tests/stpa/ -q
```

### QA-FULL-03: Linting passes

**Steps:**
1. Run ruff on the new STPA source and test files.
2. Verify no lint errors.

**Command:**
```bash
ruff check src/scenario_forge/stpa/ tests/stpa/
```
