# Scenario-Forge Attack Pattern Format Analysis

Exhaustive analysis of how the AP-* attack pattern format is defined, loaded,
mapped, and consumed by the scenario-forge pipeline. Every field, every
consumption point, every design constraint.

---

## 1. Attack Pattern Schema

### 1.1 File-level structure

Each YAML file has the same top-level shape:

```yaml
source:
  name: "scenario-forge abstract attack patterns"
  version: "0.1.0"
  derived_from:
    - "OWASP Agentic AI Threats & Mitigations v1.1"
    - "NIST AI 100-2e2023"

patterns:
  AP-T7-01:
    id: "AP-T7-01"
    threat_id: "T7"
    name: "..."
    description: >
      ...
    nist_classification:
      attacker_goal: "integrity"
      attacker_knowledge: "black_box"
      learning_stage: "deployment"
      attack_class: "poisoning.targeted_poisoning"  # OPTIONAL
    prerequisite_capabilities:
      min_zones: ["input", "reasoning"]
      kc_requires:
        any: [KC1.1, KC1.2, KC1.3, KC1.4]
        all: [KCX-MAGENT]                          # OPTIONAL
```

### 1.2 All files and their coverage

| File | Threats Covered | Pattern Count |
|------|----------------|---------------|
| `attack-patterns.yaml` | T7 | 5 (AP-T7-01 to AP-T7-05) |
| `attack-patterns-agentic-only.yaml` | T8, T9, T10, T14, T16 | 19 |
| `attack-patterns-memory-tool.yaml` | T1, T2, T3, T4 | 17 |
| `attack-patterns-halluc-intent.yaml` | T5, T6, T11, T13 | 16 |
| `attack-patterns-comms-human-supply.yaml` | T12, T15, T17 | 9 |
| **Total** | T1-T17 (all) | **66 patterns** |

### 1.3 Field inventory

Every pattern has these fields:

| Field | Type | Required | Present in all files |
|-------|------|----------|---------------------|
| `id` | string (e.g. "AP-T7-01") | YES | YES |
| `threat_id` | string (e.g. "T7") | YES | YES |
| `name` | string | YES | YES |
| `description` | string (multi-line) | YES | YES |
| `nist_classification` | object | YES | YES |
| `nist_classification.attacker_goal` | string enum | YES | YES |
| `nist_classification.attacker_knowledge` | string enum | YES | YES |
| `nist_classification.learning_stage` | string enum | YES | YES |
| `nist_classification.attack_class` | string (dotted path) | NO | Only some patterns |
| `prerequisite_capabilities` | object | YES | YES |
| `prerequisite_capabilities.min_zones` | list[string] | YES | YES |
| `prerequisite_capabilities.kc_requires` | object | YES | YES |
| `prerequisite_capabilities.kc_requires.any` | list[string] | YES | YES |
| `prerequisite_capabilities.kc_requires.all` | list[string] | NO | Some patterns only |

#### `attacker_goal` values observed:
- `"integrity"` -- most common
- `"abuse"` -- second most common
- `"availability"` -- T4, T7-02, T10

#### `attacker_knowledge` values observed:
- `"black_box"` -- most common
- `"gray_box"` -- second most common
- `"white_box"` -- T17 only

#### `learning_stage` values observed:
- `"deployment"` -- ALL patterns (no variation)

#### `attack_class` values observed (when present):
- `"poisoning.targeted_poisoning"` -- T1
- `"genai.indirect_prompt_injection.abuse_violations"` -- T2, T11
- `"genai.indirect_prompt_injection.integrity_violations"` -- T5
- `"genai.direct_prompt_injection.jailbreak"` -- T6-01, T6-02, T6-04
- `"genai.indirect_prompt_injection"` -- T6-03, T6-05
- `"poisoning.backdoor_poisoning"` -- T12
- `"genai.indirect_prompt_injection.privacy_compromises"` -- T15
- `"genai.supply_chain"` -- T17

Not present on: T3, T4, T7, T8, T9, T10, T13, T14, T16 (the agentic-only threats with no NIST attack-class mapping).

#### `kc_requires.all` values (KCX extended capability codes):
- `KCX-PSTATE` -- persistent state (T7-02)
- `KCX-MAGENT` -- multi-agent (T7-03, T9-02, T9-04, T9-06, T14-*, T16-*, T4-02, T13-*, T12-*, T3-03)
- `KCX-PMEM` -- persistent memory (T1-01, T1-03, T5-*, T2-04)
- `KCX-SHMEM` -- shared memory (T1-04)
- `KCX-VSTORE` -- vector store (T2-05)
- `KCX-HITL` -- human in the loop (T10-*)
- `KCX-AUDIT` -- audit trail access (T8-*)
- `KCX-PRIV` -- privilege management (T3-01)
- `KCX-XAUTH` -- cross-boundary auth (T3-02)

### 1.4 Representative examples

**AP-T7-01** (minimal -- no `attack_class`, no `kc_requires.all`):
```yaml
AP-T7-01:
  id: "AP-T7-01"
  threat_id: "T7"
  name: "Constraint bypass via goal-priority conflict"
  description: >
    The agent encounters a situation where satisfying its primary objective
    conflicts with an operational constraint...
  nist_classification:
    attacker_goal: "integrity"
    attacker_knowledge: "black_box"
    learning_stage: "deployment"
  prerequisite_capabilities:
    min_zones: ["input", "reasoning"]
    kc_requires:
      any: [KC1.1, KC1.2, KC1.3, KC1.4]
```

**AP-T1-04** (maximal -- has `attack_class`, has `kc_requires.all`, multi-zone):
```yaml
AP-T1-04:
  id: "AP-T1-04"
  threat_id: "T1"
  name: "Shared memory corruption for cross-agent influence"
  description: >
    An attacker writes false operational data into a memory structure shared
    among multiple agents...
  nist_classification:
    attacker_goal: "integrity"
    attacker_knowledge: "black_box"
    learning_stage: "deployment"
    attack_class: "poisoning.targeted_poisoning"
  prerequisite_capabilities:
    min_zones: ["input", "memory", "inter_agent"]
    kc_requires:
      all: [KCX-SHMEM]
      any: [KC4.4, KC4.6]
```

**AP-T16-03** (complex -- wide `kc_requires.any`, dual `all`):
```yaml
AP-T16-03:
  id: "AP-T16-03"
  threat_id: "T16"
  name: "Tool capability misrepresentation via registry description poisoning"
  description: >
    An attacker embeds misleading, overly broad, or adversarially crafted
    tool descriptions in a shared tool registry...
  nist_classification:
    attacker_goal: "integrity"
    attacker_knowledge: "gray_box"
    learning_stage: "deployment"
  prerequisite_capabilities:
    min_zones: ["input", "reasoning", "inter_agent"]
    kc_requires:
      all: [KC2.3, KCX-MAGENT]
      any: [KC5.1, KC5.2, KC5.3, KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, ...]
```

**AP-T15-02** (human manipulation -- no `kc_requires.all`):
```yaml
AP-T15-02:
  id: "AP-T15-02"
  threat_id: "T15"
  name: "AI-mediated social engineering via deceptive instruction generation"
  description: >
    An attacker compromises an AI assistant's output generation through
    indirect prompt injection, causing it to produce urgent, authoritative
    messages...
  nist_classification:
    attacker_goal: "abuse"
    attacker_knowledge: "black_box"
    learning_stage: "deployment"
    attack_class: "genai.indirect_prompt_injection.privacy_compromises"
  prerequisite_capabilities:
    min_zones: ["input", "reasoning", "tool_execution"]
    kc_requires:
      any: [KC6.1.1, KC6.1.2, KC6.2.1, KC6.2.2, ...]
```

---

## 2. SSSOM Mapping Files

### 2.1 Overview

Five `.sssom.tsv` files, one per attack pattern YAML file. They provide
provenance mappings from each AP-* pattern to LAAF techniques and MITRE
ATLAS techniques.

### 2.2 Columns

| Column | Description |
|--------|-------------|
| `subject_id` | Attack pattern ID (e.g. `AP-T7-01`) |
| `subject_source` | Always `scenario-forge` |
| `predicate_id` | Always `skos:relatedMatch` |
| `object_id` | Technique ID (LAAF: `S1`, `M3`, etc.; ATLAS: `AML.T0054`, etc.) |
| `object_source` | Either `laaf` or `mitre-atlas` |
| `mapping_justification` | Always `semapv:ManualMappingCuration` |

### 2.3 Mapping semantics

Each pattern maps to exactly 2 LAAF techniques and 2+ ATLAS techniques
(via `skos:relatedMatch`). The LAAF techniques describe the injection/delivery
method; the ATLAS techniques describe the attacker TTP.

The original `attack-patterns.sssom.tsv` (T7 only) maps ONLY to LAAF
techniques (no ATLAS IDs). All other files include both LAAF and ATLAS IDs.

### 2.4 Pipeline consumption

Loaded by:
- `load_attack_pattern_provenance()` in `src/scenario_forge/data/loaders.py:216-244`
  - When no path given, globs all `attack-patterns*.sssom.tsv` files and concatenates
- `build_pattern_provenance_index()` in `src/scenario_forge/data/loaders.py:247-274`
  - Builds `{pattern_id: {source: [object_ids]}}` nested index

Used by:
- `expand_seeds()` in `src/scenario_forge/pipeline/seeds.py:141-144`
  - Extracts LAAF IDs (`prov_laaf_ids`) and ATLAS IDs (`prov_atlas_ids`) per pattern
  - LAAF IDs become `ScenarioSeed.laaf_technique_ids` (used as fallback technique pool)
  - ATLAS provenance IDs become `ScenarioSeed.atlas_provenance_ids` (filtered against zone-3 gating)

---

## 3. Cross-Taxonomy Mappings

File: `data/taxonomies/mappings/cross-taxonomy-mappings.yaml`

### 3.1 Sections

| Section | What it maps | Direction | Used by pipeline |
|---------|-------------|-----------|-----------------|
| `t_to_asi` | T1-T17 -> ASI01-ASI10 | Forward | YES (threat surface) |
| `t_to_llm` | T1-T17 -> LLM01-LLM10 | Forward | YES (threat surface, reversed) |
| `asi_to_llm` | ASI01-ASI10 -> LLM01-LLM10 | Forward | NO (reference only) |
| `llm_to_asi` | LLM01-LLM10 -> ASI01-ASI10 | Forward | NO (reference only) |
| `t_to_nist` | T1-T17 -> NIST attack classes | Forward | NO (informational) |
| `t_to_atlas` | T1-T17 -> AML.T* techniques | Forward | YES (threat surface) |
| `t_direct` | T7-T10, T14-T16 -> direct path | Capability-based | YES (threat surface) |
| `agentic_only_threats` | List of agentic-only T-threats | Descriptive | NO (reference only) |
| `gaps` | Coverage gaps between taxonomies | Descriptive | NO (reference only) |

### 3.2 Predicate/confidence model

Each mapping entry has:
- `source` / `target` -- taxonomy IDs
- `predicate` -- one of: `exact_match`, `broad_match`, `narrow_match`, `related_match`, `extends`, `no_match`
- `confidence` -- float 0.0-1.0
- `notes` -- provenance explanation

### 3.3 Pipeline consumption of cross-taxonomy

In `src/scenario_forge/pipeline/threats.py`:

- `_build_llm_to_t_index()` (line 72): reverses `t_to_llm` to get LLM ID -> T-threats
- `_build_t_to_atlas_index()` (line 83): builds T-threat -> ATLAS technique IDs
- `_build_t_to_asi_index()` (line 101): builds T-threat -> ASI IDs
- `_build_direct_t_mappings()` (line 120): extracts `t_direct` entries
- `_resolve_direct_threats()` (line 131): resolves which direct-path threats are in scope

---

## 4. Pipeline Consumption -- Where Each Field Is Used

### 4.1 Loading and parsing

**File:** `src/scenario_forge/data/loaders.py`

- `load_attack_patterns()` (line 174-198):
  - Globs all `attack-patterns*.yaml` files from `data/taxonomies/attack-patterns/`
  - Merges all `patterns` dicts into one flat `dict[str, dict]`
  - Returns raw dicts keyed by pattern ID (e.g. `"AP-T7-01"`)
  - Fields accessed: `patterns` key from YAML

- `build_threat_to_patterns_index()` (line 201-208):
  - Iterates all patterns, builds `{threat_id: [pattern_ids]}` index
  - **Field used: `threat_id`** (line 207)

- `load_attack_pattern_provenance()` (line 216-244):
  - Globs all `attack-patterns*.sssom.tsv`
  - Returns list of `SSSOMMapping` Pydantic models

- `build_pattern_provenance_index()` (line 247-274):
  - Groups SSSOM mappings by pattern ID and source

### 4.2 Threat gating (Stage 2 pre-filter)

**File:** `src/scenario_forge/data/threat_gating.py`

- `determine_threat_scope()` (line 232-315):
  - Loads all attack patterns via `load_attack_patterns()` (line 258)
  - Groups by threat_id via `build_threat_to_patterns_index()` (line 259)
  - For each in-scope threat, loads pattern dicts and calls `_filter_attack_patterns()` (line 281-283)
  - **Fields used: `id`, `threat_id`**

- `_filter_attack_patterns()` (line 185-224):
  - Iterates pattern dicts
  - **Fields used: `id` (line 206), `prerequisite_capabilities` (line 207)**
  - Calls `_evaluate_prerequisite_capabilities()` for each pattern

- `_evaluate_prerequisite_capabilities()` (line 154-182):
  - **Fields used:**
    - `kc_requires.any` (line 175-176) -- checks if profile has at least one
    - `kc_requires.all` (line 177-178) -- checks if profile has all
  - `min_zones` is NO LONGER used (removed in Phase 3, per docstring line 163)

### 4.3 Threat surface determination (Stage 2)

**File:** `src/scenario_forge/pipeline/threats.py`

- `determine_threat_surface()` (line 172-328):
  - Gets in-scope threats from `determine_threat_scope()` which returns `attack_pattern_ids` per threat
  - Collects `attack_pattern_ids` from threat scope entries (line 214-216)
  - Passes them through to `ThreatSurfaceEntry.attack_pattern_ids` (line 282-285)
  - **Attack pattern fields used indirectly: `id`, `threat_id`, `prerequisite_capabilities`**

### 4.4 Seed expansion (Stage 3)

**File:** `src/scenario_forge/pipeline/seeds.py`

- `expand_seeds()` (line 116-254):
  - Loads patterns via `load_attack_patterns()` (line 138)
  - For each AP-ID in `entry.attack_pattern_ids`:
    - Looks up the pattern dict (line 155-156)
    - **Fields directly accessed:**
      - `threat_id` (line 159)
      - `name` (line 164) -> becomes `ScenarioSeed.attack_pattern_name`
      - `description` (line 165) -> becomes `ScenarioSeed.attack_pattern_description`
    - `_extract_seed_constraints()` is called (line 174-176):
      - **Fields accessed:**
        - `min_complexity` (line 94) -- top-level field (currently never present in any pattern)
        - `prerequisite_capabilities` (line 95)
        - `prerequisite_capabilities.kc_requires.all` (line 98) -- maps KCX codes to capability strings

### 4.5 Candidate expansion and filtering (Stage 3.5)

**File:** `src/scenario_forge/pipeline/candidates.py`

- `expand_candidates()` (line 129-278):
  - Uses `ScenarioSeed` fields (populated from attack pattern data):
    - `seed_id` (the AP-* ID)
    - `attack_pattern_name` (from pattern `name`)
    - `attack_pattern_description` (from pattern `description`)
    - `threat_id`, `threat_name`
    - `atlas_technique_ids` / `laaf_technique_ids` (from SSSOM provenance)
    - `required_capabilities` (derived from `kc_requires.all` via `_extract_seed_constraints`)
  - Checks `required_capabilities` against profile (lines 159-189)

- `filter_candidates()` (line 286-449):
  - Groups candidates by `seed_id` (AP-* pattern ID)
  - Renders filter prompt with `attack_pattern_name`, `attack_pattern_description`, `threat_id`, `threat_name`
  - See prompt template analysis below

### 4.6 Scenario generation (Stage 4)

**File:** `src/scenario_forge/pipeline/generate/assembly.py`

The `ScenarioSeed` object (carrying attack pattern data) is passed to all
4 LLM calls. The seed's fields that originate from the attack pattern are:

| Seed field | AP-* source field | Used in which LLM calls |
|------------|-------------------|------------------------|
| `seed_id` | `id` | All calls (scenario_id construction) |
| `attack_pattern_name` | `name` | Call 0, 1, 2, 3 (via prompt templates) |
| `attack_pattern_description` | `description` | Call 0, 1, 2 (via prompt templates) |
| `threat_id` | `threat_id` | Call 2 (tree threat_id validation), validation |
| `threat_name` | from threats YAML via `threat_id` | Call 0, 1, 2, 3 (via prompt templates) |
| `threat_description` | from threats YAML via `threat_id` | Call 0, 1, 2 (via prompt templates) |
| `laaf_technique_ids` | from SSSOM provenance | Fallback technique pool, semantic validation |
| `atlas_provenance_ids` | from SSSOM provenance | Leaf technique provenance check |

#### Prompt template usage of attack pattern fields:

**filter_user.j2:**
- `{{ attack_pattern_name }}` (line 3)
- `{{ attack_pattern_description }}` (line 4)
- `{{ threat_id }}` (line 5)
- `{{ threat_name }}` (line 5)

**call0_user.j2 (Actor Profile):**
- `{{ seed.attack_pattern_name }}` (line 6)
- `{{ seed.attack_pattern_description }}` (line 7)
- `{{ seed.threat_name }}` (line 8)
- `{{ seed.threat_description }}` (line 8)

**call1_user.j2 (Narrative):**
- `{{ seed.attack_pattern_name }}` (line 6)
- `{{ seed.attack_pattern_description }}` (line 7)
- `{{ seed.threat_name }}` (line 8)
- `{{ seed.threat_description }}` (line 8)
- `{{ seed.threat_name }}` (line 24, in taxonomy section)

**call2_user.j2 (Attack Tree):**
- `{{ seed.attack_pattern_name }}` (line 3)
- `{{ seed.attack_pattern_description }}` (line 4)
- `{{ seed.threat_name }}` (line 5)
- `{{ seed.threat_description }}` (line 5)

**call3_user.j2 (Gherkin):**
- `{{ seed.attack_pattern_name }}` (line 10)
- `{{ seed.threat_name }}` (line 11)

### 4.7 Scenario envelope assembly

**File:** `src/scenario_forge/pipeline/generate/assembly.py`, line 237-247

The `scenario_seed_metadata` dict on each envelope captures:
```python
scenario_seed_metadata = {
    "seed_id": seed.seed_id,              # AP-* pattern ID
    "threat_id": seed.threat_id,           # T-threat ID
    "threat_name": seed.threat_name,
    "attack_pattern_name": seed.attack_pattern_name,
    "attack_pattern_description": seed.attack_pattern_description,
    "owasp_origin": seed.owasp_origin,     # from SSSOM
    "laaf_technique_ids": seed.laaf_technique_ids,  # from SSSOM
    "atlas_provenance_ids": seed.atlas_provenance_ids,  # from SSSOM
}
```

### 4.8 Validation (Stage 5)

**File:** `src/scenario_forge/pipeline/validation.py`

Attack pattern fields used in validation:

1. **`threat_id`** -- Semantic validation checks that tree node `threat_id` values
   are in T1-T17 range (line 1590), and that at least one tree node carries the
   scenario's `threat_id` from `scenario_seed_metadata` (line 1418-1432).

2. **`attack_pattern_name`** -- `check_seed_mechanism_fidelity()` (line 2341-2375)
   extracts mechanism keywords from the pattern name and checks they appear in the
   narrative text.

3. **`laaf_technique_ids`** -- Semantic validation rule `seed_technique_provenance`
   (line 1541-1555) checks that at least one LAAF technique from the seed appears
   in the attack tree.

4. **`atlas_provenance_ids`** -- `check_leaf_technique_provenance()` (line 1705-1778)
   checks that at least one leaf node's `technique_id` matches the seed's
   `atlas_provenance_ids`.

---

## 5. Design Constraints

### 5.1 Structurally required fields (pipeline breaks without them)

| Field | Why required | Consumption point |
|-------|-------------|-------------------|
| `id` | Used as the primary key everywhere -- seed_id, scenario_id construction, grouping, dedup | `loaders.py:206`, `seeds.py:155`, `candidates.py:42` |
| `threat_id` | Used to group patterns by threat, match to OWASP threats YAML, build taxonomy chain, validate tree nodes | `loaders.py:207`, `seeds.py:159`, `threats.py:214`, `validation.py:1418` |
| `name` | Passed to all 4 LLM prompt templates as `attack_pattern_name`; used in seed mechanism fidelity validation | `seeds.py:164`, all `call*_user.j2` |
| `description` | Passed to LLM prompts as `attack_pattern_description` for all 4 calls | `seeds.py:165`, all `call*_user.j2` |

### 5.2 Fields used for filtering/matching (pipeline degrades without them)

| Field | Purpose | Consumption point |
|-------|---------|-------------------|
| `prerequisite_capabilities.kc_requires` | Threat gating -- determines which patterns survive for a given profile | `threat_gating.py:171-178` |
| `prerequisite_capabilities.kc_requires.all` | Maps to `required_capabilities` on seeds, used in candidate expansion pre-filter | `seeds.py:95-113`, `candidates.py:159-189` |

### 5.3 Fields passed to LLM prompts (influence generation quality)

| Field | Template(s) | Template variable |
|-------|------------|-------------------|
| `name` | filter_user, call0_user, call1_user, call2_user, call3_user | `attack_pattern_name` / `seed.attack_pattern_name` |
| `description` | filter_user, call0_user, call1_user, call2_user | `attack_pattern_description` / `seed.attack_pattern_description` |

These are the most impactful fields for scenario quality -- the LLM grounds
its actor profile, narrative, attack tree, and Gherkin spec in these descriptions.

### 5.4 Fields that are informational only (NOT consumed by pipeline code)

| Field | Status | Notes |
|-------|--------|-------|
| `nist_classification.attacker_goal` | **UNUSED by pipeline** | Present on every pattern but never read by any Python code or template |
| `nist_classification.attacker_knowledge` | **UNUSED by pipeline** | Same |
| `nist_classification.learning_stage` | **UNUSED by pipeline** | Same (always "deployment") |
| `nist_classification.attack_class` | **UNUSED by pipeline** | Same; optional field, only present on patterns with NIST mapping |
| `prerequisite_capabilities.min_zones` | **UNUSED by pipeline** | Was removed in Phase 3 (per `threat_gating.py` docstring line 163). Present on every pattern but never evaluated. |
| `source` (file-level) | **UNUSED by pipeline** | Metadata header, not loaded |
| `source.version` | **UNUSED by pipeline** | Same |
| `source.derived_from` | **UNUSED by pipeline** | Same |

### 5.5 SSSOM provenance fields (used indirectly via provenance index)

| SSSOM field | Pipeline role |
|-------------|--------------|
| `subject_id` (AP-* ID) | Links provenance to pattern |
| `object_id` (LAAF/ATLAS technique ID) | Populates `laaf_technique_ids` and `atlas_provenance_ids` on seeds |
| `object_source` (`laaf` / `mitre-atlas`) | Determines which seed field to populate |

### 5.6 Naming convention constraints

- Pattern IDs MUST follow `AP-T{N}-{NN}` format (e.g. `AP-T7-01`)
  - The `T{N}` part must match the `threat_id` field value
  - The `{NN}` suffix is a zero-padded sequence number within the threat
  - This convention is relied upon for grouping and display

- `threat_id` MUST be one of `T1` through `T17` (validated in `validation.py:44`)

### 5.7 Hard constraints summary for format adoption/synthesis

1. **MUST have:** `id`, `threat_id`, `name`, `description` -- without these the pipeline crashes.

2. **SHOULD have:** `prerequisite_capabilities.kc_requires` -- without this, patterns are never filtered and may produce scenarios for systems that lack the required capabilities.

3. **NICE TO HAVE but unused:** `nist_classification` (all sub-fields), `prerequisite_capabilities.min_zones` -- present for documentation/provenance but not consumed by any pipeline code.

4. **The `description` field is the most critical for quality** -- it is the primary grounding text passed to the LLM in all 4 generation calls. A weak or vague description produces weak scenarios. The description should be:
   - Domain-agnostic (no specific application references)
   - Mechanism-focused (describes HOW the attack works, not a specific target)
   - 50-100 words (the current norm)

5. **SSSOM provenance is important but separate** -- each pattern needs a companion `.sssom.tsv` entry mapping it to LAAF and/or ATLAS technique IDs. Without these, the pattern's seeds will have empty technique pools and be skipped during candidate expansion.

6. **File naming must match glob patterns:**
   - YAML: `attack-patterns*.yaml` (loaded by `_DEFAULT_ATTACK_PATTERNS_DIR.glob("attack-patterns*.yaml")`)
   - SSSOM: `attack-patterns*.sssom.tsv` (loaded by `_DEFAULT_ATTACK_PATTERNS_DIR.glob("attack-patterns*.sssom.tsv")`)

### 5.8 How technique IDs flow through the pipeline

```
SSSOM provenance (per AP-*)
  |
  v
ScenarioSeed
  .laaf_technique_ids    <- from SSSOM object_source="laaf"
  .atlas_provenance_ids  <- from SSSOM object_source="mitre-atlas" (filtered by zone-3 gating)
  .atlas_technique_ids   <- from ThreatSurfaceEntry (cross-taxonomy t_to_atlas, then gating)
  |
  v
CandidateTriple
  .atlas_technique_ids   <- cross-product of seed.atlas_technique_ids || seed.laaf_technique_ids
  |                         with profile.entry_points
  |
  v
FilteredSeed
  .pinned_technique_ids  <- accepted by LLM candidate filter
  |
  v
Prompt templates (call0-call3)
  technique_context      <- pinned technique names/descriptions from ATLAS_TECHNIQUE_NAMES/DESCRIPTIONS
  |
  v
ScenarioEnvelope
  .attack_tree           <- tree leaf nodes carry technique_id annotations
  .scenario_seed_metadata.laaf_technique_ids    <- for provenance validation
  .scenario_seed_metadata.atlas_provenance_ids  <- for provenance validation
```

The SSSOM provenance provides the technique IDs that seed the candidate
expansion. Without SSSOM entries, a pattern has no techniques to offer the
candidate cross-product, and the pattern's seeds are silently dropped at
`expand_candidates()` (line 229-233 in `candidates.py`).
