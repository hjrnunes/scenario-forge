# Scenario-Forge Data Flow Diagrams

## 1. End-to-End Pipeline Overview

```
                              INPUTS                                    PIPELINE                                   OUTPUTS
                    ============================          ====================================          ============================

                     use-case.txt                          Stage 1: Capability Profiling                 capability-profile.yaml
                     (plain text)           ──────────────►  (1 LLM call)              ──────────────►   zones_active: [1, 2]
                     "A stateless LLM-                       infer_capability_profile()                  has_persistent_memory: false
                      powered chatbot..."                                                                multi_agent: false
                                                                    │                                    entry_points: [...]
                                                                    │ CapabilityProfile
                                                                    ▼
                     risk-extraction.json                   Stage 2: Threat Surface                      threat-surface.yaml
                     (from policy-mapper)   ──────────────►  (deterministic, no LLM)   ──────────────►   entries:
                     [{risk_id, risk_name,                   3-hop taxonomy chain                         - risk_card: {...}
                       confidence, threat,                                                                  owasp_llm_ids: [LLM09]
                       vulnerability...}]                           │                                       agentic_threat_ids: [T7]
                                                                    │ ThreatSurface                         attack_pattern_ids: [AP-T7-01]
                     *.sssom.tsv            ──────┐                 ▼
                     (taxonomy mappings)          │        Stage 3: Scenario Seeds                        (in-memory seeds list)
                                                  ├──────►  (deterministic, no LLM)   ──────────────►   [ScenarioSeed(AP-T7-01),
                     cross-taxonomy-        ──────┘           Expand attack patterns                       ScenarioSeed(AP-T15-01), ...]
                       mappings.yaml                                │
                                                                    │ List[ScenarioSeed]
                     OWASP / ATLAS /                                ▼
                       NIST taxonomies     ──────────────► Stage 4: Scenario Generation                  scenarios/AP-T7-01-f088b5.yaml
                     (reference data)                        (4 LLM calls per seed)    ──────────────►   scenarios/AP-T7-01-f088b5.feature
                                                             x N seeds in parallel                       ... (one pair per seed)
                     attack-goals.json     ──────┐               │
                     threat-goal-           ──────┤   attack goal selection                              run-manifest.yaml
                       affinity.yaml               │   (deterministic, per seed)                           (pipeline metadata)
                                                   │        │
                                                   └────────▼
                                                                    │ List[ScenarioEnvelope]
                                                                    ▼
                                                           Post: Coverage & Eval                         coverage-gaps.json
                                                             (deterministic)           ──────────────►   eval-scorecard.yaml
                                                                    │                                    report.html
                                                                    ▼
                                                                  DONE
```

---

## 2. Input Data Sources

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              INPUT DATA SOURCES                                  │
├────────────────────┬─────────┬───────────────────────────────────────────────────┤
│ Source             │ Format  │ Example Content                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ use-case.txt       │ .txt    │ "A stateless LLM-powered customer service         │
│ (user-provided)    │         │  chatbot for an eBay-like marketplace.            │
│                    │         │  No memory, no tool access, no state."            │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ risk-extraction    │ .json   │ [{"risk_id": "atlas-hallucination",               │
│ (from policy-      │         │   "risk_name": "Hallucination",                   │
│  mapper tool)      │         │   "confidence": 0.809,                            │
│                    │         │   "threat": "AI may generate inaccurate...",      │
│                    │         │   "vulnerability": "Lack of groundedness...",     │
│                    │         │   "consequence": "Untruthful content...",         │
│                    │         │   "impact": "Negative impacts on..."}]            │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ SSSOM mappings     │ .tsv    │ AP-T1-01  scenario-forge  skos:exactMatch         │
│ data/taxonomies/   │         │   T1-S1  owasp-agentic                            │
│  attack-patterns/  │         │ AP-T1-01  scenario-forge  skos:relatedMatch       │
│  *.sssom.tsv       │         │   AML.T0020  mitre-atlas                          │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ Cross-taxonomy     │ .yaml   │ t_to_asi:                                         │
│ mappings           │         │   - source: T1                                    │
│ data/taxonomies/   │         │     target: ASI06                                 │
│  mappings/         │         │     predicate: exact_match                        │
│                    │         │     confidence: 1.0                               │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ OWASP LLM Top 10   │ .json   │ {"id": "LLM01",                                   │
│ data/taxonomies/   │         │  "name": "Prompt Injection",                      │
│  owasp-llm-top10/  │         │  "severity": "Critical",                          │
│  LLM{01-10}.json   │         │  "mappings": [{framework: "MITRE ATLAS",          │
│                    │         │    control_id: "AML.T0051.000"}...]}              │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ OWASP Agentic      │ .yaml   │ threats:                                          │
│ Threats v1.1       │         │   T7:                                             │
│ data/taxonomies/   │         │     name: "Misaligned & Deceptive Behavior"       │
│  owasp-agentic-    │         │     attack_patterns: [AP-T7-01, AP-T7-02, ...]    │
│  threats/          │         │                                                   │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ Attack Patterns    │ .yaml   │ patterns:                                         │
│ data/taxonomies/   │         │   AP-T7-01:                                       │
│  attack-patterns/  │         │     threat_id: T7                                 │
│                    │         │     name: "Constraint bypass via goal-priority    │
│                    │         │           conflict"                               │
│                    │         │     prerequisite_capabilities:                    │
│                    │         │       min_zones: [input, reasoning]               │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ MITRE ATLAS        │ .yaml   │ techniques:                                       │
│ data/taxonomies/   │         │   AML.T0051:                                      │
│  atlas/            │         │     name: "LLM Prompt Injection"                  │
│                    │         │     tactic: "Initial Access"                      │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ NIST AI 100-2      │ .yaml   │ classification_dimensions:                        │
│ data/taxonomies/   │         │   - dimension: attacker_goal                      │
│  nist-ai-100-2/    │         │     values: [integrity, availability,             │
│                    │         │              confidentiality, abuse]              │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ Attack Goals       │ .json   │ categories:                                       │
│ data/taxonomies/   │         │   - id: "availability"                            │
│  attack-goals/     │         │     name: "Availability Disruption"               │
│  attack-goals.json │         │     sub_goals: [{id: "AV-1",                      │
│                    │         │       name: "Service Denial"}, ...]               │
│                    │         │                                                   │
├────────────────────┼─────────┼───────────────────────────────────────────────────┤
│                    │         │                                                   │
│ Threat-Goal        │ .yaml   │ affinities:                                       │
│ Affinity Map       │         │   T1:                                             │
│ data/taxonomies/   │         │     primary: [integrity]                          │
│  attack-goals/     │         │     secondary: [privacy, abuse]                   │
│  threat-goal-      │         │     excluded: [availability]                      │
│  affinity.yaml     │         │                                                   │
│                    │         │                                                   │
└────────────────────┴─────────┴───────────────────────────────────────────────────┘
```

---

## 3. Stage 2: Three-Hop Taxonomy Chain (Deterministic)

```
    risk-extraction.json            SSSOM .tsv files            cross-taxonomy-mappings.yaml
    ┌──────────────────┐         ┌───────────────────┐         ┌───────────────────────┐
    │ risk_id:         │         │ AP-T7-01 ──► T7-S1│         │ T1  ──► ASI06         │
    │  atlas-halluc... │         │ AP-T1-01 ──► T1-S1│         │ T2  ──► ASI02         │
    │ (IBM Risk Atlas) │         │ AP-T1-01 ──► AML. │         │ T7  ──► ASI07         │
    └────────┬─────────┘         │   T0020           │         │ LLM01 ──► AML.T0051   │
             │                   └─────────┬─────────┘         └──────────┬────────────┘
             │                             │                              │
             ▼                             ▼                              ▼
    ┌────────────────────────────────────────────────────────────────────────────────┐
    │                                                                                │
    │   HOP 1: Risk Atlas ID ──────────────────────────► OWASP LLM Top 10 IDs        │
    │          atlas-hallucination                        [LLM09, LLM02]             │
    │          (via SSSOM + risk_card mappings)                                      │
    │                                                         │                      │
    │   HOP 2: OWASP LLM IDs ─────────────────────────► OWASP Agentic Threat IDs     │
    │          [LLM09, LLM02]                            [T15, T7, T8]               │
    │          (via cross-taxonomy-mappings.yaml)                                    │
    │                                                         │                      │
    │   HOP 3: Agentic Threats ────────────────────────► Filtered by Capability      │
    │          [T15, T7, T8]                              Profile zones_active       │
    │          (via threat_gating.py)                     [T15, T7, T8] ✓            │
    │                                                         │                      │
    │   DIRECT PATH (agentic-only threats T7-T10, T14-T16):   │                      │
    │          T-threats ──────────────────────────────► Capability filter only      │
    │          (bypasses LLM hop)                                                    │
    │                                                         │                      │
    │   ATTACK PATTERNS:                                      │                      │
    │          In-scope T-threats ──────────────────────► AP-* IDs resolved          │
    │          (from threat_gating, attack_pattern_ids)   [AP-T7-01, AP-T15-01, ...]│
    │                                                         │                      │
    │   ATLAS TECHNIQUES:                                     │                      │
    │          In-scope T-threats ──────────────────────► ATLAS IDs resolved         │
    │          (via t_to_atlas in cross-taxonomy)         [AML.T0051, AML.T0053, ...]│
    │          Zone-3-gated techniques filtered if                                   │
    │          tool_execution not in zones_active                                    │
    │                                                                                │
    └───────────────────────────────────────────┬────────────────────────────────────┘
                                                │
                                                ▼
                                    threat-surface.yaml
                                    ┌───────────────────────┐
                                    │ entries:              │
                                    │  - risk_card: {...}   │
                                    │    owasp_llm_ids:     │
                                    │      [LLM09, LLM02]   │
                                    │    agentic_threat_ids:│
                                    │      [T15, T7, T8]    │
                                    │    attack_pattern_ids:│
                                    │      [AP-T7-01,       │
                                    │       AP-T15-01, ...] │
                                    │    atlas_technique_ids│
                                    │      [AML.T0051, ...] │
                                    └───────────────────────┘
```

---

## 4. Attack Goal Selection (Deterministic, per Seed)

```
                      attack-goals.json                    threat-goal-affinity.yaml
                      ┌───────────────────────┐            ┌───────────────────────────┐
                      │ categories:           │            │ affinities:               │
                      │   availability:       │            │   T1:                     │
                      │     sub_goals:        │            │     primary: [integrity]  │
                      │       AV-1, AV-2, ... │            │     secondary: [privacy,  │
                      │   integrity:          │            │                 abuse]    │
                      │     sub_goals:        │            │     excluded:             │
                      │       IN-1, IN-2, ... │            │       [availability]      │
                      │   privacy:            │            │   T7:                     │
                      │     sub_goals:        │            │     primary: [integrity,  │
                      │       PR-1, PR-2, ... │            │               abuse]     │
                      │   abuse:              │            │     ...                   │
                      │     sub_goals:        │            └──────────┬────────────────┘
                      │       AB-1, AB-2, ... │                       │
                      └──────────┬────────────┘                       │
                                 │                                    │
                                 ▼                                    ▼
                      ┌────────────────────────────────────────────────────────────────┐
                      │                                                                │
                      │  Step 1: Load all sub-goals                                    │
                      │          get_all_sub_goals(taxonomy)                            │
                      │          Flatten categories -> sub-goals, augmenting each       │
                      │          with category_id, category_name, category_description  │
                      │                                         │                      │
                      │  Step 2: Filter by system capabilities                         │
                      │          filter_sub_goals_by_zones(                             │
                      │            sub_goals, zones_active,                             │
                      │            has_persistent_memory, hitl, multi_agent             │
                      │          )                                                     │
                      │          Zone-gated goals removed:                              │
                      │            AV-5 needs inter_agent                               │
                      │            IN-5 needs persistent memory                         │
                      │            PR-5 needs persistent memory                         │
                      │            AB-7 needs multi_agent                               │
                      │            ...etc (see _GOAL_ZONE_REQUIREMENTS)                 │
                      │                                         │                      │
                      │  Step 3: Per-seed selection (for each seed)                     │
                      │          select_attack_goal(                                    │
                      │            available_goals, usage_counts,                       │
                      │            total_seeds, threat_id                               │
                      │          )                                                     │
                      │                                         │                      │
                      │  Step 3a: Affinity-aware path (when threat_id in affinity map)  │
                      │           Load affinity: primary_cats, excluded_cats            │
                      │           Remove excluded-category goals                        │
                      │           Partition into primary_pool / secondary_pool          │
                      │           Fair-share ceiling = ceil(total_seeds / n_primary)     │
                      │           Pick least-used from primary_pool                     │
                      │           Fallback to secondary_pool when primary exhausted     │
                      │           Fallback to full allowed pool as last resort           │
                      │                                         │                      │
                      │  Step 3b: Affinity-unaware path (fallback)                      │
                      │           _fair_share_pick(sub_goals, usage_counts)             │
                      │           Pick least-used sub-goal, ties broken randomly        │
                      │                                                                │
                      └───────────────────────────────────┬────────────────────────────┘
                                                          │
                                                          ▼
                                               Selected sub-goal dict
                                               ┌─────────────────────────┐
                                               │ id: "IN-3"              │
                                               │ name: "Decision         │
                                               │         Corruption"     │
                                               │ category_id: integrity  │
                                               │ category_name:          │
                                               │   "Integrity Violation" │
                                               │                         │
                                               │  ──► Passed to          │
                                               │      generate_scenario()│
                                               │      as attack_goal=    │
                                               └─────────────────────────┘
```

---

## 5. Stage 4: Per-Seed LLM Generation (4 Calls)

```
  ScenarioSeed (in-memory)            Selected attack goal
  ┌──────────────────────────┐        ┌──────────────────────┐
  │ seed_id: AP-T7-01        │        │ id: IN-3             │
  │ threat_id: T7            │        │ name: Decision       │
  │ attack_pattern_name:     │        │       Corruption     │
  │   "Constraint bypass..." │        │ category_id:         │
  │ risk_card_ref: {...}     │        │   integrity          │
  │ owasp_llm_ids: [LLM09]  │        └─────────┬────────────┘
  │ agentic_threat_ids: [T7] │                  │
  │ atlas_technique_ids: [..]│                  │
  │ owasp_origin: T7-S1      │                  │
  │ laaf_technique_ids: [...] │                  │
  │ atlas_provenance_ids: [..]│                  │
  └────────────┬─────────────┘                  │
               │                                │
    ┌──────────▼────────────────────────────────▼──────────────────────────────────┐
    │                                                                             │
    │  CALL 0: Actor Profile                                                      │
    │  ┌─────────────────────────────────┐    ┌─────────────────────────────────┐ │
    │  │ System: "You are a red-team     │    │ ActorProfile (Pydantic)         │ │
    │  │  persona generator..."          │    │  actor_type: nation-state       │ │
    │  │ User: seed context + threat     │──►│  capability_level: intermediate │ │
    │  │  description + use-case         │    │  beliefs: "..."                 │ │
    │  │  + attack_goal context block    │    │  desires: "..."                 │ │
    │  │  + actor type diversity hints   │    │  intentions: "..."              │ │
    │  │  + ATLAS technique context      │    │  resources: [...]               │ │
    │  │                                 │    │  goal_category: "IN-3"          │ │
    │  │ Structured output (Pydantic)    │    │  goal_category_name: "Decision  │ │
    │  │                                 │    │    Corruption"                  │ │
    │  │                                 │    │  goal_category_parent:          │ │
    │  └─────────────────────────────────┘    │    "Integrity Violation"        │ │
    │                                         └────────────┬────────────────────┘ │
    │                                                      │                      │
    │  CALL 1: Narrative                                   │                      │
    │  ┌─────────────────────────────────┐    ┌────────────▼────────────────────┐ │
    │  │ System: "You are a red-team     │    │ NarrativeLayer (Pydantic)       │ │
    │  │  scenario writer..."            │    │  title: "Subverting Class..."   │ │
    │  │ User: actor_profile +           │──►│  entry_point: "user prompts..."  │ │
    │  │  seed context + zones_active    │    │  zone_sequence: [1, 2]          │ │
    │  │  + entry point diversity hints  │    │  steps:                         │ │
    │  │  + pattern exclusions           │    │   - step: 1, zone: 1,           │ │
    │  │                                 │    │     action: "Craft prompt..."   │ │
    │  │ Structured output (Pydantic)    │    │     control_point: "..."        │ │
    │  └─────────────────────────────────┘    └────────────┬────────────────────┘ │
    │                                                      │                      │
    │  CALL 2: Attack Tree                                 │                      │
    │  ┌─────────────────────────────────┐    ┌────────────▼────────────────────┐ │
    │  │ System: "Produce a YAML         │    │ Raw YAML text ──► AttackTree    │ │
    │  │  attack tree..."                │    │  goal: "Generate deceptive..."  │ │
    │  │ User: narrative steps +         │──►│  root:                           │ │
    │  │  threat IDs + technique IDs     │    │   id: n1, gate: AND             │ │
    │  │  + actor_profile context        │    │   children:                     │ │
    │  │                                 │    │    - id: n1.1, gate: OR         │ │
    │  │ Unstructured text output        │    │      children: [LEAF nodes]     │ │
    │  │ (parsed as YAML post-hoc)       │    │                                 │ │
    │  └─────────────────────────────────┘    └────────────┬────────────────────┘ │
    │                                                      │                      │
    │  CALL 3: Behavior Spec                               │                      │
    │  ┌─────────────────────────────────┐    ┌────────────▼────────────────────┐ │
    │  │ System: "Write a Gherkin        │    │ Raw text (Gherkin)              │ │
    │  │  feature file..."               │    │  @id:AP-T7-01-f088b5            │ │
    │  │ User: narrative + attack_tree   │──►│  Feature: Subverting Class...    │ │
    │  │  summary + use-case             │    │    Background:                  │ │
    │  │                                 │    │      Given access to Zone 1     │ │
    │  │ Unstructured text output        │    │    Scenario:                    │ │
    │  │                                 │    │      When attacker submits...   │ │
    │  └─────────────────────────────────┘    └────────────┬────────────────────┘ │
    │                                                      │                      │
    └──────────────────────────────────────────────────────┼──────────────────────┘
                                                           │
                            ┌──────────────────────────────▼───────────────────┐
                            │          ScenarioEnvelope (assembled)            │
                            │                                                  │
                            │  scenario_id: AP-T7-01-f088b5                    │
                            │  actor_profile: { ... from Call 0 }              │
                            │  narrative: { ... from Call 1 }                  │
                            │  attack_tree: { ... from Call 2 }                │
                            │  behavior_spec: "... from Call 3"                │
                            │  scenario_seed_metadata:                         │
                            │    { seed_id, threat_id, threat_name,            │
                            │      attack_pattern_name,                        │
                            │      attack_pattern_description,                 │
                            │      owasp_origin, laaf_technique_ids,           │
                            │      atlas_provenance_ids }                      │
                            │  faceting: { risk_card, taxonomy_chain,          │
                            │              capability_profile,                 │
                            │              maestro_layers }                    │
                            │  priority: { composite: 0.72, signals: {...} }   │
                            │  generation: { model, call_metadata: [           │
                            │    {call: actor_profile, tokens: 953/323},       │
                            │    {call: narrative, tokens: 2015/642},          │
                            │    {call: attack_tree, tokens: 1143/675},        │
                            │    {call: behavior_spec, tokens: 1488/389}]}     │
                            │                                                  │
                            │  ──► Written to: scenarios/AP-T7-01-f088b5.yaml  │
                            │  ──► Written to: scenarios/AP-T7-01-f088b5       │
                            │                          .feature                │
                            └──────────────────────────────────────────────────┘
```

---

## 6. Complete Data Lineage (File-Level)

```
USER-PROVIDED FILES                    BUNDLED REFERENCE DATA                     GENERATED OUTPUTS
==================                    ======================                     =================

use-case.txt ──────────┐
                       │               data/taxonomies/
                       │               ├─ owasp-agentic-threats/
                       │               │  └─ *-v1.1.yaml ────────────┐
                       │               ├─ owasp-llm-top10/           │
                       │               │  └─ LLM{01-10}.json ────────┤
                       ├──► runner.py  ├─ owasp-agentic-top10/       │
                       │    (pipeline  │  └─ ASI{01-10}.json ────────┤
                       │     orchest.) ├─ atlas/                     ├──► loaders.py
                       │               │  └─ ATLAS-2026.05.yaml ─────┤    (data loading)
risk-extraction.json───┤               ├─ nist-ai-100-2/             │
                       │               │  └─ nist-ai-100-2e2023.yaml─┤
                       │               ├─ attack-patterns/           │
*.sssom.tsv ───────────┤               │  ├─ attack-patterns.yaml ───┤
                       │               │  └─ *.sssom.tsv ────────────┤
                       │               ├─ attack-goals/              │
                       │               │  ├─ attack-goals.json ──────┤
                       │               │  └─ threat-goal-            │
                       │               │     affinity.yaml ──────────┤
                       │               └─ mappings/                  │
                       │                  └─ cross-taxonomy-         │
                       │                     mappings.yaml ──────────┘
                       │
                       │
                       │         PIPELINE STAGES                          OUTPUT DIRECTORY
                       │         ===============                          ================
                       │
                       ├──► Run Manifest (start)  ─────────────────────► output/{name}/
                       │    [write run-manifest.yaml]                     ├─ run-manifest.yaml
                       │                                                  │    (input hashes, model config,
                       ├──► Stage 1 (profile.py) ──────────────────────►  │     prompt template hashes)
                       │    [1 LLM call]                                  ├─ use-case.txt
                       │         │                                        ├─ capability-profile.yaml
                       │         ▼                                        ├─ threat-surface.yaml
                       ├──► Stage 2 (threats.py) ──────────────────────►  ├─ scenarios/
                       │    [deterministic]                               │  ├─ AP-T7-01-f088b5.yaml
                       │         │                                        │  ├─ AP-T7-01-f088b5.feature
                       │         ▼                                        │  ├─ AP-T15-01-16cf51.yaml
                       ├──► Stage 3 (seeds.py) ─────────── (in memory)    │  ├─ AP-T15-01-16cf51.feature
                       │    [deterministic]                               │  ├─ calls.jsonl
                       │         │                                        │  └─ ... (one pair per seed)
                       │         ▼                                        ├─ coverage-gaps.json
                       ├──► Attack Goal Selection ─── (in memory)         ├─ eval-scorecard.yaml
                       │    [deterministic, per seed]                      └─ report.html
                       │         │
                       │         ▼
                       └──► Stage 4 (generate.py) ────────────────────►
                            [4 LLM calls x N seeds]
                                 │
                                 ▼
                            Post-pipeline
                            ├─ coverage.py (deterministic)
                            ├─ eval/runner.py (deterministic)
                            ├─ report/generator.py (deterministic)
                            └─ Run Manifest update (end timestamp, counts)
```

---

## 7. Diversity Enforcement (Batch-Level)

```
  The runner tracks 6 diversity dimensions across the batch via Counters:

  ┌────────────────────────┬──────────────────────────────────────────────────────┐
  │ Dimension              │ Strategy                                             │
  ├────────────────────────┼──────────────────────────────────────────────────────┤
  │ Entry Points           │ assign_entry_point(): affinity score (keyword→zone   │
  │ entry_point_usage      │ Jaccard overlap) - overuse penalty.                  │
  │                        │ get_overused_entry_points() builds exclude list.     │
  ├────────────────────────┼──────────────────────────────────────────────────────┤
  │ Attack Patterns        │ extract_narrative_keywords(): NLP keyword extraction │
  │ pattern_usage          │ from narrative. get_overused_patterns() builds       │
  │                        │ exclude list to avoid repetitive attack techniques.  │
  ├────────────────────────┼──────────────────────────────────────────────────────┤
  │ Structural Patterns    │ extract_structural_pattern(): phase-sequence hash    │
  │ structural_usage       │ (e.g. "inject->hallucinate->persist->bypass").       │
  │                        │ get_overused_structural_patterns() builds excludes.  │
  ├────────────────────────┼──────────────────────────────────────────────────────┤
  │ Actor Types            │ Fair-share ceiling = ceil(total_seeds / num_types).  │
  │ actor_type_usage       │ Least-used type preferred, overused types excluded.  │
  ├────────────────────────┼──────────────────────────────────────────────────────┤
  │ Capability Levels      │ Least-used level preferred (hint, not enforced).     │
  │ capability_level_usage │ 4 levels: novice, intermediate, advanced, expert.    │
  ├────────────────────────┼──────────────────────────────────────────────────────┤
  │ Attack Goals           │ select_attack_goal(): affinity-aware fair-share.     │
  │ goal_usage             │ Primary affinity preferred, secondary fallback,      │
  │                        │ excluded categories removed. See Section 4 above.    │
  └────────────────────────┴──────────────────────────────────────────────────────┘

  All diversity hints are injected into LLM prompts as guidance.
  The LLM may deviate; actual generated values are tracked for
  subsequent seeds.
```

---

## 8. LLM Call Summary

```
┌─────────┬───────────────────────────────┬────────────────────┬──────────────────────────────┐
│ Stage   │ Function                      │ Output Format      │ Typical Tokens (in/out)      │
├─────────┼───────────────────────────────┼────────────────────┼──────────────────────────────┤
│ Stage 1 │ infer_capability_profile()    │ Structured         │ ~500 / ~100                  │
│         │                               │ (Stage1Profile)    │                              │
├─────────┼───────────────────────────────┼────────────────────┼──────────────────────────────┤
│ Stage 4 │ _call_actor_profile()         │ Structured         │ ~950 / ~320                  │
│ Call 0  │                               │ (ActorProfile)     │                              │
├─────────┼───────────────────────────────┼────────────────────┼──────────────────────────────┤
│ Stage 4 │ _call_narrative()             │ Structured         │ ~2000 / ~640                 │
│ Call 1  │                               │ (NarrativeLayer)   │                              │
├─────────┼───────────────────────────────┼────────────────────┼──────────────────────────────┤
│ Stage 4 │ _call_attack_tree()           │ Unstructured       │ ~1140 / ~675                 │
│ Call 2  │                               │ (raw YAML text)    │                              │
├─────────┼───────────────────────────────┼────────────────────┼──────────────────────────────┤
│ Stage 4 │ _call_behavior_spec()         │ Unstructured       │ ~1490 / ~390                 │
│ Call 3  │                               │ (raw Gherkin text) │                              │
├─────────┼───────────────────────────────┼────────────────────┼──────────────────────────────┤
│         │                               │                    │                              │
│ TOTAL   │ 1 + (4 x N seeds)             │                    │ ~6k in + ~2k out per seed    │
│         │ e.g. 10 seeds = 41 calls      │                    │ + ~500 in / ~100 out for S1  │
└─────────┴───────────────────────────────┴────────────────────┴──────────────────────────────┘

LLM Client Config:
  Base URL:  SCENARIO_FORGE_MODEL_BASE_URL  (OpenAI-compatible endpoint)
  API Key:   SCENARIO_FORGE_API_KEY
  Model:     SCENARIO_FORGE_MODEL_NAME      (default: gemma-3n-e4b-it)
  Max Tokens: SCENARIO_FORGE_MAX_COMPLETION_TOKENS (optional)

  Structured calls:   openai.beta.chat.completions.parse(response_format=PydanticModel)
  Unstructured calls:  openai.chat.completions.create() → raw text
```

---

## 9. Schneider 5-Zone Model (Referenced Throughout)

```
                    ┌──────────────────────────────────────────────┐
                    │              AI SYSTEM ZONES                 │
                    │                                              │
                    │   Zone 1: INPUT                              │
                    │   User prompts, API inputs, data uploads     │
                    │                                              │
                    │   Zone 2: REASONING                          │
                    │   LLM planning, inference, decisions         │
                    │                                              │
                    │   Zone 3: TOOL EXECUTION                     │
                    │   External API calls, tool invocations       │
                    │                                              │
                    │   Zone 4: MEMORY                             │
                    │   Session state, persistent storage, KBs     │
                    │                                              │
                    │   Zone 5: INTER-AGENT                        │
                    │   Multi-agent communication, coordination    │
                    │                                              │
                    └──────────────────────────────────────────────┘

The capability profile determines which zones are active (e.g. a
stateless chatbot only has zones [1, 2]). Stage 4 narratives and
attack trees annotate every step/node with its zone. The eval
scorecard checks zone alignment across all layers.
```

---

## 10. Run Manifest

```
  Written at pipeline start; updated at pipeline end.

  run-manifest.yaml (runner.py)
  ┌────────────────────────────────────────────────────────────────────┐
  │ version: "0.1.0"                    # scenario-forge package ver  │
  │ timestamp_start: "2026-07-06T..."   # pipeline start time        │
  │ timestamp_end: "2026-07-06T..."     # pipeline end time (added)  │
  │                                                                    │
  │ inputs:                                                            │
  │   use_case_hash: "sha256:..."       # SHA-256 of use-case.txt    │
  │   risk_extraction_hash: "sha256:..."# SHA-256 of risk-extraction │
  │   sssom_hash: "sha256:..."          # SHA-256 of SSSOM TSV       │
  │                                                                    │
  │ config:                                                            │
  │   model: "gemma-3n-e4b-it"          # LLM model name             │
  │   temperature: 0.7                  # sampling temperature        │
  │   max_completion_tokens: null       # token limit (or null)       │
  │   prompt_template_hashes:           # SHA-256 per template file   │
  │     call0_system.j2: "sha256:..."                                  │
  │     call0_user.j2: "sha256:..."                                    │
  │     call1_system.j2: "sha256:..."                                  │
  │     call1_user.j2: "sha256:..."                                    │
  │     ...                                                            │
  │                                                                    │
  │ seeds_generated: 12                 # total seeds expanded        │
  │ scenarios_generated: 10             # successful scenario count   │
  │ scenarios_failed: 2                 # failed generation count     │
  └────────────────────────────────────────────────────────────────────┘

  Purpose: Reproducibility and provenance. Enables diffing runs by
  comparing input hashes and model configuration.
```

---

## 11. Post-Pipeline Data Flows

```
     All scenario YAMLs                                      coverage-gaps.json
     in output/*/scenarios/                                  ┌──────────────────────────┐
     ┌─────────────────────┐                                 │ coverage_gaps:           │
     │ AP-T7-01-f088b5     │──┐                              │   uncovered_entry_points:│
     │   .yaml             │  │                              │     []                   │
     │ AP-T15-01-16cf51    │  │                              │   uncovered_zones: []     │
     │   .yaml             │  ├──► coverage.py ────────────►│ attacker_diversity:      │
     │ ...                 │  │    (gap analysis)            │   model_counts:          │
     └─────────────────────┘  │                              │     nation-state: 3      │
                              │                              │     insider: 2           │
     capability-profile.yaml──┘                              │   dominant_fraction: 0.3 │
                                                             └──────────────────────────┘

     Coverage Remediation Pass (runner.py):
       If uncovered_entry_points exist after initial generation,
       _remediate_coverage_gaps() runs additional seeds to fill gaps.

     All scenario YAMLs         All .feature files           eval-scorecard.yaml
     ┌─────────────────────┐    ┌────────────────────┐       ┌──────────────────────────┐
     │ (narratives,        │    │ AP-T7-01-f088b5    │       │ evaluation:              │
     │  attack_trees,      │──┐ │  .feature          │──┐    │   scenario_count: 10     │
     │  zone_sequences)    │  │ │ AP-T15-01-16cf51   │  │    │   consistency:           │
     └─────────────────────┘  │ │  .feature          │  │    │     mean: 0.9556         │
                              ├─┤ ...                │  ├──►│   gherkin:                │
     capability-profile.yaml──┘ └────────────────────┘  │    │     parse_success: 1.0   │
                                                        │    └──────────────────────────┘
                              eval/runner.py ───────────┘
                              ├─ consistency.py (zone alignment, step<->node match)
                              ├─ diversity.py (attacker type spread)
                              ├─ gherkin.py (parse validation)
                              ├─ grounding.py (taxonomy grounding)
                              └─ plausibility.py (structural plausibility)
```

---

## 12. Report Generation Data Flow

```
  report/generator.py: generate_report(output_dir)

  Reads these artifacts from disk:
  ┌──────────────────────────┐
  │ capability-profile.yaml  │──┐
  │ threat-surface.yaml      │──┤
  │ scenarios/*.yaml         │──┤
  │ scenarios/*.feature      │──┤   generator.py
  │ scenarios/calls.jsonl    │──┼──► (loads all,     ──► build_full_page()
  │ coverage-gaps.json       │──┤    sorts by           ──► report.html
  │ eval-scorecard.yaml      │──┤    priority)
  │ use-case.txt             │──┘
  └──────────────────────────┘

  Passes to template.py section builders:
  ┌──────────────────────────────────────────────────────────────────────┐
  │ build_use_case_section(use_case_text)                               │
  │ build_capability_profile_section(profile_data)                      │
  │ build_threat_surface_section(ts_data)                               │
  │ build_coverage_section(coverage_data)                               │
  │ build_threat_technique_section(scenarios)                           │
  │ build_attacker_diversity_section(scenarios)                         │
  │ build_scenarios_section(                                            │
  │     scenarios, feature_files, call_logs,                            │
  │     threat_surface=ts_data,           <── NEW: provenance chain     │
  │     capability_profile=profile_data   <── NEW: provenance chain     │
  │ )                                                                   │
  │ build_scorecard_section(scorecard_data)                             │
  │ build_raw_data_section(raw_files)                                   │
  │ build_glossary_section()                                            │
  └──────────────────────────────────────────────────────────────────────┘

  build_full_page() assembles the single-page HTML report with:
  ┌──────────────────────────────────────────────────────────────────────┐
  │ Sidebar navigation (auto-hides empty sections)                      │
  │ Sections:                                                           │
  │   1. Use Case description                                          │
  │   2. Capability Profile                                            │
  │   3. Threat Surface (Sankey diagram)                                │
  │   4. Coverage Analysis                                             │
  │   5. Threat-Technique Matrix                                       │
  │   6. Actor Profiles (diversity chart)                               │
  │   7. Scenarios (main section, see below)                            │
  │   8. Eval Scorecard                                                │
  │   9. Raw Data (YAML/JSON source browser)                            │
  │  10. Glossary                                                       │
  └──────────────────────────────────────────────────────────────────────┘


  Scenarios section structure (build_scenarios_section):
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  DASHBOARD HEADER                                                    │
  │  ┌────────────────────────────────────────────────────────────────┐  │
  │  │ Priority donut chart (HIGH / MEDIUM / LOW counts)             │  │
  │  │ Total scenarios, high/medium/low breakdown                    │  │
  │  └────────────────────────────────────────────────────────────────┘  │
  │                                                                      │
  │  COVERAGE HEATMAP                                                    │
  │  ┌────────────────────────────────────────────────────────────────┐  │
  │  │ Threat (rows) x Zone (columns) matrix                         │  │
  │  │ Cell color intensity = scenario count                         │  │
  │  │ Coverage gap percentage displayed                             │  │
  │  └────────────────────────────────────────────────────────────────┘  │
  │                                                                      │
  │  CHIP FILTERS                                                        │
  │  ┌────────────────────────────────────────────────────────────────┐  │
  │  │ Threat ID chips (toggle to filter cards)                      │  │
  │  │ Zone chips (toggle to filter cards)                           │  │
  │  │ Priority chips: HIGH / MEDIUM / LOW (toggle to filter)        │  │
  │  └────────────────────────────────────────────────────────────────┘  │
  │                                                                      │
  │  SCENARIO CARDS (one per scenario, collapsible)                      │
  │  ┌────────────────────────────────────────────────────────────────┐  │
  │  │ Header: [collapse] scenario_id | title | score bar | priority │  │
  │  │ data-threats, data-zones, data-priority attrs for JS filter   │  │
  │  │                                                                │  │
  │  │ 9 Tabs (CSS-only radio button tabs):                           │  │
  │  │  1. Provenance  (8-step derivation chain, see below)          │  │
  │  │  2. Generation Inputs  (per-call grouped sub-tables)          │  │
  │  │  3. Actor Profile  (BDI: beliefs/desires/intentions)          │  │
  │  │  4. ATLAS Techniques  (Gherkin-grounded technique cards)      │  │
  │  │  5. Narrative  (summary + entry point + zone breadcrumb)      │  │
  │  │  6. Attack Tree  (recursive AND/OR tree rendering)            │  │
  │  │  7. Behavior Spec  (syntax-highlighted Gherkin)               │  │
  │  │  8. Priority Signals  (composite score breakdown)             │  │
  │  │  9. LLM Calls  (expandable prompt/response log)               │  │
  │  └────────────────────────────────────────────────────────────────┘  │
  │                                                                      │
  └──────────────────────────────────────────────────────────────────────┘
```

---

## 13. Provenance Chain (8-Step Derivation)

```
  _build_provenance_chain(scenario, threat_surface, capability_profile)

  Displayed as Tab 1 in each scenario card. Shows how deterministic
  pipeline inputs flowed into this specific scenario.

  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  Step 1: Risk Card                                                   │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ Risk ID:    atlas-hallucination                              │    │
  │  │ Risk Name:  Hallucination                                    │    │
  │  │ Taxonomy:   IBM Risk Atlas                                   │    │
  │  │ Confidence: 0.81                                             │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 2: OWASP LLM IDs (SSSOM Mapping)                              │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ [LLM09] [LLM02]         (badges with tooltip names)         │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 3: Agentic Threats (surviving)                                 │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ [T7 - Misaligned & Deceptive Behavior]                      │    │
  │  │ [T15 - ...]             (badges with tooltip descriptions)   │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 4: Attack Pattern                                              │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ Seed ID: AP-T7-01                                            │    │
  │  │ Name:    Constraint bypass via goal-priority conflict        │    │
  │  │ Description: (truncated to 300 chars)                        │    │
  │  │ Threat:  T7 - Misaligned & Deceptive Behavior                │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 5: Attack Goal                                                 │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ Goal: IN-3 Decision Corruption                               │    │
  │  │ Category: Integrity Violation                                │    │
  │  │ ┌────────────────────────────────────────────────────────┐   │    │
  │  │ │ T7 affinity: primary: [integrity, abuse]              │   │    │
  │  │ │              secondary: [privacy, availability]       │   │    │
  │  │ │              excluded: []                              │   │    │
  │  │ └────────────────────────────────────────────────────────┘   │    │
  │  │ Sub-goal grid: all goals with tier highlights + selection    │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 6: ATLAS Techniques                                            │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ [AML.T0051 - LLM Prompt Injection]                          │    │
  │  │ [AML.T0053 - AI Agent Tool Invocation]                      │    │
  │  │ (badges with tooltip descriptions)                           │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 7: Entry Point                                                 │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ "User chat input"       (from narrative.entry_point)         │    │
  │  └──────────────────────────┬───────────────────────────────────┘    │
  │                             ▼                                        │
  │  Step 8: Zone Sequence                                               │
  │  ┌──────────────────────────────────────────────────────────────┐    │
  │  │ [input] → [reasoning]   (color-coded zone breadcrumb)        │    │
  │  └──────────────────────────────────────────────────────────────┘    │
  │                                                                      │
  └──────────────────────────────────────────────────────────────────────┘

  Data sources for each step:
    Steps 1-3:  faceting.risk_card, faceting.taxonomy_chain
    Step 4:     scenario_seed_metadata (seed_id, attack_pattern_name, etc.)
    Step 5:     actor_profile (goal_category, goal_category_name,
                goal_category_parent) + live taxonomy/affinity data
    Step 6:     faceting.taxonomy_chain.atlas_technique_ids
    Step 7:     narrative.entry_point
    Step 8:     faceting.capability_profile.zones_traversed
```
