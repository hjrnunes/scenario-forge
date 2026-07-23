# Attack Pattern Format Comparison and Synthesis

Critical comparison of MITRE ATLAS case study format (v6, 2026.06) and
scenario-forge abstract attack pattern format, with synthesis proposals.

---

## 1. Structural Comparison

### 1.1 Top-Level Organization

**ATLAS v6** has five major sections:

| Section | Purpose |
|---|---|
| `tactics` (16 entries, AML.TA0000-TA0015) | Kill chain phases: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Defense Evasion, Discovery, Collection, Exfiltration, Impact, Privilege Escalation, Credential Access, Command & Control, Lateral Movement, plus AI-specific Model Access and Attack Staging |
| `techniques` (~100+, AML.T0000-T01xx) | Specific attacker methods, organized under tactics, with sub-techniques (e.g. AML.T0051.001) |
| `mitigations` | Defensive measures mapped to techniques |
| `case-studies` (63, AML.CS0000-CS0062) | Documented incidents and exercises |
| `relationships` | Step-by-step kill chains linking case studies to techniques via ordered `employs` relationships |

**Scenario-forge** has a flat structure across 5 YAML files:

| Element | Purpose |
|---|---|
| `source` | Provenance metadata (version, derived_from) |
| `patterns` (66 entries, AP-T1-01 through AP-T17-02) | Abstract attack mechanism descriptions |
| SSSOM TSV files (5 sidecar files) | External provenance mappings to LAAF and ATLAS |

### 1.2 What Each Captures That the Other Does Not

**ATLAS captures, scenario-forge does not:**

- **Kill chain ordering.** Each case study decomposes into numbered steps (S00, S01, ..., Snn) linked by `leads-to` pointers. CS0045 (MCP data exfiltration via Cursor) has 11 steps spanning 7 different tactics. This is the single most important structural difference.
- **Tactic assignment per step.** Each step maps to both a technique AND a tactic, making it possible to see where in the kill chain a technique appears.
- **Real-world evidence.** Actor names, dates, references, CVEs, reporter attribution.
- **Case study type classification.** `Exercise` vs `Incident` -- distinguishing demonstrated proofs-of-concept from actual attacks.
- **Technique maturity.** Each technique has a `maturity` field (`Demonstrated`, `Feasible`).
- **Platform applicability.** Techniques specify platforms (Enterprise, Mobile, etc.).
- **ATT&CK cross-references.** Direct links from ATLAS tactics/techniques to MITRE ATT&CK IDs.

**Scenario-forge captures, ATLAS does not:**

- **Prerequisite capabilities.** `min_zones` (input, reasoning, tool_execution, memory, inter_agent) and `kc_requires` (KC1.1, KC6.2.2, KCX-MAGENT, etc.) enable deterministic filtering against a capability profile.
- **NIST attack classification.** `attacker_goal` (integrity, availability, abuse), `attacker_knowledge` (black_box, gray_box, white_box), `learning_stage` (deployment), and optionally `attack_class` (genai.indirect_prompt_injection.abuse_violations, etc.).
- **Domain-agnostic mechanism descriptions.** Abstract enough to instantiate against any agentic use case -- a bank, a healthcare system, a coding assistant -- without modification.
- **Threat category grouping.** Direct binding to OWASP agentic threat IDs (T1-T17), which drives the pipeline's threat surface mapping.
- **SSSOM provenance.** Standardized semantic mappings to LAAF techniques and ATLAS technique IDs, enabling multi-taxonomy interoperability.

### 1.3 Abstraction Level

This is the core difference. The two formats sit at different levels of the abstraction stack:

```
                    ATLAS
                    -----
Level 4:  Case Studies    (concrete: "ChatGPT memory poisoned via Google Docs")
Level 3:  Techniques      (semi-abstract: "Indirect Prompt Injection via Integration")
Level 2:  Tactics         (abstract: "Execution", "Persistence")

              Scenario-Forge
              ---------------
Level 3.5: Attack Patterns  (abstract mechanism: "Persistent memory rule injection")
Level 2.5: Threat IDs       (category: "T1 - Memory Poisoning")
```

ATLAS techniques (Level 3) are the closest analog to scenario-forge attack patterns (Level 3.5), but they differ in purpose: ATLAS techniques describe *what the attacker does* (verb-centric), while scenario-forge patterns describe *what goes wrong and why* (mechanism-centric). For example:

- ATLAS technique AML.T0080.000: "Poison AI Agent Memory" -- a concrete action.
- Scenario-forge AP-T1-01: "Persistent memory rule injection" -- an abstract mechanism that explains *how* and *why* memory poisoning leads to a security failure (the agent treats fabricated rules as authoritative, overriding validation logic).

The scenario-forge level is better suited for synthetic scenario generation because it provides enough mechanistic detail to seed LLM generation while remaining abstract enough to instantiate across domains.

### 1.4 Kill Chain Handling

**ATLAS** has a full directed-graph kill chain model per case study:

```yaml
# CS0040: Hacking ChatGPT's Memories
relationships:
  AML.CS0040:
    employs:
    - target: AML.T0065          # Craft Adversarial Input
      tactic: AML.TA0003         # Resource Development
      step-id: S00
      leads-to: [S01]
    - target: AML.T0068          # Prompt Obfuscation
      tactic: AML.TA0007         # Defense Evasion
      step-id: S01
      leads-to: [S02]
    - target: AML.T0093          # Deliver Via Connected App
      tactic: AML.TA0004         # Initial Access
      step-id: S02
      leads-to: [S03]
    - target: AML.T0051.001      # Indirect Prompt Injection
      tactic: AML.TA0005         # Execution
      step-id: S03
      leads-to: [S04]
    - target: AML.T0080.000      # Poison AI Agent Memory
      tactic: AML.TA0006         # Persistence
      step-id: S04
      leads-to: [S05]
    - target: AML.T0093          # Persistence via Shared Doc
      tactic: AML.TA0006         # Persistence
      step-id: S05
      leads-to: [S06]
    - target: AML.T0048.003      # Harm to Downstream Entity
      tactic: AML.TA0011         # Impact
      step-id: S06
      leads-to: []
```

This is a rich representation: 7 steps, 5 different tactics, branching possible via `leads-to` lists, and each step has its own descriptive text explaining the step's specifics.

**Scenario-forge** has no kill chain model. Each pattern is a flat, self-contained mechanism description. The SSSOM files map each pattern to 2-3 ATLAS technique IDs, but these are *associative* mappings, not *sequential* ones. There is no ordering, no tactic assignment, no step graph.

The pipeline compensates for this at generation time: Stage 4 Call 2 asks the LLM to produce an attack tree (a YAML tree of nodes), which functions as a de facto kill chain. But this kill chain is invented per-scenario by the LLM, not structurally constrained by the seed.

### 1.5 Technique References

**ATLAS** techniques are first-class objects with full definitions (name, description, platform, maturity, sub-techniques). Case studies reference them by ID in the relationships section.

**Scenario-forge** patterns reference ATLAS technique IDs only via SSSOM sidecar files, using `skos:relatedMatch` predicates. These are loose associations ("this pattern is related to this ATLAS technique"), not structural bindings. The pipeline also receives ATLAS technique IDs through the risk extraction -> SSSOM -> threat surface pathway, where they're filtered against the capability profile in Stage 3.5.

### 1.6 Attacker Characterization

**ATLAS** case studies have:
- `actor`: Named entity (APT28, Embrace the Red, HiddenLayer)
- `type`: Exercise or Incident
- `target`: Named system (ChatGPT, Claude Computer Use, Cursor)
- `date` and `date-granularity`

These are concrete, historical facts -- useful for evidence but not for scenario generation.

**Scenario-forge** patterns have:
- `attacker_goal`: CIA-triad-like classification (integrity, availability, abuse)
- `attacker_knowledge`: Access model (black_box, gray_box, white_box)
- `learning_stage`: Pipeline phase (all currently `deployment`)

These are abstract taxonomic properties -- useful for filtering and characterization but missing the narrative richness of real attacker profiles.

### 1.7 Provenance and Evidence

**ATLAS**: Every case study has references (URLs, paper citations, CVE IDs). Each step in the relationship graph has a prose description explaining exactly what happened. This is forensic-grade provenance.

**Scenario-forge**: The `source` block declares derivation from OWASP and NIST. SSSOM files provide standardized semantic mappings. But individual patterns have no references, no evidence, no citations. The provenance is taxonomic ("this pattern is related to AML.T0053") rather than evidentiary ("this pattern was observed in incident X").

---

## 2. Strengths and Weaknesses

### 2.1 ATLAS

**Strengths:**

1. **Kill chain richness.** The step-ordered relationship model is the gold standard for representing multi-phase attacks. CS0041 (Rules File Backdoor) has 10 steps across 6 tactics -- this is exactly the kind of sequential detail that scenario-forge's Stage 4 tries to generate from scratch.

2. **Evidence-backed.** Every case study is grounded in real-world or demonstrated attacks. CS0042 (SesameOp) is an actual incident with a Microsoft DART report; CS0053 (Poisoned Postmark MCP) is a real supply chain compromise. This grounds the taxonomy in reality.

3. **Growing agentic coverage.** CS0040-CS0062 are heavily agentic: MCP attacks, computer-use exploitation, agent memory poisoning, coding assistant supply chain attacks, agent C2 channels. ATLAS is actively tracking the threat landscape scenario-forge cares about.

4. **Industry standard.** ATLAS is the de facto standard for AI/ML threat classification. Referencing ATLAS IDs gives scenario-forge outputs external credibility and interoperability.

5. **Technique-tactic binding.** The same technique can appear under different tactics in different case studies (e.g. AML.T0093 appears as both Initial Access and Persistence in CS0040). This captures the reality that techniques serve different tactical purposes in different contexts.

**Weaknesses for scenario generation:**

1. **Concrete, not generative.** Case studies describe what happened in a specific incident to a specific system. "The researcher hid the prompt in a Google Doc" is not useful as a seed for generating a scenario about a healthcare agent. The abstraction work of stripping domain details must happen somewhere.

2. **No prerequisite model.** ATLAS has no analog to `min_zones` or `kc_requires`. It cannot answer "does this attack apply to an agent without persistent memory?" -- a question the pipeline must answer in Stage 3.5.

3. **No NIST classification.** No attacker_goal/knowledge/learning_stage classification. No mapping to the NIST AI 100-2e2023 taxonomy.

4. **Kill chains are instance-specific.** Each kill chain is bound to a specific case study. There is no way to extract a reusable "kill chain template" from CS0040 and apply it to a different agent with different capabilities. The kill chain is evidence, not a pattern.

5. **Sparse agentic coverage relative to the space.** 23 agentic case studies (CS0040-CS0062) vs 66 scenario-forge patterns. ATLAS covers the attacks that have actually been demonstrated; scenario-forge covers the attacks that are theoretically possible. For forward-looking threat modeling, the latter matters more.

6. **No applicability filtering.** ATLAS cannot tell you which case studies are relevant to a specific use case's capability profile. Every case study is either relevant or it isn't, based on human judgment.

### 2.2 Scenario-Forge

**Strengths:**

1. **Domain-agnostic abstraction.** AP-T2-02 ("Multi-tool chain exploitation for data exfiltration") can seed scenarios for a financial agent, a healthcare agent, or a coding assistant with equal effectiveness. The mechanism is abstract enough to be universally applicable while specific enough to be mechanistically coherent.

2. **Prerequisite model enables deterministic filtering.** The `min_zones` + `kc_requires` structure lets the pipeline reject impossible seeds before LLM generation. An agent without persistent memory will never see T1 patterns. This is the killer feature for pipeline integration.

3. **Multi-taxonomy provenance via SSSOM.** Patterns map to LAAF, ATLAS, and OWASP via standardized semantic mappings. This is cleaner and more maintainable than embedding cross-references inline.

4. **NIST classification is useful but underexploited.** The attacker_goal/knowledge/stage fields are currently used only as metadata. They could drive generation parameters (e.g. black_box attacks should not assume the attacker knows model internals).

5. **Comprehensive coverage of the threat space.** 66 patterns across 17 threat categories cover the full OWASP agentic threat landscape, including threats that have no real-world case studies yet (T10 overwhelming HITL, T16 insecure inter-agent protocols).

**Weaknesses:**

1. **No sequential structure.** Each pattern is a flat description. There is no notion of steps, phases, or ordering. The LLM must invent the entire attack sequence during scenario generation (Call 2: attack tree). This means the format provides no structural constraints on kill chain plausibility.

2. **No technique-tactic binding.** The SSSOM mappings to ATLAS techniques are associative, not positional. AP-T1-01 maps to AML.T0070 and AML.T0043, but the pipeline has no way to know that T0070 serves a different tactical purpose than T0043 in the context of this pattern.

3. **Descriptions are mechanistic but not operational.** AP-T8-02 says "An attacker designs interactions that cause the agent to take security-relevant actions while producing minimal or obscured log entries" -- but it does not describe HOW the attacker achieves this in practice. It is a mechanism description, not an attack playbook. This is by design (domain-agnostic), but it means the LLM has less to work with.

4. **Missing evidence linkage.** No pattern has citations, references, or links to real-world demonstrations. When a pattern is grounded in a real ATLAS case study (e.g. AP-T1-01 is essentially CS0040), this connection is implicit, not explicit.

5. **Static NIST classification is limiting.** Every pattern is `learning_stage: deployment`. The attacker_knowledge field is set per-pattern but the same mechanism can be exploited with different knowledge levels. The classification is too static for a generative system.

6. **Flat threat_id is coarser than a kill chain.** A pattern belongs to exactly one threat category (T1, T7, etc.). Real attacks span multiple threat categories -- a memory poisoning attack (T1) that leads to tool misuse (T2) that achieves privilege escalation (T3). The flat model cannot represent this.

---

## 3. Synthesis Proposals

### 3.1 Option A: Minimal Adaptation (Conservative)

**Approach:** Keep the current scenario-forge format. Add optional fields inspired by ATLAS to enrich patterns without restructuring.

**Format example:**

```yaml
patterns:
  AP-T1-01:
    id: "AP-T1-01"
    threat_id: "T1"
    name: "Persistent memory rule injection"
    description: >
      An attacker repeatedly reinforces a false operational rule in the agent's
      persistent memory until the agent treats it as established fact. Once
      embedded, the fabricated rule overrides legitimate validation logic,
      causing the agent to authorize actions that violate its actual constraints.

    # --- Existing fields (unchanged) ---
    nist_classification:
      attacker_goal: "integrity"
      attacker_knowledge: "black_box"
      learning_stage: "deployment"
      attack_class: "poisoning.targeted_poisoning"
    prerequisite_capabilities:
      min_zones: ["input", "memory"]
      kc_requires:
        all: [KCX-PMEM]
        any: [KC4.3, KC4.4, KC4.5, KC4.6]

    # --- New optional fields ---
    tactic_phases:
      - AML.TA0004    # Initial Access
      - AML.TA0006    # Persistence
      - AML.TA0011    # Impact
    atlas_case_study_refs:
      - id: AML.CS0040
        relevance: "direct"
        note: "ChatGPT memory poisoning via Google Docs demonstrates this exact mechanism"
    operational_steps_hint:
      - "Attacker crafts payload containing false operational rules"
      - "Payload is delivered via an input channel the agent trusts"
      - "Agent stores the fabricated rule in persistent memory"
      - "In subsequent sessions, agent treats the rule as authoritative"
      - "Agent authorizes actions that violate its actual constraints"
```

**Pipeline changes needed:**

- `seeds.py`: Extract `tactic_phases` and `operational_steps_hint` into ScenarioSeed fields.
- Stage 4 templates (Call 1/Call 2): Provide tactic_phases as a structural constraint ("the attack should traverse these phases") and steps_hint as initial scaffolding for the attack tree.
- No changes to Stage 3.5 filtering (prerequisite_capabilities unchanged).
- SSSOM files remain the source of truth for ATLAS technique mappings.

**Pros:**
- Zero disruption to existing pipeline, data loading, or SSSOM infrastructure.
- New fields are additive and optional -- patterns without them still work.
- Case study refs provide evidence linkage without importing the full ATLAS structure.
- Tactic phases hint guides generation quality without over-constraining.

**Cons:**
- `tactic_phases` is just a list, not a graph. No `leads-to` ordering. Weaker than ATLAS's step model.
- `operational_steps_hint` is free text. Not machine-interpretable for validation.
- Still no first-class representation of multi-technique kill chains.
- Evidence linkage is manually curated per pattern -- does not scale.

**Migration effort:** Low. Add fields to patterns incrementally. No schema changes required. Estimated: 2-3 days for tooling, 2-3 days for curating new fields across 66 patterns.

---

### 3.2 Option B: Hybrid Model (Moderate)

**Approach:** Create a new format that adds a structured kill chain template to each attack pattern, drawing on ATLAS's relationship model but keeping it abstract and reusable. The pattern becomes a composable attack building block with defined entry/exit points.

**Format example:**

```yaml
patterns:
  AP-T1-01:
    id: "AP-T1-01"
    threat_id: "T1"
    name: "Persistent memory rule injection"
    description: >
      An attacker repeatedly reinforces a false operational rule in the agent's
      persistent memory until the agent treats it as established fact.

    # --- Prerequisite model (unchanged, this is the crown jewel) ---
    prerequisite_capabilities:
      min_zones: ["input", "memory"]
      kc_requires:
        all: [KCX-PMEM]
        any: [KC4.3, KC4.4, KC4.5, KC4.6]

    # --- Attacker characterization (expanded) ---
    attacker_profile:
      goal: "integrity"
      knowledge: "black_box"
      min_complexity: null
      nist_attack_class: "poisoning.targeted_poisoning"

    # --- Structured kill chain template ---
    kill_chain:
      - step: setup
        tactic: AML.TA0003         # Resource Development
        techniques: [AML.T0065]     # Craft Adversarial Input
        abstract_action: >
          Craft payload containing false operational rules or policies
          that the agent's memory system will accept as legitimate.
      - step: delivery
        tactic: AML.TA0004         # Initial Access
        techniques: [AML.T0051.000, AML.T0051.001]
        abstract_action: >
          Deliver payload through a trusted input channel -- direct prompt,
          connected application, or poisoned data source.
      - step: persistence
        tactic: AML.TA0006         # Persistence
        techniques: [AML.T0080.000]
        abstract_action: >
          Agent stores the fabricated rule in persistent memory,
          establishing persistence across sessions.
      - step: activation
        tactic: AML.TA0005         # Execution
        techniques: []
        abstract_action: >
          In a subsequent session, agent retrieves the poisoned memory
          and treats the fabricated rule as authoritative context.
      - step: impact
        tactic: AML.TA0011         # Impact
        techniques: [AML.T0048]
        abstract_action: >
          Agent authorizes actions that violate its actual constraints,
          causing integrity violation in downstream operations.

    # --- Composability ---
    chains_with:
      - pattern: "AP-T2-04"
        relationship: "enables"
        note: "Poisoned memory can drive tool misuse in subsequent sessions"
      - pattern: "AP-T5-01"
        relationship: "amplifies"
        note: "Fabricated data compounds via hallucination amplification"

    # --- Evidence ---
    evidence:
      - source: "AML.CS0040"
        type: "direct_demonstration"
      - source: "AML.CS0051"
        type: "variant"
```

**Pipeline changes needed:**

- **Data model:** New `KillChainStep` and `PatternEvidence` models. `ScenarioSeed` gains `kill_chain` and `chains_with` fields.
- **Stage 3 (seeds.py):** Extract kill chain steps into the seed. When `--max-scenario-techniques 2`, `chains_with` enables seed pairs that are structurally composable, not just randomly combined.
- **Stage 3.5 (candidates.py):** Filter techniques in the kill chain against the capability profile's zone coverage. If the profile lacks `memory` zone, reject patterns with memory-dependent persistence steps.
- **Stage 4 templates:** Call 2 (attack tree) receives the kill chain template as a structural scaffold. The LLM fills in domain-specific details rather than inventing the entire sequence. This should improve attack tree quality substantially.
- **Eval:** New consistency metric: does the generated attack tree align with the seed's kill chain template?
- **SSSOM files:** Can be retired or demoted. The kill chain embeds technique references inline with tactic context, which is strictly richer than flat SSSOM associations.

**Pros:**
- Kill chain templates bring ATLAS's structural richness to an abstract, reusable format.
- `chains_with` enables principled multi-pattern composition (vs. the current random pairing).
- Technique references carry tactic context -- the pipeline knows AML.T0051.001 is being used for Execution, not Persistence.
- `abstract_action` per step gives the LLM a structural skeleton while preserving domain-agnosticism.
- Evidence linkage is explicit and typed.

**Cons:**
- Significant schema change. All 66 patterns need kill chain templates.
- Kill chain templates are subjective -- the same mechanism can be executed through different tactical phases. Curating 66 templates is substantial work.
- Risk of over-constraining generation. A rigid kill chain template might prevent the LLM from discovering novel attack paths.
- `chains_with` relationships form a graph that needs careful curation to avoid explosion.

**Migration effort:** Medium-high. New data model and loader (1 week). Template refactoring for Stage 4 (1 week). Curating kill chains for 66 patterns (2-3 weeks, can be LLM-assisted with ATLAS case studies as examples). Total: 4-5 weeks.

---

### 3.3 Option C: ATLAS-Native (Ambitious)

**Approach:** Adopt the ATLAS v6 format as the primary representation. Encode scenario-forge's abstract patterns as synthetic "case studies" with relationship graphs, and extend the ATLAS schema with prerequisite fields.

**Format example:**

```yaml
# Extends ATLAS v6 format with scenario-forge-specific fields

case-studies:
  SF.AP0001:
    name: "Persistent memory rule injection"
    description: >
      An attacker repeatedly reinforces a false operational rule in the agent's
      persistent memory until the agent treats it as established fact.
    references: []
    created-date: '2025-01-15'
    modified-date: '2025-07-20'
    type: AbstractPattern                  # New type (vs Exercise/Incident)
    actor: GenericExternalAttacker         # Abstract actor archetype
    target: AgenticAISystem               # Abstract target
    id: SF.AP0001
    object-type: case-study

    # --- scenario-forge extensions ---
    sf-extensions:
      threat_id: "T1"
      prerequisite_capabilities:
        min_zones: ["input", "memory"]
        kc_requires:
          all: [KCX-PMEM]
          any: [KC4.3, KC4.4, KC4.5, KC4.6]
      nist_classification:
        attacker_goal: "integrity"
        attacker_knowledge: "black_box"
        learning_stage: "deployment"
        attack_class: "poisoning.targeted_poisoning"

relationships:
  SF.AP0001:
    employs:
    - source: SF.AP0001
      target: AML.T0065
      relationship-type: employs
      description: >
        Attacker crafts payload containing false operational rules that
        the agent's memory system will accept as legitimate context.
      tactic: AML.TA0003
      step-id: S00
      leads-to: [S01]
    - source: SF.AP0001
      target: AML.T0051.001
      relationship-type: employs
      description: >
        Payload delivered through a trusted input channel the agent
        processes as operational data rather than user instruction.
      tactic: AML.TA0004
      step-id: S01
      leads-to: [S02]
    - source: SF.AP0001
      target: AML.T0080.000
      relationship-type: employs
      description: >
        Agent stores fabricated rule in persistent memory, establishing
        cross-session persistence of the attacker's payload.
      tactic: AML.TA0006
      step-id: S02
      leads-to: [S03]
    - source: SF.AP0001
      target: AML.T0048
      relationship-type: employs
      description: >
        Agent authorizes actions that violate its actual constraints,
        treating the fabricated rule as authoritative operational guidance.
      tactic: AML.TA0011
      step-id: S03
      leads-to: []
```

**Pipeline changes needed:**

- **Data loading:** Complete rewrite of `loaders.py` to parse ATLAS v6 format. Must extract case-studies, relationships, and sf-extensions into the existing pipeline data model.
- **ID scheme:** Migrate from AP-T1-01 to SF.AP0001 (or adapt pipeline to handle either).
- **Seeds:** Completely rewrite `seeds.py` to extract scenario seeds from ATLAS-format case studies with sf-extensions.
- **Stage 3.5:** Must parse relationship graphs to extract technique lists for filtering.
- **Stage 4:** Templates must be adapted to consume relationship step graphs instead of flat descriptions.
- **SSSOM:** Largely replaced by inline technique references in the relationships section.
- **Eval:** Must be updated to validate against the relationship graph structure.

**Pros:**
- Native interoperability with ATLAS tooling, reporting, and analysis.
- Can directly incorporate real ATLAS case studies as additional seeds alongside abstract patterns.
- The relationship graph is a proven, mature representation for multi-step attacks.
- Industry alignment: producing ATLAS-compatible output increases the project's credibility and portability.

**Cons:**
- **Massive rewrite.** Every data loader, seed expander, candidate filter, and template must be adapted. This is not incremental -- it is a new pipeline.
- **Format friction.** ATLAS v6 was designed for cataloging observed incidents, not for generating synthetic scenarios. The `sf-extensions` block is a bolted-on namespace that may conflict with future ATLAS versions.
- **Verbosity.** The ATLAS format is extremely verbose. The relationship section for a single 4-step pattern is ~40 lines of YAML vs. 6 lines for the current description-only format. Across 66 patterns, this is 2,600+ lines of relationships alone.
- **Over-engineering.** Adopting a full case-study model for abstract patterns misrepresents what they are. An abstract pattern is NOT a case study. Forcing it into that mold creates semantic confusion.
- **Loss of SSSOM infrastructure.** The current SSSOM-based provenance model is standards-compliant and extensible. Embedding technique references inline sacrifices this.

**Migration effort:** Very high. Full pipeline rewrite (4-6 weeks). Data migration (2 weeks). Template refactoring (2 weeks). Total: 8-10 weeks minimum.

---

## 4. Recommendation

**Option B (Hybrid Model), implemented incrementally starting with Option A's minimal additions.**

### Rationale

The core insight from this comparison is that ATLAS's kill chain model is genuinely valuable but its case-study format is wrong for our purpose. The scenario-forge prerequisite model is genuinely valuable but the flat pattern format undersells the generation pipeline.

Option B captures the best of both:

1. **Keeps the prerequisite model.** This is our differentiator. ATLAS cannot filter patterns by capability profile. Option B preserves this while adding kill chain structure.

2. **Adds structured kill chains without over-constraining.** The `abstract_action` per step is domain-agnostic text, not a concrete incident description. The LLM gets a structural skeleton but retains freedom to instantiate it for any domain.

3. **Makes technique references contextual.** Instead of flat SSSOM associations, each technique reference carries its tactic and step position. This is strictly more informative.

4. **Enables principled composition.** `chains_with` gives the pipeline a structural basis for multi-pattern scenarios instead of random technique pairing.

5. **Does not require adopting ATLAS's case-study model.** Our patterns are patterns, not case studies. Option B keeps them as patterns with enriched structure.

### Implementation strategy

Phase 1 (now): Implement Option A's minimal additions as a compatibility layer.
- Add `tactic_phases` and `atlas_case_study_refs` to 10-15 high-priority patterns.
- Add `operational_steps_hint` to those same patterns.
- No pipeline changes needed -- the fields are informational.
- This provides immediate value for documentation and manual analysis.

Phase 2 (next sprint): Design and validate the kill chain schema.
- Define the `KillChainStep` data model.
- Write 5-10 kill chain templates using ATLAS case studies as reference material (CS0040-CS0062 are ideal sources).
- Prototype pipeline integration: pass kill chain steps to Call 2 templates.
- Evaluate whether kill chain scaffolding improves attack tree quality vs. the unscaffolded baseline.

Phase 3 (if Phase 2 validates): Full rollout.
- Curate kill chain templates for all 66 patterns (LLM-assisted, human-reviewed).
- Add `chains_with` relationships.
- Refactor SSSOM files to be computed from inline technique references (rather than manually maintained).
- Add kill chain consistency metric to eval.

### Design decisions to lock in now

1. **Keep the AP-T{n}-{nn} ID scheme.** Do not adopt ATLAS IDs. Our patterns are ours.

2. **Keep prerequisite_capabilities as-is.** This is non-negotiable for pipeline filtering.

3. **Kill chain steps should reference ATLAS technique IDs, not define new technique objects.** We are consumers of the ATLAS technique taxonomy, not maintainers of it.

4. **Kill chain templates are suggestive, not prescriptive.** The template should influence but not constrain the LLM's attack tree generation. Mark them as `hint` or `scaffold` in the schema.

5. **Support both T-threat and ASI-id grouping.** The current `threat_id` field binds to OWASP T-threats. Add an optional `asi_ids` field to support ATLAS threat categories. The pipeline should be able to filter by either taxonomy.

6. **Preserve the SSSOM infrastructure** for cross-taxonomy mappings that do not fit the kill chain model (e.g. LAAF technique correspondences). SSSOM is standards-compliant and multi-purpose; kill chain templates are attack-pattern-specific.

### What to extract from ATLAS now

Regardless of which option is implemented, ATLAS v6 provides immediate value:

- **CS0040-CS0062** should be analyzed to validate existing patterns and identify gaps. Several case studies (CS0047 Amazon Q, CS0049 poisoned ClawdBot skill, CS0053 poisoned Postmark MCP) may warrant new attack patterns.
- **The tactic taxonomy** (16 tactics) should be adopted as the vocabulary for kill chain steps. Do not invent new tactical phases.
- **Technique IDs** from the agentic case studies should be cross-referenced against existing SSSOM mappings to find and fill coverage gaps.
- **The `maturity` field** (Demonstrated vs. Feasible) is worth borrowing -- some of our patterns describe attacks that have been demonstrated in the wild (AP-T1-01 = CS0040), while others are purely theoretical.
