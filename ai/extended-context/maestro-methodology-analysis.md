# MAESTRO Methodology: Influence on fg-gen's Modeling

Analysis of the MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) framework's methodology and its implications for fg-gen's intermediate representation and pipeline design.

- [MAESTRO: Agentic AI Threat Modeling Framework](https://cloudsecurityalliance.org/blog/2025/01/28/maestro-multi-agent-security-threat-risk-outcome-threat-modeling-framework-for-agentic-ai) (Ken Huang, Cloud Security Alliance, Jan 2025)

See also: [Threat Modeling Agentic AI — Schneider](threat-modeling-agentic-ai-schneider.md), which references MAESTRO as a coverage validation layer (Phase 3 in the integration workflow).

---

## MAESTRO's core methodology

MAESTRO decomposes agentic AI systems into seven architectural layers and applies threat analysis at each layer independently, then across layers. The methodology has six steps:

1. **System decomposition** — break the target system into components mapped to a seven-layer architecture (foundation models, data operations, agent frameworks, deployment infrastructure, evaluation/observability, security/compliance, agent ecosystem).
2. **Layer-specific threat modeling** — identify threats specific to each layer using MAESTRO's threat landscapes.
3. **Cross-layer threat identification** — analyze how vulnerabilities in one layer enable attacks in others (supply chain, lateral movement, privilege escalation, goal misalignment cascades).
4. **Risk assessment** — evaluate each threat on likelihood and impact; prioritize using a risk matrix.
5. **Mitigation planning** — develop layer-specific, cross-layer, and AI-specific mitigations.
6. **Implementation and monitoring** — deploy mitigations and continuously update the threat model.

MAESTRO also defines architecture patterns (single-agent, multi-agent, hierarchical, distributed ecosystem, human-in-the-loop, self-learning) and maps primary threat profiles to each pattern.

The key methodological contributions beyond existing frameworks:

| Principle | What it adds |
|-----------|-------------|
| Layered decomposition | Threats analyzed per architectural layer, not per component or per attack category |
| Cross-layer chaining | Explicit modeling of attack paths that traverse multiple layers |
| Architecture-pattern awareness | Threat profile conditioned on the target system's agent topology |
| Dual-axis risk assessment | Likelihood x impact, not impact alone |
| Continuous evolution | Threat models treated as living artifacts, not one-time outputs |

---

## Gap analysis: fg-gen's current model

### What the model can express

fg-gen's `FGSpec` captures single-risk threat specifications with provenance, faceted test dimensions, scenario templates, constraints, and violation patterns. The `Provenance` model tracks risk origin through taxonomy, evidence, causal chain, ATLAS vectors, and cross-taxonomy references.

The `Interaction` model supports multi-turn and agent-mode scenarios with zone annotations (Schneider's five-zone model). `campaign.yaml` aggregates specs with coverage statistics and shared facets.

### What the model cannot express

| MAESTRO concept | Current gap in fg-gen |
|----------------|----------------------|
| **Architectural layer** | No concept of where in the stack a risk manifests. A `Provenance` has `taxonomy` and `cross_taxonomy` but no layer annotation. The same risk ID produces the same spec regardless of whether it targets the data pipeline, the foundation model, or the agent ecosystem. |
| **Cross-layer attack chains** | The model is one-risk-one-spec. No way to express "spec A is a precondition for spec B" or "these three specs form a multi-layer attack path." `campaign.yaml` lists specs but has no graph structure. |
| **Architecture pattern** | The campaign has no notion of the target system's topology. Specs don't know whether they're testing a single agent, a multi-agent hierarchy, or a distributed ecosystem. All specs are generated identically regardless. |
| **Likelihood** | `_severity_from_impact()` in `scaffold.py` classifies risk by keyword-matching on impact text alone. No likelihood dimension. The causal chain has `threat_source` (which implies likelihood) but this isn't used in risk scoring. |
| **System decomposition** | fg-gen takes a flat list of `RiskMatchInput` objects with no system model. Risks are not anchored to specific components, trust boundaries, or data flows. Facets like `attack_surface` get generic defaults because there's no architecture to draw from. |
| **Campaign versioning** | Campaigns are one-shot outputs. No stable identifiers that survive re-generation, no diff support, no way to track which specs changed between policy revisions. |

---

## Methodology influences on fg-gen

### 1. Layer annotations on Provenance

MAESTRO's per-layer decomposition suggests that `Provenance` should carry a `layers` field indicating which architectural layers the risk targets. This is distinct from taxonomy — a risk categorized as "data poisoning" under OWASP LLM manifests differently at Layer 2 (manipulating training data) versus Layer 1 (adversarial examples at inference time).

The layer annotation would enable:

- Template selection conditioned on layer (different facets for the same risk category at different layers)
- Coverage reporting per layer in `campaign.yaml` ("Layer 7: 80% covered, Layer 2: 40%")
- Cross-referencing with MAESTRO's layer-specific threat landscapes during scaffold

Source: the upstream policy mapper already extracts causal chains with `threat_source` and `vulnerability` fields that imply architectural position. A mapping from these to MAESTRO layers could be deterministic (keyword-based) or LLM-assisted in Pass 2.

### 2. Cross-layer attack chains

MAESTRO's cross-layer threats (supply chain attacks, lateral movement, privilege escalation, goal misalignment cascades) describe multi-step attack paths that traverse architectural boundaries. These cannot be expressed as isolated single-risk specs.

Two possible modeling approaches:

**A. Campaign-level chain graph.** Add a `chains` section to `campaign.yaml` that links specs into directed graphs:

```yaml
chains:
  - id: supply-chain-to-goal-drift
    description: "Compromised data pipeline poisons model, causing goal misalignment in agent ecosystem"
    steps:
      - spec: data-poisoning-risk-042.fg
        layer: 2
      - spec: model-behavior-drift-risk-017.fg
        layer: 1
      - spec: goal-misalignment-risk-089.fg
        layer: 7
```

**B. Spec-level preconditions.** Add `requires` and `enables` fields to `FGSpec` that reference other specs by risk ID. More granular but creates coupling between specs.

Approach A is more consistent with fg-gen's design — the campaign is already the aggregation layer, and chains are a campaign-level concern. Individual specs remain self-contained.

### 3. Architecture pattern conditioning

MAESTRO identifies that different agent topologies produce fundamentally different threat profiles:

| Pattern | Primary threats | Irrelevant threats |
|---------|-----------------|-------------------|
| Single-agent | Goal manipulation, prompt injection | Inter-agent communication, Sybil attacks |
| Multi-agent | Communication channel attacks, identity attacks | Single-point goal manipulation |
| Hierarchical | Compromise of higher-level agents, cascade control | Distributed consensus manipulation |
| Human-in-the-loop | Feedback manipulation, approval fatigue | Fully autonomous goal drift |
| Self-learning | Data poisoning via backdoor triggers | Static goal manipulation |

If the campaign declared an architecture pattern (or the extraction result included one), the scaffold could:

- Filter out irrelevant template categories (don't generate inter-agent specs for a single-agent system)
- Weight scenario hints toward pattern-relevant attack vectors
- Select appropriate interaction modes (`multi_turn` vs `agent`) based on pattern

This would be a CLI parameter (`--architecture-pattern`) that conditions spec generation without changing the underlying models.

### 4. Risk assessment with likelihood and impact

MAESTRO prescribes a two-dimensional risk matrix. Currently `scaffold.py` collapses risk to a single severity label via `_severity_from_impact()`, which keyword-matches on impact text only.

The causal chain already carries the raw material for likelihood estimation:

- `threat_source` implies attacker capability and motivation
- `vulnerability` implies exploitability
- `threat` implies attack feasibility

Separating likelihood from impact would let downstream generators prioritize facet combination exploration — high-likelihood, high-impact corners of the test space first. This could be modeled as:

- A `likelihood` field on `Violation` (parallel to existing `severity`)
- Or a `risk_score` computed from both dimensions on `Provenance`

The severity keyword approach in `scaffold.py` could be extended with likelihood keywords (e.g., "publicly known," "automated tool available," "requires physical access") without changing the pipeline architecture.

### 5. System decomposition as pipeline input

The deepest methodological influence. MAESTRO's step 1 is "decompose the system into components mapped to the seven-layer architecture." fg-gen currently receives a flat risk list with no system model.

If the extraction result (or a companion file) included a lightweight system decomposition — components, trust boundaries, data flows, agent topology — the scaffold could:

- Anchor risks to specific components rather than generating generic facets
- Populate `attack_surface` facets from the actual architecture
- Detect which MAESTRO layers are present in the target system and scope coverage accordingly
- Generate cross-layer chain candidates automatically (when risks span components in different layers)

This requires upstream changes in the policy mapper and a new input schema. A minimal version:

```python
class SystemComponent(BaseModel):
    id: str
    name: str
    layer: int  # MAESTRO layer 1-7
    trust_level: Literal["trusted", "semi-trusted", "untrusted"]

class SystemDecomposition(BaseModel):
    components: list[SystemComponent]
    data_flows: list[tuple[str, str]]  # component_id pairs
    architecture_pattern: str
```

This is a longer-term influence that would change the extraction pipeline, not just fg-gen.

### 6. Versioned and diffable campaigns

MAESTRO emphasizes continuous monitoring and adaptation — threat models are living documents. Currently, re-running fg-gen on an updated extraction result produces a new campaign with no connection to the previous one. There's no way to answer "what changed since the last policy revision?"

Enabling diffable campaigns requires:

- **Stable spec identifiers** that survive re-generation (currently derived from `slugify(risk_name)`, which is stable if risk names don't change)
- **Campaign version metadata** in `campaign.yaml` (timestamp, input hashes, previous campaign reference)
- **Diff output** — a mode that compares two campaigns and reports new, removed, and modified specs

The rendering layer already produces deterministic output for the same input, so textual diff would work for detecting changes. A structured diff (new risks, removed risks, changed facets) would be more useful for tracking threat model evolution.

---

## Relationship to Schneider's five-zone model

MAESTRO and Schneider's five-zone lens operate at different levels of abstraction and complement each other:

| Dimension | MAESTRO layers | Schneider zones |
|-----------|---------------|----------------|
| **What they decompose** | The technology stack (infrastructure to ecosystem) | The attack propagation path (input to inter-agent) |
| **Orientation** | Vertical (architectural layers) | Horizontal (attack flow across components) |
| **Primary use** | Coverage validation — "did we threat-model every layer?" | Attack discovery — "how does this attack move through the system?" |
| **Granularity** | Coarse (7 layers) | Fine (5 zones per attack path) |
| **Threat identification** | Enumerated per layer | Emerged from scenario walkthroughs |

Schneider's own integration table positions MAESTRO as Phase 3 (validation) after zone-based discovery (Phase 1) and attack tree formalization (Phase 2). In fg-gen's terms:

- **Zones** inform `Interaction.zones` on individual scenario templates — they describe where an attack step happens
- **MAESTRO layers** would inform `Provenance.layers` — they describe which part of the architecture is at risk
- **Attack trees** (Schneider Part 2) map to cross-layer chains — they describe how attack steps compose

The three concepts are orthogonal and can coexist in the model. A scenario template has zones (Schneider), its parent spec has layer annotations (MAESTRO), and the campaign has chains linking specs (attack trees).

---

## Practical applicability

### Actionable now (fg-gen changes only)

| Change | Complexity | Impact |
|--------|-----------|--------|
| Add `layers: list[int]` to `Provenance` | Low | Enables per-layer coverage reporting |
| Add `--architecture-pattern` CLI parameter | Low | Filters irrelevant templates |
| Add `chains` section to `campaign.yaml` schema | Medium | Enables cross-layer attack path modeling |
| Extend `_severity_from_impact()` with likelihood keywords | Low | Two-dimensional risk scoring |
| Add campaign version metadata to `campaign.yaml` | Low | Foundation for diffable campaigns |

### Requires upstream changes

| Change | Dependency | Impact |
|--------|-----------|--------|
| System decomposition input | Policy mapper must extract or accept component/layer annotations | Enables architecture-anchored specs |
| Automatic layer inference from causal chains | Policy mapper must produce richer `threat_source`/`vulnerability` fields | Removes manual layer annotation |
| Structured campaign diff | Stable risk IDs across extraction runs | Tracks threat model evolution |

### Lower priority

MAESTRO Layers 3 (agent frameworks) and 4 (deployment infrastructure) describe threats better addressed by conventional security tooling (dependency scanning, container hardening, IaC validation) than by Faceted Gherkin test specifications. These layers are relevant to a holistic security program but outside fg-gen's scope as a red-teaming spec generator targeting AI behavior.
