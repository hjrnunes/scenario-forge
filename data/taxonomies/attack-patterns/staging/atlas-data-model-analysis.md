# ATLAS v6 Data Model: Exhaustive Structural Analysis

Based on ATLAS data release 2026.06, format-version 6.0.0.

---

## 1. V6 YAML Format: Top-Level Structure

The canonical export file `dist/v6/ATLAS-2026.06.yaml` has **8 top-level keys**:

| Key | Type | Entries | Purpose |
|-----|------|---------|---------|
| `format-version` | string | `"6.0.0"` | Semantic version of the data format |
| `collection` | dict | 9 fields | Metadata about this ATLAS release |
| `matrix` | dict | 8 fields | The single ATLAS matrix definition |
| `tactics` | dict | 16 entries | All tactics, keyed by tactic ID |
| `techniques` | dict | 173 entries | All techniques (parent + sub), keyed by technique ID |
| `mitigations` | dict | 35 entries | All mitigations, keyed by mitigation ID |
| `case-studies` | dict | 63 entries | All case studies, keyed by case study ID |
| `relationships` | dict | 272 entries | All relationships, keyed by source object ID |

**Key design choice**: Objects and relationships are stored separately. The `relationships` section is a flat dictionary keyed by source object ID, with each value being a dict of relationship-type to list-of-relationships. This is a normalized design -- objects carry their own fields, and the graph edges live in `relationships`.

---

## 2. Common Object Fields (AtlasObject Base)

Every object type inherits from `AtlasObject` and shares these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier, pattern-constrained per type |
| `name` | string | Yes | Printable ASCII, short descriptive name |
| `description` | string | Yes | ASCII text (may include newlines), long description |
| `references` | list[Reference] | Yes | External references (can be empty `[]`) |
| `created-date` | date string | Yes | ISO format `YYYY-MM-DD` |
| `modified-date` | date string | Yes | ISO format `YYYY-MM-DD` |
| `uuid` | string | Computed | UUID5 derived deterministically from the `id` using domain `atlas.mitre.org.` |
| `object-type` | string | Computed | One of: `collection`, `matrix`, `tactic`, `technique`, `mitigation`, `case-study` |

### Reference Object

```yaml
- id: ref-1         # kebab-case identifier
  title: "Title"    # printable ASCII
  url: https://...  # valid HTTP URL
```

### AttackReference Object (for cross-references to MITRE ATT&CK)

```yaml
attack-reference:
  id: T1596          # ATT&CK technique/tactic/mitigation ID
  url: https://attack.mitre.org/techniques/T1596/
```

---

## 3. ID Naming Conventions

| Object Type | Pattern | Examples |
|-------------|---------|----------|
| Collection | `ATLAS-collection` (singleton) | `ATLAS-collection` |
| Matrix | `ATLAS-matrix` (singleton) | `ATLAS-matrix` |
| Tactic | `AML.TA####` | `AML.TA0000` through `AML.TA0015` |
| Parent Technique | `AML.T####` | `AML.T0000`, `AML.T0051` |
| Sub-Technique | `AML.T####.###` | `AML.T0051.000`, `AML.T0051.001` |
| Mitigation | `AML.M####` | `AML.M0000` through `AML.M0034` |
| Case Study | `AML.CS####` | `AML.CS0000` through `AML.CS0062` |
| Case Study Step | `S##` | `S00`, `S01`, ... `S17` |

The `AML.` prefix distinguishes ATLAS IDs from ATT&CK IDs (which use bare `TA####`, `T####`, `M####`).

---

## 4. Tactics Model

### Complete Kill Chain (16 tactics, ordered by matrix position)

| Position | ID | Name | ATT&CK Mapping | Techniques |
|----------|-----|------|-----------------|------------|
| 1 | AML.TA0002 | Reconnaissance | TA0043 | 12 |
| 2 | AML.TA0003 | Resource Development | TA0042 | 26 |
| 3 | AML.TA0004 | Initial Access | TA0001 | 15 |
| 4 | AML.TA0000 | AI Model Access | *none (AI-specific)* | 4 |
| 5 | AML.TA0005 | Execution | TA0002 | 13 |
| 6 | AML.TA0006 | Persistence | TA0003 | 14 |
| 7 | AML.TA0012 | Privilege Escalation | TA0004 | 4 |
| 8 | AML.TA0007 | Defense Evasion | TA0005 | 16 |
| 9 | AML.TA0013 | Credential Access | TA0006 | 7 |
| 10 | AML.TA0008 | Discovery | TA0007 | 16 |
| 11 | AML.TA0015 | Lateral Movement | TA0008 | 6 |
| 12 | AML.TA0009 | Collection | TA0009 | 6 |
| 13 | AML.TA0001 | AI Attack Staging | *none (AI-specific)* | 17 |
| 14 | AML.TA0014 | Command and Control | TA0011 | 4 |
| 15 | AML.TA0010 | Exfiltration | TA0010 | 9 |
| 16 | AML.TA0011 | Impact | TA0040 | 19 |

**Key observations**:
- 2 AI-specific tactics with no ATT&CK equivalent: **AI Model Access** (position 4) and **AI Attack Staging** (position 13)
- The ordering differs from ATT&CK: AI Model Access is inserted between Initial Access and Execution; AI Attack Staging sits between Collection and C2
- 14 of 16 tactics map directly to ATT&CK Enterprise tactics
- Tactics added incrementally: TA0000-TA0011 were the original set; TA0012-TA0015 were added later (Privilege Escalation, Credential Access, C2, Lateral Movement)

### Tactic Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | TacticId | Yes | `AML.TA####` |
| `name` | string | Yes | Tactic name |
| `description` | string | Yes | Multi-paragraph description |
| `references` | list[Reference] | Yes | Always `[]` for tactics |
| `created-date` | date | Yes | |
| `modified-date` | date | Yes | |
| `attack-reference` | AttackReference or null | No | Cross-reference to ATT&CK tactic |
| `uuid` | string | Computed | |
| `object-type` | string | Always `"tactic"` | |

---

## 5. Techniques Model

### Overall Statistics

- **103 parent techniques** (pattern `AML.T####`)
- **70 sub-techniques** (pattern `AML.T####.###`)
- **173 total techniques**

### Technique Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | TechniqueId | Yes | `AML.T####` or `AML.T####.###` |
| `name` | string | Yes | Technique name |
| `description` | string | Yes | Multi-paragraph description, may contain markdown links |
| `references` | list[Reference] | Yes | External references |
| `created-date` | date | Yes | |
| `modified-date` | date | Yes | |
| `platforms` | list[string] | Yes | One or more of the 4 platform values |
| `maturity` | string | Yes | One of: `Feasible`, `Demonstrated`, `Realized` |
| `attack-reference` | AttackReference or null | No | Cross-reference to ATT&CK technique |
| `uuid` | string | Computed | |
| `object-type` | string | Always `"technique"` | |

**Note**: Sub-techniques have the exact same field set as parent techniques. The parent-child relationship is encoded in the `relationships` section via `specializes` edges, not as a nested field on the technique object.

### Full Technique Example

```yaml
AML.T0051:
  name: LLM Prompt Injection
  description: 'An adversary may craft malicious prompts as inputs to an LLM...'
  references: []
  created-date: '2023-10-25'
  modified-date: '2026-05-27'
  platforms:
  - Generative AI
  - Agentic AI
  id: AML.T0051
  maturity: Realized
  uuid: 6ff098e9-2864-579e-bebb-a0f1c92ec772
  object-type: technique
```

### Sub-Technique Example

```yaml
AML.T0051.000:
  name: Direct
  description: 'An adversary may inject prompts directly as a user of the LLM...'
  references: []
  created-date: '2023-10-25'
  modified-date: '2026-05-27'
  platforms:
  - Generative AI
  - Agentic AI
  id: AML.T0051.000
  maturity: Realized
  uuid: 073f16fc-c4c0-5351-8a22-9c77aaaab91f
  object-type: technique
```

### Sub-Technique to Parent Relationship

The parent-child relationship is encoded via `specializes` in the relationships section:

```yaml
relationships:
  AML.T0051.000:
    achieves:
    - source: AML.T0051.000
      target: AML.TA0005
      relationship-type: achieves
    specializes:
    - source: AML.T0051.000
      target: AML.T0051
      relationship-type: specializes
```

**Sub-techniques can (and do) achieve different tactics than their parent.** Sub-techniques inherit the parent's object-type but have their own platform and maturity values.

### Platform Values

| Platform | Count | Description |
|----------|-------|-------------|
| Agentic AI | 114 | Techniques applicable to AI agent systems |
| Generative AI | 92 | Techniques applicable to LLMs/generative models |
| Predictive AI | 71 | Techniques applicable to traditional ML/prediction models |
| Enterprise | 61 | Techniques from conventional cybersecurity |

Techniques can have multiple platforms. The platform list is ordered per the `TechniquePlatformType` enum definition: `Predictive AI`, `Generative AI`, `Agentic AI`, `Enterprise`.

### Maturity Values

| Maturity | Count | Meaning |
|----------|-------|---------|
| Demonstrated | 90 | Technique has been demonstrated in research/exercise |
| Realized | 64 | Technique has been observed in real-world incidents |
| Feasible | 19 | Technique is theoretically feasible but not yet demonstrated |

### Techniques with Multiple Tactic Mappings

14 techniques map to more than one tactic (via multiple `achieves` relationships):

| Technique | Tactics |
|-----------|---------|
| AML.T0012 Valid Accounts | Initial Access, Privilege Escalation |
| AML.T0015 Evade AI Model | Initial Access, Defense Evasion, Impact |
| AML.T0018 Manipulate AI Model | AI Attack Staging, Persistence |
| AML.T0020 Poison Training Data | Resource Development, Persistence |
| AML.T0052 Phishing | Initial Access, Lateral Movement |
| AML.T0053 AI Agent Tool Invocation | Execution, Privilege Escalation |
| AML.T0054 LLM Jailbreak | Defense Evasion, Privilege Escalation |
| AML.T0081 Modify AI Agent Configuration | Persistence, Defense Evasion |
| AML.T0093 Prompt Infiltration via Public-Facing App | Initial Access, Persistence |

### ATT&CK Cross-References

37 of 173 techniques have `attack-reference` linking to an ATT&CK Enterprise technique. Examples:
- `AML.T0051 LLM Prompt Injection` -- no ATT&CK equivalent (AI-native)
- `AML.T0011 User Execution` -> ATT&CK `T1204`
- `AML.T0078 Drive-by Compromise` -> ATT&CK `T1189`

---

## 6. Mitigations Model

### Mitigation Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | MitigationId | Yes | `AML.M####` |
| `name` | string | Yes | Mitigation name |
| `description` | string | Yes | Mitigation description |
| `references` | list[Reference] | Yes | External references |
| `created-date` | date | Yes | |
| `modified-date` | date | Yes | |
| `lifecycle-phases` | list[string] | Yes | One or more ML lifecycle phases |
| `categories` | list[string] | Yes | One or more category types |
| `attack-reference` | AttackReference or null | No | Cross-reference to ATT&CK mitigation |
| `uuid` | string | Computed | |
| `object-type` | string | Always `"mitigation"` | |

### Lifecycle Phases (enum `MitigationLifecyclePhasesType`)

1. Business and Data Understanding
2. Data Preparation
3. AI Model Engineering
4. AI Model Evaluation
5. Deployment
6. Monitoring and Maintenance

### Mitigation Categories (enum `MitigationCategoryType`)

- **Policy** -- organizational policy controls
- **Technical - AI** -- AI-specific technical controls
- **Technical - Cyber** -- traditional cybersecurity controls

### Mitigation-to-Technique Linking

Mitigations are linked to techniques via `mitigates` relationships in the relationships section. Each mitigates relationship has an optional `description` field that explains how the mitigation applies to that specific technique.

```yaml
relationships:
  AML.M0000:
    mitigates:
    - source: AML.M0000
      target: AML.T0000
      relationship-type: mitigates
      description: 'Limit the connection between publicly disclosed approaches...'
```

Total: **247 mitigates relationships** across 35 mitigations.

### Complete Mitigation List (35 mitigations)

| ID | Name | Categories | Phases |
|----|------|-----------|--------|
| AML.M0000 | Limit Public Release of Information | Policy | Business and Data Understanding |
| AML.M0001 | Limit Model Artifact Release | Policy | Business and Data Understanding, Deployment |
| AML.M0002 | Passive AI Output Obfuscation | Technical - AI | AI Model Evaluation, Deployment |
| AML.M0003 | Model Hardening | Technical - AI | Data Preparation, AI Model Engineering |
| AML.M0004 | Restrict Number of AI Model Queries | Technical - Cyber | Business and Data Understanding, Deployment, Monitoring |
| AML.M0005 | Control Access to AI Models and Data at Rest | Policy | Business, Data Prep, Engineering, Evaluation |
| AML.M0006 | Use Ensemble Methods | Technical - AI | AI Model Engineering |
| AML.M0007 | Sanitize Training Data | Technical - AI | Business, Data Prep, Monitoring |
| AML.M0008 | Validate AI Model | Technical - AI | AI Model Evaluation, Monitoring |
| AML.M0009 | Use Multi-Modal Sensors | Technical - Cyber | Business, Data Prep, Engineering |
| AML.M0010 | Input Restoration | Technical - AI | Data Prep, Evaluation, Deployment, Monitoring |
| AML.M0011 | Restrict Library Loading | Technical - Cyber | Deployment |
| AML.M0012 | Encrypt Sensitive Information | Technical - Cyber | Data Prep, Engineering, Deployment |
| AML.M0013 | Code Signing | Technical - Cyber | Deployment |
| AML.M0014 | Verify AI Artifacts | Technical - Cyber | Business, Data Prep, Engineering |
| AML.M0015 | Adversarial Input Detection | Technical - AI | Data Prep, Engineering, Evaluation, Deployment, Monitoring |
| AML.M0016 | Vulnerability Scanning | Technical - Cyber | Data Prep, Engineering |
| AML.M0017 | AI Model Distribution Methods | Policy | Deployment |
| AML.M0018 | User Training | Policy | All 6 phases |
| AML.M0019 | Control Access to AI Models and Data in Production | Policy | Deployment, Monitoring |
| AML.M0020 | Generative AI Guardrails | Technical - AI | Engineering, Evaluation, Deployment, Monitoring |
| AML.M0021 | Generative AI Guidelines | Technical - AI | Engineering, Evaluation, Deployment |
| AML.M0022 | Generative AI Model Alignment | Technical - AI | Engineering, Evaluation, Deployment |
| AML.M0023 | AI Bill of Materials | Policy | Business, Data Prep, Engineering |
| AML.M0024 | AI Telemetry Logging | Technical - Cyber | Deployment, Monitoring |
| AML.M0025 | Maintain AI Dataset Provenance | Technical - AI | Business, Data Prep |
| AML.M0026 | Privileged AI Agent Permissions Configuration | Technical - Cyber | Deployment |
| AML.M0027 | Single-User AI Agent Permissions Configuration | Technical - Cyber | Deployment |
| AML.M0028 | AI Agent Tools Permissions Configuration | Technical - Cyber | Deployment |
| AML.M0029 | Human In-the-Loop for AI Agent Actions | Technical - AI | Deployment |
| AML.M0030 | Restrict AI Agent Tool Invocation on Untrusted Data | Technical - AI | Deployment |
| AML.M0031 | Memory Hardening | Technical - AI | Engineering, Deployment, Monitoring |
| AML.M0032 | Segmentation of AI Agent Components | Technical - Cyber | Business, Deployment |
| AML.M0033 | Input and Output Validation for AI Agent Components | Technical - AI | Business, Data Prep, Deployment |
| AML.M0034 | Deepfake Detection | Technical - AI | Engineering, Evaluation, Deployment, Monitoring |

**Note**: Mitigations M0026-M0033 are **agentic-specific** mitigations added to address AI agent attack surfaces.

---

## 7. Case Studies Model

### Case Study Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | CaseStudyId | Yes | `AML.CS####` |
| `name` | string | Yes | Case study title |
| `description` | string | Yes | Multi-paragraph narrative description |
| `references` | list[Reference] | Yes | External references (papers, blog posts, etc.) |
| `created-date` | date | Yes | When this case study entry was created |
| `modified-date` | date | Yes | When this case study entry was last modified |
| `type` | string | Yes | Either `"Incident"` or `"Exercise"` |
| `actor` | string | Yes | Who performed the attack |
| `target` | string | Yes | What was attacked |
| `reporter` | string or null | Conditional | Who reported the incident. **Required for Incidents, must be null for Exercises** |
| `date` | date | Yes | When the incident/exercise occurred |
| `date-granularity` | string | Yes | One of: `Year`, `Month`, `Day` |
| `uuid` | string | Computed | |
| `object-type` | string | Always `"case-study"` | |

### Case Study Types

- **Incident** (real-world): Must have a `reporter` field. Examples: VirusTotal Poisoning, ShadowRay, Storm-2139.
- **Exercise** (research/red-team): Must NOT have a `reporter` field. Examples: Cursor MCP attack, PoisonGPT, Morris II worm.

### Case Study Example

```yaml
AML.CS0045:
  name: Data Exfiltration via an MCP Server used by Cursor
  description: 'The Backslash Security Research Team demonstrated...'
  references:
  - id: ref-1
    title: 'Backslash Security Blog Post'
    url: https://...
  created-date: '2025-09-17'
  modified-date: '2025-12-23'
  type: Exercise
  actor: Backslash Security Research Team
  target: Cursor
  date: '2025-06-24'
  date-granularity: Day
  id: AML.CS0045
  uuid: ...
  object-type: case-study
```

### Date Handling

The `date` field accepts partial dates:
- `YYYY` (year only) -- stored as `YYYY-01-01`, granularity `Year`
- `YYYY-MM` (year-month) -- stored as `YYYY-MM-01`, granularity `Month`
- `YYYY-MM-DD` (full date) -- granularity `Day`

The `date-granularity` field tells you how to interpret the date.

---

## 8. Relationships Model (Critical Section)

The relationships section is the graph layer that connects all objects. It is organized as:

```yaml
relationships:
  <source-object-id>:
    <relationship-type>:
    - source: <source-id>
      target: <target-id>
      relationship-type: <type>
      [additional fields per type]
```

### Five Relationship Types

| Type | Direction | Count | Purpose |
|------|-----------|-------|---------|
| `sequences` | Matrix -> Tactic | 16 | Orders tactics in the kill chain |
| `achieves` | Technique -> Tactic | 188 | Maps techniques to the tactics they achieve |
| `specializes` | Sub-technique -> Parent | 70 | Hierarchical technique nesting |
| `mitigates` | Mitigation -> Technique | 247 | Links mitigations to techniques |
| `employs` | Case Study -> Technique | 504 | Maps case study steps to techniques |

### Relationship Field Schemas

#### `sequences` (Matrix -> Tactic)
```yaml
- source: ATLAS-matrix
  target: AML.TA0002
  relationship-type: sequences
  position: 1    # integer, 1-based, defines kill chain order
```
Fields: `source`, `target`, `relationship-type`, `position`

#### `achieves` (Technique -> Tactic)
```yaml
- source: AML.T0051
  target: AML.TA0005
  relationship-type: achieves
```
Fields: `source`, `target`, `relationship-type` (minimal -- no extra fields)

#### `specializes` (Sub-technique -> Parent Technique)
```yaml
- source: AML.T0051.000
  target: AML.T0051
  relationship-type: specializes
```
Fields: `source`, `target`, `relationship-type` (minimal)

#### `mitigates` (Mitigation -> Technique)
```yaml
- source: AML.M0000
  target: AML.T0000
  relationship-type: mitigates
  description: 'Limit the connection between publicly disclosed approaches...'
```
Fields: `source`, `target`, `relationship-type`, `description` (optional -- explains how the mitigation applies to this specific technique)

#### `employs` (Case Study -> Technique) -- the richest relationship type
```yaml
- source: AML.CS0045
  target: AML.T0065
  relationship-type: employs
  description: 'The researchers crafted a malicious prompt...'
  tactic: AML.TA0003
  step-id: S00
  leads-to:
  - S01
```
Fields:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | CaseStudyId | Yes | The case study |
| `target` | TechniqueId | Yes | The technique employed |
| `relationship-type` | string | Always `"employs"` | |
| `description` | string | Yes | Narrative of how the technique was used in this step |
| `tactic` | TacticId | Yes | The tactic under which this technique was employed |
| `step-id` | string | Yes | Step identifier in format `S##` (e.g., `S00`, `S01`) |
| `leads-to` | list[string] | Yes | List of subsequent step-ids (empty `[]` for terminal steps) |

### How Relationships Encode Multi-Step Attack Sequences

The `employs` relationships form a **directed graph** of attack steps. Each step has:
1. A `step-id` (e.g., `S00`, `S01`)
2. A `leads-to` list pointing to subsequent steps
3. A `tactic` indicating which kill-chain phase this step falls under
4. A `technique` indicating what was done
5. A `description` narrating the specific action

**Important properties**:
- Steps are **zero-indexed** (`S00` is the first step)
- Steps are **strictly sequential** in all current data (no branching -- `leads-to` always has 0 or 1 entry)
- Terminal steps have `leads-to: []`
- The **same technique can appear in different steps** (with different tactics)
- The tactic in `employs` may differ from the technique's primary tactic mapping via `achieves` -- this is because a technique can be used in service of a different tactic depending on the attack context
- Attack chains range from 3 to 18 steps (median ~6-7)
- The longest chain is AML.CS0051 (OpenClaw C2 via Prompt Injection) with 18 steps

### DB Model Detail: Extra Fields

In the SQLAlchemy model (`models.py`), `employs` relationship data beyond `source`/`target`/`type`/`description` is stored in a JSON `extra_fields` column:

```python
class Relationship(Base):
    source: Mapped[str]
    target: Mapped[str]
    relationship_type: Mapped[AtlasRelationshipType]
    description: Mapped[str | None]
    extra_fields: Mapped[dict | None] = mapped_column(JSON)
```

The `extra_fields` dict contains: `tactic`, `step_id`, `leads_to`, and `position` (for sequences). This means the DB model is generic -- the extra relationship fields are schema-specific and stored as JSON.

---

## 9. Complete Relationship Chain Examples

### Example 1: AML.CS0045 -- Data Exfiltration via MCP Server (Cursor)

An 11-step attack chain demonstrating MCP-based supply chain attack:

```
S00: AML.T0065 LLM Prompt Crafting            (Resource Development)
 -> S01: AML.T0079 Stage Capabilities          (Resource Development)
 -> S02: AML.T0068 LLM Prompt Obfuscation      (Defense Evasion)
 -> S03: AML.T0079 Stage Capabilities           (Resource Development)
 -> S04: AML.T0078 Drive-by Compromise          (Initial Access)
 -> S05: AML.T0051.001 Indirect Prompt Injection (Execution)
 -> S06: AML.T0053 AI Agent Tool Invocation      (Privilege Escalation)
 -> S07: AML.T0068 LLM Prompt Obfuscation        (Defense Evasion)
 -> S08: AML.T0083 Credentials from AI Agent Config (Credential Access)
 -> S09: AML.T0086 Exfiltration via Agent Tool    (Exfiltration)
 -> S10: AML.T0048.000 Financial Harm             (Impact) [terminal]
```

### Example 2: AML.CS0046 -- Data Destruction via Claude Computer-Use

A 7-step attack chain targeting Claude's computer-use agent:

```
S00: AML.T0065 LLM Prompt Crafting              (Resource Development)
 -> S01: AML.T0093 Prompt Infiltration via App   (Initial Access)
 -> S02: AML.T0051.001 Indirect Prompt Injection (Execution)
 -> S03: AML.T0054 LLM Jailbreak                (Defense Evasion)
 -> S04: AML.T0068 LLM Prompt Obfuscation       (Defense Evasion)
 -> S05: AML.T0053 AI Agent Tool Invocation      (Execution)
 -> S06: AML.T0101 Data Destruction via Agent Tool (Impact) [terminal]
```

### Example 3: AML.CS0053 -- Poisoned Postmark MCP Server (Real Incident)

A 9-step supply chain attack on a real MCP tool:

```
S00: AML.T0073 Impersonation                    (Defense Evasion)
 -> S01: AML.T0017 Develop Capabilities          (Resource Development)
 -> S02: AML.T0104 Publish Poisoned AI Agent Tool (Resource Development)
 -> S03: AML.T0109 AI Supply Chain Rug Pull       (Defense Evasion)
 -> S04: AML.T0010.005 AI Agent Tool              (Initial Access)
 -> S05: AML.T0110 AI Agent Tool Poisoning        (Persistence)
 -> S06: AML.T0011.002 Poisoned AI Agent Tool     (Execution)
 -> S07: AML.T0086 Exfiltration via Agent Tool    (Exfiltration)
 -> S08: AML.T0048 External Harms                 (Impact) [terminal]
```

---

## 10. Collection and Matrix Objects

### Collection Object

A singleton metadata record describing the ATLAS release:

```yaml
collection:
  name: ATLAS
  description: Adversarial Threat Landscape for AI Systems
  references: []
  created-date: '2020-10-23'
  modified-date: '2026-05-27'
  version: '2026.06'      # <-- unique to Collection
  id: ATLAS-collection
  uuid: 7a735cfc-0469-5d8b-b11f-d014be33394e
  object-type: collection
```

The Collection has one extra field beyond AtlasObject: `version` (the ATLAS data release version, e.g. `"2026.06"`).

### Matrix Object

A singleton defining the ATLAS matrix:

```yaml
matrix:
  name: ATLAS
  description: Adversarial Threat Landscape for AI Systems
  references: []
  created-date: '2020-10-23'
  modified-date: '2026-05-27'
  id: ATLAS-matrix
  uuid: 967c63ff-22bd-5ff8-aa59-1e1fca8dec78
  object-type: matrix
```

The Matrix object itself has no extra fields. Its tactic ordering is defined via `sequences` relationships in the relationships section.

---

## 11. Python Code: Authoritative Schema Details

### `atlas/schemas.py` -- Pydantic Validation Models

The Pydantic schemas in `schemas.py` are the authoritative validation layer. Key revelations:

1. **AtlasExport** is the top-level export schema:
   ```python
   class AtlasExport(ConfiguredBaseModel):
       format_version: str  # semver pattern
       collection: Collection
       matrix: Matrix
       tactics: dict[TacticId, Tactic]
       techniques: dict[TechniqueId, Technique]
       mitigations: dict[MitigationId, Mitigation]
       case_studies: dict[CaseStudyId, CaseStudy]
       relationships: dict[AtlasObjectId, dict[AtlasRelationshipType, list[AtlasRelationship]]]
   ```

2. **Kebab-case aliasing**: All fields use kebab-case in YAML (`created-date`, `object-type`) but camelCase/snake_case in Python. The `alias_generator=to_kebab` handles this.

3. **UUID computation**: UUIDs are deterministically computed from IDs using UUID5 with domain `atlas.mitre.org.`:
   ```python
   ATLAS_UUID_DOMAIN = uuid.UUID("atlas.mitre.org.".encode("utf-8").hex())
   uuid = str(uuid.uuid5(ATLAS_UUID_DOMAIN, self.id))
   ```

4. **Technique maturity is required**: It's a separate field from TechniqueFields (defined on the Technique response class), not optional.

5. **Platform ordering**: Platforms are sorted per enum definition order: Predictive AI, Generative AI, Agentic AI, Enterprise.

6. **EmploysRelationshipFields** has strict validation:
   ```python
   class EmploysRelationshipFields(StrictConfiguredBaseModel):
       technique: TechniqueId
       tactic: TacticId
       step_id: CaseStudyStepId | None = None
       leads_to: list[CaseStudyStepId] = Field(default_factory=list)
       description: str | None = Field(None, pattern=ASCII_TEXT)
   ```

7. **Input vs Response schemas**: The code separates create/update schemas (no `id`) from response schemas (with `id`). For example, `TechniqueInput` vs `TechniqueResponse`.

### `atlas/enums.py` -- Enum Definitions

All enumerated value types:

```python
class AtlasObjectType(Enum):
    COLLECTION = "collection"
    MATRIX = "matrix"
    TACTIC = "tactic"
    TECHNIQUE = "technique"
    MITIGATION = "mitigation"
    CASE_STUDY = "case-study"

class AtlasRelationshipType(Enum):
    SEQUENCES = "sequences"
    ACHIEVES = "achieves"
    SPECIALIZES = "specializes"
    MITIGATES = "mitigates"
    EMPLOYS = "employs"

class TechniqueMaturity(Enum):
    FEASIBLE = "Feasible"
    DEMONSTRATED = "Demonstrated"
    REALIZED = "Realized"

class TechniquePlatformType(Enum):
    PREDICTIVE = "Predictive AI"
    GENERATIVE = "Generative AI"
    AGENTIC = "Agentic AI"
    ENTERPRISE = "Enterprise"

class MitigationCategoryType(Enum):
    POLICY = "Policy"
    TECHNICAL_AI = "Technical - AI"
    TECHNICAL_CYBER = "Technical - Cyber"

class MitigationLifecyclePhasesType(Enum):
    DATA_UNDERSTANDING = "Business and Data Understanding"
    DATA_PREPARATION = "Data Preparation"
    MODEL_ENGINEERING = "AI Model Engineering"
    MODEL_EVALUATION = "AI Model Evaluation"
    DEPLOYMENT = "Deployment"
    MONITORING = "Monitoring and Maintenance"

class CaseStudyType(Enum):
    INCIDENT = "Incident"
    EXERCISE = "Exercise"

class DateGranularity(Enum):
    YEAR = "Year"
    MONTH = "Month"
    DAY = "Day"
```

### `atlas/models.py` -- SQLAlchemy DB Models

The DB layer uses single-table inheritance (`AtlasObject` as the polymorphic base). Key design:

1. **Composite primary keys**: All objects use `(id, version)` as their primary key, enabling multiple versions of the same object.

2. **Relationship uniqueness constraints**:
   - Non-employs relationships: unique on `(source, target, version, relationship_type)`
   - Employs relationships: unique on `(source, target, version, relationship_type, extra_fields)` -- this allows the same case study to employ the same technique multiple times in different steps

3. **Source/Target constraints**: `source != target` is enforced at DB level.

4. **Lazy loading strategy**: Relationships use `selectin` loading for navigation, `select` for technique-tactic joins.

### `atlas/mappers/case_studies.py` -- Relationship Extraction

The case study mapper reveals how `employs` relationships are stored in the DB:
```python
for rel in db_obj.source_relationships:
    if rel.relationship_type == AtlasRelationshipType.EMPLOYS:
        extra = rel.extra_fields or {}
        attack_chain.append(
            EmploysRelationshipFields(
                technique=rel.target,
                tactic=extra["tactic"],
                step_id=extra.get("step_id"),
                leads_to=extra.get("leads_to", []),
                description=rel.description,
            )
        )
```

The `tactic`, `step_id`, and `leads_to` are stored in `extra_fields` JSON, while `description` is a first-class column. Similarly for `sequences`, the `position` is stored in `extra_fields`.

---

## 12. JSON Schemas (dist/schemas/)

Three JSON Schema files define validation for different contexts:

### `atlas_output_schema.json` -- Legacy/Website Output

This is an older, flatter format (pre-v6) for website rendering. Key differences from v6:
- Uses `matrices[].tactics[]` and `matrices[].techniques[]` arrays (denormalized)
- Sub-techniques have `subtechnique-of` field (inline, not via relationships)
- Case studies use `procedure[]` (array of steps) instead of the relationships section
- Maturity values are lowercase: `feasible`, `demonstrated`, `realized`
- Does not include mitigations or relationships as separate sections
- Case studies use `incident-date`, `incident-date-granularity`, `summary` (not `description`)

### `atlas_contribution_schema.json` -- Community Contributions

Schema for submitting new content to ATLAS. Supports:
- Inline definitions (new tactics/techniques/mitigations can be defined inline within a contribution)
- `items-to-remove` for specifying objects to deprecate
- Case studies wrapped in `study`/`meta` structure
- `reported-by` field is deprecated, replaced by `reporter`

### `atlas_website_case_study_schema.json` -- Case Study Submissions

Specialized schema for case study contributions via the website.

---

## 13. Agentic AI Technique Inventory

114 techniques are tagged with the `Agentic AI` platform. A selection of the most agent-specific ones:

### Agent-Native Techniques (only Agentic AI or Agentic+Generative)

| ID | Name | Maturity | Other Platforms |
|----|------|----------|-----------------|
| AML.T0002.002 | AI Agent Configuration | Demonstrated | Generative AI |
| AML.T0010.005 | AI Agent Tool | Realized | Predictive, Generative |
| AML.T0011.002 | Poisoned AI Agent Tool | Realized | - |
| AML.T0034.002 | Agentic Resource Consumption | Feasible | - |
| AML.T0053 | AI Agent Tool Invocation | Demonstrated | - |
| AML.T0080 | AI Agent Context Poisoning | Demonstrated | - |
| AML.T0080.000 | Memory | Demonstrated | - |
| AML.T0080.001 | Thread | Demonstrated | - |
| AML.T0081 | Modify AI Agent Configuration | Demonstrated | - |
| AML.T0083 | Credentials from AI Agent Configuration | Demonstrated | - |
| AML.T0084 | Discover AI Agent Configuration | Demonstrated | - |
| AML.T0084.000 | Embedded Knowledge | Demonstrated | - |
| AML.T0084.001 | Tool Definitions | Demonstrated | - |
| AML.T0084.002 | Activation Triggers | Demonstrated | - |
| AML.T0084.003 | Call Chains | Demonstrated | - |
| AML.T0085 | Data from AI Services | Demonstrated | - |
| AML.T0085.000 | RAG Databases | Demonstrated | - |
| AML.T0085.001 | AI Agent Tools | Demonstrated | - |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | Realized | - |
| AML.T0098 | AI Agent Tool Credential Harvesting | Demonstrated | - |
| AML.T0099 | AI Agent Tool Data Poisoning | Feasible | - |
| AML.T0100 | AI Agent Clickbait | Demonstrated | - |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | Realized | - |
| AML.T0103 | Deploy AI Agent | Realized | - |
| AML.T0104 | Publish Poisoned AI Agent Tool | Realized | - |
| AML.T0108 | AI Agent | Demonstrated | - |
| AML.T0110 | AI Agent Tool Poisoning | Realized | - |
| AML.T0112 | Machine Compromise | Demonstrated | - |
| AML.T0112.000 | Local AI Agent | Demonstrated | - |

---

## 14. Version History and Format Evolution

The `dist/manifest.yaml` shows that the v6 format has been used since the earliest releases (backported). Each release generates both:
- A v6 format file in `dist/v6/`
- A legacy format file in `dist/legacy/` (format versions 2.x through 5.x)

As of 2026.05, legacy format generation was dropped. The `format-version` constant is `6.0.0`.

The Version DB model supports branching/copying versions:
```python
class Version(Base):
    version: Mapped[str]       # primary key
    base_version: Mapped[str | None]  # parent version for copies
    created_date: Mapped[date]
    modified_date: Mapped[date]
    publish_date: Mapped[date | None]
```

---

## 15. Summary: Key Design Properties for Integration

1. **Normalized graph model**: Objects are flat dictionaries; relationships are a separate section encoding the graph edges. This is clean for programmatic consumption but means you must join across sections to get a complete picture.

2. **Five relationship types are exhaustive**: `sequences`, `achieves`, `specializes`, `mitigates`, `employs` are the only edge types. No others are defined or supported.

3. **Attack chains are DAGs** (in theory): The `leads-to` field on `employs` relationships could encode branching, but in practice all 504 current `employs` edges are strictly sequential (0 or 1 successor). No branching has been used.

4. **Techniques are polymorphic**: Sub-techniques and parent techniques share the same schema. The hierarchy is encoded purely via `specializes` relationships, not via nesting.

5. **Platforms are a multi-valued tag**: A technique can apply to any combination of `{Predictive AI, Generative AI, Agentic AI, Enterprise}`.

6. **Maturity is an evidence level**: `Feasible` < `Demonstrated` < `Realized` tracks whether a technique has been theorized, lab-tested, or observed in the wild.

7. **ATT&CK alignment is partial and optional**: 37/173 techniques, 14/16 tactics, and 5/35 mitigations cross-reference ATT&CK. The AI-native concepts have no ATT&CK equivalent.

8. **Case studies encode complete kill chains**: Each case study has an ordered sequence of steps, each linking (technique, tactic, description) with explicit sequencing via step-ids.

9. **The v6 format is the canonical format**: The legacy format was maintained for backward compatibility but has been dropped as of 2026.05.

10. **The data is versioned by release**: Each release (e.g., "2026.06") is a snapshot. The DB supports composite `(id, version)` keys, allowing the same object to exist in multiple versions.
