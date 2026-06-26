# scenario-forge

LLM-driven red-teaming scenario generator for AI and agentic systems. scenario-forge takes a use-case description, a policy-mapper risk extraction, and an SSSOM taxonomy mapping, then runs them through a multi-stage pipeline that profiles system capabilities, maps threat surfaces across taxonomies (NIST, OWASP, MITRE ATLAS), expands scenario seeds, and uses an LLM to generate structured adversarial attack scenarios with Gherkin test cases and an HTML report.

> **Status:** Pre-alpha prototype. Interfaces will change without notice.

## Installation

Requires Python 3.11+. Install with [uv](https://docs.astral.sh/uv/):

```bash
uv pip install -e .
```

For development dependencies (pytest, ruff):

```bash
uv pip install -e ".[dev]"
```

## Usage

### Full pipeline

```bash
scenario-forge generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --sssom mappings.sssom.tsv \
  --output-dir output/my-system \
  --base-url http://localhost:8080/v1 \
  --model gemma-3n-e4b-it
```

The `--use-case` flag accepts either a literal string or `@path/to/file.txt` to read from a file.

LLM connection can also be configured via environment variables:

- `SCENARIO_FORGE_MODEL_BASE_URL` -- LLM endpoint (OpenAI-compatible)
- `SCENARIO_FORGE_API_KEY` -- API key
- `SCENARIO_FORGE_MODEL_NAME` -- model name (default: `gemma-3n-e4b-it`)

### Profile only (stage 1)

```bash
scenario-forge profile \
  --use-case @use-case.txt \
  --output capability-profile.yaml
```

### Generate report from existing output

```bash
scenario-forge report --output-dir output/my-system
```

## Pipeline overview

The `generate` command runs four stages, then produces a report:

1. **Capability profiling** -- An LLM infers the system's capability profile (active zones, entry points, data flows) from the use-case description.
2. **Threat surface determination** -- Risk cards from a policy-mapper extraction are matched against SSSOM taxonomy mappings and cross-taxonomy mappings to identify actionable threats and governance-only items.
3. **Scenario seed expansion** -- Each actionable risk card is expanded into concrete scenario seeds, pairing risk cards with specific agentic threat IDs.
4. **Scenario generation** -- An LLM generates a structured attack scenario for each seed, including attack trees, preconditions, and Gherkin-format test steps.
5. **Report** -- An HTML report is auto-generated summarizing all scenarios.

## Output

The pipeline writes to the specified `--output-dir`:

```
output/my-system/
  capability-profile.yaml   # Stage 1: inferred capability profile
  threat-surface.yaml       # Stage 2: mapped threat surface
  scenarios/
    <scenario-id>.yaml      # Stage 4: structured scenario envelope
    <scenario-id>.feature   # Stage 4: Gherkin feature file
  report.html               # Summary report
```

## Inputs

- **use-case** -- Free-text description of the AI system under assessment
- **risk-extraction.json** -- Output from [policy-mapper](https://github.com/policy-mapper) risk extraction
- **SSSOM TSV** -- Taxonomy mapping file in [SSSOM](https://mapping-commons.github.io/sssom/) format
- **cross-taxonomy-mappings.yaml** (optional) -- Custom cross-taxonomy mappings; a default is bundled
- **OWASP agentic threats YAML** (optional) -- Custom threats file; a default is bundled
