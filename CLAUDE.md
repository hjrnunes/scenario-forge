# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Build & Test

```bash
uv sync                    # Install/update dependencies
ruff check src/            # Linting
uv run pytest tests/ -x    # Tests (842 as of v17)
```

### Running the pipeline

```bash
uv run scenario-forge generate \
    --use-case '@output/<prev>/use-case.txt' \
    --risk-extraction <path-to-risk-extraction.json> \
    --sssom <path-to-risk_to_category.sssom.tsv> \
    --output-dir output/<output-dir>
```

Key flags:
- `--profile <path>` — reuse a pre-built capability-profile.yaml (skips Stage 1 inference)
- `--zones 'input,reasoning,tool_execution'` — restrict to specific zones
- `--max-scenario-techniques 2` — allow technique pairs (default: 1 = singles only)
- `--max-scenarios-per-pattern N` — cap scenarios per attack pattern
- `--no-eval` — skip deterministic eval metrics after generation

### Running eval separately

```bash
uv run scenario-forge eval --output-dir output/<dir>
```

### Generating the HTML report

```bash
uv run scenario-forge report --output-dir output/<dir>
```

## Architecture Overview

Multi-stage AI threat scenario generation pipeline for agentic AI systems.

### Pipeline stages

1. **Stage 1 — Capability Profile**: Single LLM call extracts zones, entry points, KC sub-codes, flags from a use-case description. Output: `capability-profile.yaml`.
2. **Stage 2 — Threat Surface**: Maps risk extraction cards to OWASP agentic threats via SSSOM taxonomy. Output: `threat-surface.yaml`.
3. **Stage 3 — Seed Expansion**: Generates scenario seeds from the threat surface. Deterministic.
4. **Stage 3.5 — Candidate Filter**: LLM call per seed group validates technique-entry point fit. Expands candidates and filters by capability profile.
5. **Stage 4 — Scenario Generation**: Per seed, 4 sequential LLM calls:
   - Call 0: BDI actor profile (`call0_system/user.j2`)
   - Call 1: Attack narrative (`call1_system/user.j2`)
   - Call 2: Attack tree YAML (`call2_system/user.j2`)
   - Call 3: Gherkin behavior spec (`call3_system/user.j2`)
6. **Eval**: Deterministic metrics — consistency, technique agreement, plausibility, parsimony, diversity.
7. **Report**: Self-contained HTML report from all artifacts.

### Key files

- `src/scenario_forge/pipeline/runner.py` — orchestrates all stages
- `src/scenario_forge/pipeline/profile.py` — Stage 1 capability profile inference
- `src/scenario_forge/pipeline/candidates.py` — Stage 3.5 candidate expansion + LLM filter
- `src/scenario_forge/pipeline/generate.py` — Stage 4 scenario generation (4 LLM calls per scenario)
- `src/scenario_forge/pipeline/validation.py` — phantom capability + BDI validation passes
- `src/scenario_forge/data/prompts/*.j2` — all Jinja2 prompt templates
- `src/scenario_forge/report/template.py` — HTML report builder (inline CSS/HTML)
- `src/scenario_forge/report/generator.py` — loads artifacts and assembles report

### Output directory layout

```
output/<run>/
  capability-profile.yaml    # Stage 1
  threat-surface.yaml        # Stage 2
  calls.jsonl                # Non-scenario LLM calls (profile, filter)
  run-manifest.yaml          # Run metadata, hashes, timing
  eval-scorecard.yaml        # Eval metrics
  coverage-gaps.json         # Coverage analysis
  report.html                # Self-contained HTML report
  use-case.txt               # Copy of input use case
  scenarios/
    *.yaml                   # Scenario envelopes
    *.feature                # Gherkin specs
    calls.jsonl              # Per-scenario LLM calls (call 0-3)
```

## Conventions & Patterns

### QA assessment workflow

Full QA uses a workflow with 7 batch reviewers + 1 synthesis agent. Scenarios are split by threat category into batches (A-T2T3, B-T7a, C-T7b, D-T8, E-T9, F-T10, G-T15). Each reviewer checks every scenario in its batch against `ai/extended-context/quality-assessment-checklist.md`. The synthesis agent merges findings into `ai/findings/qa-<run>.md`. Never sample — review every scenario.

Previous QA reports for format reference: `ai/findings/qa-klarna-fs-isac-v15.md`, `v16.md`, `v17.md`.

### Known accepted behaviors (not defects)

- T6 cross-reference on tree nodes — per-node threat_id reflects mechanism, not scenario-level threat (`decision-t6-crossref-policy`)
- Partial technique provenance — if candidate filter rejects a technique, tree should not force it (`decision-technique-provenance-partial`)
- Entry point directionality — RAG knowledge-grounding = input direction (`decision-entry-point-directionality`)

### Prompt template editing

- Templates are Jinja2 (`.j2` files in `src/scenario_forge/data/prompts/`)
- System prompts contain hard constraints and instructions; user prompts contain context data + task directive
- User prompts use `---` separator and `## Your Task` heading to separate context from instructions
- Preserve all `{{ variable }}` references exactly when editing
- Template variable blocks (e.g. `{{ technique_context }}{{ diversity_section }}`) may render empty — preserve them

### Experiment runs

- Use a git worktree to isolate prompt changes from master
- Run `uv sync` in the worktree before running the pipeline
- Reuse the baseline capability profile with `--profile` to control variables
- Output to a clearly labeled directory (e.g. `output/<baseline>-<variant>`)
- Compare against baseline using eval scorecard + targeted manual review
- Experiment workers do NOT change source code on master — if results suggest a code change, file a bead
