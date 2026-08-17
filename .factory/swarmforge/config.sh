# swarmforge-droid project config. Sourced by SubagentStop verify hooks
# and by the helper scripts (swarm_handoff.sh, ready_for_next.sh, etc.).
# Fill in your project's commands. Empty commands are skipped with a warning.
SWARMFORGE_RUNTIME_ROOT=".swarmforge"  # change to .swarmforge-droid to coexist with original SwarmForge
SWARMFORGE_HANDOFFS_DIR="${SWARMFORGE_HANDOFFS_DIR:-$SWARMFORGE_RUNTIME_ROOT/handoffs}"  # set to a custom path to override
SWARMFORGE_ROLES_TSV="${SWARMFORGE_ROLES_TSV:-$SWARMFORGE_RUNTIME_ROOT/roles.tsv}"  # set to a custom path to override
SWARMFORGE_REPORTS_DIR="${SWARMFORGE_REPORTS_DIR:-$SWARMFORGE_RUNTIME_ROOT/reports}"  # set to a custom path to override
# Acceptance-pipeline paths (Plan C: explicit defaults, overridable).
SWARMFORGE_FEATURES_DIR="features"                    # Gherkin .feature source directory
SWARMFORGE_ACCEPTANCE_IR_DIR="build/acceptance/ir"    # gherkin-parser IR output
SWARMFORGE_ACCEPTANCE_DRY_DIR="build/acceptance/dry"  # gherkin-ir-dry-checker reports
SWARMFORGE_ACCEPTANCE_GENERATED_DIR="build/acceptance/generated"  # entrypoint generator output
SWARMFORGE_ACCEPTANCE_MUTATION_DIR="build/acceptance-mutation"    # mutation workspace (ephemeral)
SWARMFORGE_GENERATION_CMD="./scripts/acceptance.sh"          # full generation: parse, DRY-check, generate, clean, run
SWARMFORGE_FILE_POLICY="generated-output"  # committed-snapshot | generated-output
SWARMFORGE_LANGUAGE="python"
SWARMFORGE_TOOLS_CONSENT="given"    # given | declined (set by /swarmforge-setup or orchestrator)
SWARMFORGE_BEADS=true           # true | false (set by /swarmforge-setup; orchestrator uses Beads when .beads/ is present and this is true)
SWARMFORGE_SPEC_REVIEW=false    # true | false (operator opt-in; true = orchestrator asks for spec approval before coding)
SWARMFORGE_TEST_CMD="uv run pytest tests/ -x"
SWARMFORGE_ACCEPTANCE_CMD="./scripts/acceptance.sh --test"
SWARMFORGE_QUALITY_CMD="./scripts/quality.sh"
SWARMFORGE_QA_CMD=""
SWARMFORGE_COVERAGE_CMD="uv run pytest tests/ --cov=src --cov-branch --cov-report=lcov:lcov.info -q"      # generates lcov.info for LCOV-consuming tools (Python: crap4py, mutate4py); -q avoids flooding the subagent context with ~6000 test lines
# Source-analysis tools intentionally exclude acceptance handlers; Ruff owns
# acceptance hygiene through SWARMFORGE_QUALITY_CMD.
SWARMFORGE_CRAP_CMD="crap4py src/ --lcov lcov.info --max-crap 6"
SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"
# Mutation invocation TEMPLATE. The hardender substitutes the changed source
# file paths for `src/` (never run the whole tree unless explicitly directed —
# a full-tree run with the full suite per mutant can take hours and times out
# the delegation). --since-last-run skips already-manifested unchanged code.
SWARMFORGE_MUTATION_CMD="mutate4py src/ --since-last-run --test-command 'uv run pytest tests/ -x -q' --lcov lcov.info --max-workers 8 --verbose"      # language mutation tool invocation (hardender)
SWARMFORGE_CRAP_THRESHOLD=6
SWARMFORGE_MUTATION_SCORE_MIN=80
SWARMFORGE_MUTATION_SITES_MAX=100
