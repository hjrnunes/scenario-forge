# swarmforge-droid project config. Sourced by SubagentStop verify hooks.
# Fill in your project's commands. Empty commands are skipped with a warning.
SWARMFORGE_LANGUAGE="python"
SWARMFORGE_TOOLS_CONSENT="given"    # given | declined (set by /swarmforge-setup or orchestrator)
SWARMFORGE_TEST_CMD="uv run pytest tests/ -x"
SWARMFORGE_ACCEPTANCE_CMD=""
SWARMFORGE_QA_CMD=""
SWARMFORGE_COVERAGE_CMD="uv run pytest tests/ --cov=src --cov-branch --cov-report=lcov:lcov.info"      # generates lcov.info for LCOV-consuming tools (Python: crap4py, mutate4py)
SWARMFORGE_CRAP_CMD="crap4py src/ --lcov lcov.info --max-crap 6"
SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"
SWARMFORGE_MUTATION_CMD="mutate4py src/ --test-command 'uv run pytest tests/ -x' --lcov lcov.info --max-workers 8"      # language mutation tool invocation (hardender)
SWARMFORGE_CRAP_THRESHOLD=6
SWARMFORGE_MUTATION_SCORE_MIN=80
SWARMFORGE_MUTATION_SITES_MAX=100
SWARMFORGE_BEADS=true           # true | false (set by /swarmforge-setup; orchestrator uses Beads when .beads/ is present and this is true)
SWARMFORGE_SPEC_REVIEW=false    # true | false (operator opt-in; true = orchestrator asks for spec approval before coding)
