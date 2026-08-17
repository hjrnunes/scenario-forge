#!/usr/bin/env bash
# Acceptance pipeline generation command.
#
# Usage:
#   ./scripts/acceptance.sh          # Regenerate IR, DRY reports, and tests, then run them
#   ./scripts/acceptance.sh --test   # Run only the generated tests (no regeneration)
#
# This script wraps acceptance/refresh_snapshot.py and pytest so the
# SwarmForge orchestrator and role droids have a single entry point.
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${1:-}" == "--test" ]]; then
    # Enforce source hygiene before running generated acceptance tests.
    "$root/scripts/quality.sh"
    exec uv run pytest "$root/build/acceptance/generated/" -q
else
    # Full generation: parse features, run DRY checks, generate tests,
    # clean stale output, and run the generated tests.
    exec uv run python "$root/acceptance/refresh_snapshot.py" --run
fi
