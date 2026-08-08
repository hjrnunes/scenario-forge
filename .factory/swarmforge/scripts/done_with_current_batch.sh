#!/usr/bin/env bash
# done_with_current_batch.sh <role>
#
# Thin wrapper: complete the current batch for <role> and accept the next batch,
# regardless of the role's configured receive mode. Sources done_with_current.sh
# so completion logic lives in exactly one place.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=done_with_current.sh
. "$SCRIPT_DIR/done_with_current.sh"

role="${1:-${SWARMFORGE_ROLE:-}}"
[ -n "$role" ] || sf_die "usage: done_with_current_batch.sh <role>  (or set SWARMFORGE_ROLE)"
sf_done_batch "$role"
