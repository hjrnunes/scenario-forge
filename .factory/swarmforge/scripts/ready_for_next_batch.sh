#!/usr/bin/env bash
# ready_for_next_batch.sh <role>
#
# Thin wrapper: accept or resume one batch of equal-priority handoffs for <role>,
# regardless of the role's configured receive mode. Sources ready_for_next.sh so
# the queue logic lives in exactly one place.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=ready_for_next.sh
. "$SCRIPT_DIR/ready_for_next.sh"

role="${1:-${SWARMFORGE_ROLE:-}}"
[ -n "$role" ] || sf_die "usage: ready_for_next_batch.sh <role>  (or set SWARMFORGE_ROLE)"
sf_ready_batch "$role"
