#!/usr/bin/env bash
# done_with_current.sh <role>
#
# Complete the current task or batch for <role>, then accept the next one and
# pass through its TASK:/BATCH:/NO_TASK output. Reads the role's receive mode
# from .swarmforge/roles.tsv and dispatches.
#
# Output (task mode):
#   COMPLETED: <path>
#   <ready_for_next output for the next item>
# Output (batch mode):
#   COMPLETED: <each path>
#   COMPLETED BATCH: <batch dir>
#   <ready_for_next output for the next batch>
#
# Pure shell. No Babashka, no daemon.
set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Source the ready helpers (ready_for_next.sh only dispatches when run directly).
# shellcheck source=ready_for_next.sh
. "$SCRIPT_DIR/ready_for_next.sh"

# ---------------------------------------------------------------------------
# Task completion
# ---------------------------------------------------------------------------

sf_done_task() {
  local role="$1" inbox ipdir
  inbox="$(sf_handoffs_dir)/$role"
  ipdir="$inbox/in_process"

  local task_files=() batch_dirs=()
  [ -d "$ipdir" ] || sf_die "no in_process directory for role '$role'"
  task_files=( "$ipdir"/*.handoff )
  batch_dirs=( "$ipdir"/batch_*/ )

  [ "${#batch_dirs[@]}" -eq 0 ] || sf_die "in_process contains a batch; role '$role' is task mode."
  [ "${#task_files[@]}" -eq 1 ] || sf_die "expected exactly one in_process task for role '$role', found ${#task_files[@]}; repair the queue."

  local file="${task_files[0]}"
  sf_stamp "$file" completed_at "$(sf_now_iso)"
  mkdir -p "$inbox/completed"
  local dest="$inbox/completed/$(basename "$file")"
  mv "$file" "$dest"
  printf 'COMPLETED: %s\n' "$dest"

  # Accept the next task (ready_for_next.sh owns queue selection).
  sf_ready_task "$role"
}

# ---------------------------------------------------------------------------
# Batch completion
# ---------------------------------------------------------------------------

sf_done_batch() {
  local role="$1" inbox ipdir
  inbox="$(sf_handoffs_dir)/$role"
  ipdir="$inbox/in_process"

  local task_files=() batch_dirs=()
  [ -d "$ipdir" ] || sf_die "no in_process directory for role '$role'"
  task_files=( "$ipdir"/*.handoff )
  batch_dirs=( "$ipdir"/batch_*/ )

  [ "${#task_files[@]}" -eq 0 ] || sf_die "in_process contains a single task; role '$role' is batch mode."
  [ "${#batch_dirs[@]}" -eq 1 ] || sf_die "expected exactly one in_process batch for role '$role', found ${#batch_dirs[@]}; repair the queue."

  local bdir="${batch_dirs[0]%/}"
  local f
  for f in "$bdir"/*.handoff; do
    [ -e "$f" ] || continue
    sf_stamp "$f" completed_at "$(sf_now_iso)"
    printf 'COMPLETED: %s\n' "$f"
  done
  mkdir -p "$inbox/completed"
  local dest="$inbox/completed/$(basename "$bdir")"
  mv "$bdir" "$dest"
  printf 'COMPLETED BATCH: %s\n' "$dest"

  # Accept the next batch.
  sf_ready_batch "$role"
}

# ---------------------------------------------------------------------------
# Dispatch (only when executed directly)
# ---------------------------------------------------------------------------

sf_main_done() {
  local role="${1:-${SWARMFORGE_ROLE:-}}"
  [ -n "$role" ] || sf_die "usage: done_with_current.sh <role>  (or set SWARMFORGE_ROLE)"
  local mode
  mode="$(sf_role_mode "$role")"
  case "$mode" in
    task) sf_done_task "$role" ;;
    batch) sf_done_batch "$role" ;;
    *) sf_die "unknown receive mode '$mode' for role '$role' in $(sf_roles_tsv)" ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  sf_main_done "$@"
fi
