#!/usr/bin/env bash
# ready_for_next.sh <role>
#
# Accept or resume the next handoff task/batch for <role>. Reads the role's
# receive mode from .swarmforge/roles.tsv (task|batch) and dispatches.
#
# Output:
#   TASK: <path>            a single task is ready (task mode)
#   FROM: / TYPE: / PRIORITY: / TASK_NAME: / PAYLOAD:
#   BATCH: <path>           a batch is ready (batch mode)
#   COUNT: / PRIORITY: / BATCH_ITEM: ...
#   NO_TASK                 nothing queued
#
# Pure shell. No Babashka, no daemon. Adapted from SwarmForge's handoff protocol.
set -euo pipefail
shopt -s nullglob

# ---------------------------------------------------------------------------
# Shared helpers (inlined; also sourced by the done_*.sh and *_batch.sh scripts)
# ---------------------------------------------------------------------------

sf_handoffs_dir() { printf '%s\n' "${SWARMFORGE_HANDOFFS_DIR:-.swarmforge/handoffs}"; }

sf_now_ts() { date -u +%Y%m%dT%H%M%SZ; }
sf_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

sf_die() { printf '%s\n' "$*" >&2; exit 1; }

# Print the value of a header field from a handoff file (headers live before the
# first blank line; the body is opaque).
sf_hget() {
  local file="$1" field="$2"
  awk -v f="$field" '
    /^[[:space:]]*$/ { exit }
    $0 ~ "^" f ":" { sub("^" f ":[[:space:]]*", "", $0); print; exit }
  ' "$file"
}

# Print the body (everything after the first blank line).
sf_body_of() {
  local file="$1"
  awk 'p { print } /^[[:space:]]*$/ { p=1 }' "$file"
}

# Add or replace a reserved header field at the end of the header block.
sf_stamp() {
  local file="$1" field="$2" value="$3"
  local tmp="${file}.stamp.$$"
  awk -v f="$field" -v v="$value" '
    BEGIN { replaced=0; blank=0 }
    blank { print; next }
    /^[[:space:]]*$/ { if (!replaced) { print f ": " v; replaced=1 }; print; blank=1; next }
    $0 ~ "^" f ":" { print f ": " v; replaced=1; next }
    { print }
    END { if (!replaced) print f ": " v }
  ' "$file" > "$tmp" && mv "$tmp" "$file"
}

sf_roles_tsv() { printf '%s\n' "${SWARMFORGE_ROLES_TSV:-.swarmforge/roles.tsv}"; }

# Print the receive mode (task|batch) for a role. Defaults to task.
sf_role_mode() {
  local role="$1" tsv mode
  tsv="$(sf_roles_tsv)"
  if [ -f "$tsv" ]; then
    mode="$(awk -v r="$role" '$1 == r { print $2; found=1; exit } END { if (!found) print "" }' "$tsv")"
    [ -n "$mode" ] && { printf '%s\n' "$mode"; return; }
  fi
  printf '%s\n' task
}

# Sorted list of *.handoff files in a directory (one per line, ascending).
# Prints nothing (not even an empty line) when the directory has no handoffs.
sf_sorted_handoffs() {
  local dir="$1" files=() f
  [ -d "$dir" ] || return 0
  for f in "$dir"/*.handoff; do
    [ -e "$f" ] || continue
    files+=( "$f" )
  done
  [ "${#files[@]}" -gt 0 ] || return 0
  printf '%s\n' "${files[@]}" | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# Task mode
# ---------------------------------------------------------------------------

sf_print_task() {
  local file="$1" from type priority task payload
  from="$(sf_hget "$file" from)"
  type="$(sf_hget "$file" type)"
  priority="$(sf_hget "$file" priority)"
  printf 'TASK: %s\n' "$file"
  printf 'FROM: %s\n' "${from:-}"
  printf 'TYPE: %s\n' "${type:-}"
  printf 'PRIORITY: %s\n' "${priority:-}"
  if [ "$type" = "git_handoff" ]; then
    task="$(sf_hget "$file" task)"
    printf 'TASK_NAME: %s\n' "${task:-}"
  fi
  printf 'PAYLOAD:\n'
  sf_body_of "$file"
}

sf_ready_task() {
  local role="$1" inbox ipdir
  inbox="$(sf_handoffs_dir)/$role"
  ipdir="$inbox/in_process"

  local task_files=() batch_dirs=()
  if [ -d "$ipdir" ]; then
    task_files=( "$ipdir"/*.handoff )
    batch_dirs=( "$ipdir"/batch_*/ )
  fi

  if [ "${#batch_dirs[@]}" -gt 0 ]; then
    sf_die "in_process contains a batch directory; role '$role' is task mode. Run the batch helper or repair the queue."
  fi
  if [ "${#task_files[@]}" -gt 1 ]; then
    sf_die "multiple in_process tasks for role '$role'; repair the queue before accepting new work."
  fi
  if [ "${#task_files[@]}" -eq 1 ]; then
    # Resume the in-process task.
    sf_print_task "${task_files[0]}"
    return 0
  fi

  # Nothing in_process; select the first new/ file by sorted filename.
  local first=""
  while IFS= read -r f; do first="$f"; break; done < <(sf_sorted_handoffs "$inbox/new")
  if [ -z "$first" ]; then
    printf 'NO_TASK\n'
    return 0
  fi
  sf_stamp "$first" dequeued_at "$(sf_now_iso)"
  local dest="$ipdir/$(basename "$first")"
  mkdir -p "$ipdir"
  mv "$first" "$dest"
  sf_print_task "$dest"
}

# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------

sf_print_batch() {
  local bdir="${1%/}" count=0 priority=""
  printf 'BATCH: %s\n' "$bdir"
  for f in "$bdir"/*.handoff; do
    [ -e "$f" ] || continue
    count=$((count + 1))
    [ -z "$priority" ] && priority="$(sf_hget "$f" priority)"
    printf 'BATCH_ITEM: %s\n' "$f"
    printf '  FROM: %s\n' "$(sf_hget "$f" from)"
    printf '  TYPE: %s\n' "$(sf_hget "$f" type)"
    if [ "$(sf_hget "$f" type)" = "git_handoff" ]; then
      printf '  TASK_NAME: %s\n' "$(sf_hget "$f" task)"
    fi
    printf '  PAYLOAD:\n'
    sf_body_of "$f" | sed 's/^/    /'
  done
  printf 'COUNT: %d\n' "$count"
  printf 'PRIORITY: %s\n' "${priority:-}"
}

sf_ready_batch() {
  local role="$1" inbox ipdir
  inbox="$(sf_handoffs_dir)/$role"
  ipdir="$inbox/in_process"

  local task_files=() batch_dirs=()
  if [ -d "$ipdir" ]; then
    task_files=( "$ipdir"/*.handoff )
    batch_dirs=( "$ipdir"/batch_*/ )
  fi

  if [ "${#task_files[@]}" -gt 0 ]; then
    sf_die "in_process contains a single task; role '$role' is batch mode. Run the task helper or repair the queue."
  fi
  if [ "${#batch_dirs[@]}" -gt 1 ]; then
    sf_die "multiple in_process batches for role '$role'; repair the queue before accepting new work."
  fi
  if [ "${#batch_dirs[@]}" -eq 1 ]; then
    sf_print_batch "${batch_dirs[0]}"
    return 0
  fi

  # Nothing in_process; select all new/ files with the same priority as the
  # first (sorted) file and group them into one batch directory.
  local first=""
  while IFS= read -r f; do first="$f"; break; done < <(sf_sorted_handoffs "$inbox/new")
  if [ -z "$first" ]; then
    printf 'NO_TASK\n'
    return 0
  fi
  local target_priority
  target_priority="$(sf_hget "$first" priority)"
  local bdir="$ipdir/batch_$(sf_now_ts)_$$"
  mkdir -p "$bdir"
  local f
  while IFS= read -r f; do
    [ -e "$f" ] || continue
    [ "$(sf_hget "$f" priority)" = "$target_priority" ] || continue
    sf_stamp "$f" dequeued_at "$(sf_now_iso)"
    mv "$f" "$bdir/$(basename "$f")"
  done < <(sf_sorted_handoffs "$inbox/new")
  sf_print_batch "$bdir"
}

# ---------------------------------------------------------------------------
# Dispatch (only when executed directly, not when sourced)
# ---------------------------------------------------------------------------

sf_main_ready() {
  local role="${1:-${SWARMFORGE_ROLE:-}}"
  [ -n "$role" ] || sf_die "usage: ready_for_next.sh <role>  (or set SWARMFORGE_ROLE)"
  local mode
  mode="$(sf_role_mode "$role")"
  case "$mode" in
    task) sf_ready_task "$role" ;;
    batch) sf_ready_batch "$role" ;;
    *) sf_die "unknown receive mode '$mode' for role '$role' in $(sf_roles_tsv)" ;;
  esac
}

# When sourced by another script, do not dispatch.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  sf_main_ready "$@"
fi
