#!/usr/bin/env bash
# swarm_handoff.sh <role> <draft-file>
#
# Validate an outbound handoff draft and deliver it directly to each recipient's
# inbox (no daemon, no outbox staging). Keeps a sent/ audit copy for the sender.
#
# Draft format (headers only; the body is generated):
#   git_handoff:
#     type: git_handoff
#     to: <role>[,<role>...]
#     priority: NN
#     task: <short-stable-task-name>
#     commit: <10-character-commit-abbrev>
#   note:
#     type: note
#     to: <role>[,<role>...]
#     priority: NN
#     message: <one line, max 80 chars>
#
# On success: prints SENT: and DELIVERED: lines and removes the draft.
# On validation error: prints HANDOFF INVALID with repair guidance and exits 1
# without writing anything.
#
# Pure shell. No Babashka, no daemon. Adapted from SwarmForge's handoff protocol.
set -euo pipefail

SF_HANDOFFS_DIR="${SWARMFORGE_HANDOFFS_DIR:-.swarmforge/handoffs}"
SF_ROLES_TSV="${SWARMFORGE_ROLES_TSV:-.swarmforge/roles.tsv}"
RESERVED='id from role recipient created_at enqueued_at dequeued_at completed_at'

sf_die() { printf '%s\n' "$*" >&2; exit 1; }
sf_now_ts() { date -u +%Y%m%dT%H%M%SZ; }
sf_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Read a header field from a file (headers before the first blank line).
sf_get() {
  local file="$1" field="$2"
  awk -v f="$field" '
    /^[[:space:]]*$/ { exit }
    $0 ~ "^" f ":" { sub("^" f ":[[:space:]]*", "", $0); print; exit }
  ' "$file"
}

# Monotonic per-sender sequence, mkdir-locked (portable; no flock).
sf_next_seq() {
  local dir="$1"
  local lockdir="$dir/.seq.lock"
  local seqfile="$dir/.seq"
  mkdir -p "$dir"
  local i=0
  while ! mkdir "$lockdir" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 200 ] && sf_die "sequence lock timeout in $dir"
    sleep 0.05
  done
  local seq=0
  [ -f "$seqfile" ] && read -r seq < "$seqfile" 2>/dev/null || seq=0
  seq=$((seq + 1))
  printf '%s\n' "$seq" > "$seqfile"
  rmdir "$lockdir" 2>/dev/null || true
  printf '%06d\n' "$seq"
}

# Print all known roles (one per line) from roles.tsv.
sf_known_roles() {
  [ -f "$SF_ROLES_TSV" ] || return 0
  awk '{ print $1 }' "$SF_ROLES_TSV"
}

sf_is_known_role() {
  local r="$1" known
  while IFS= read -r known; do
    [ "$known" = "$r" ] && return 0
  done < <(sf_known_roles)
  return 1
}

# Canonicalize a 10-hex commit abbreviation. Print the 10-char canonical form,
# or empty + return 1 if it does not resolve to exactly one commit.
sf_canonical_commit() {
  local abbrev="$1" full
  if ! [[ "$abbrev" =~ ^[0-9a-f]{10}$ ]]; then
    printf '%s\n' "not 10 hexadecimal characters"
    return 1
  fi
  if ! full="$(git rev-parse --verify --quiet "${abbrev}^{commit}" 2>/dev/null)"; then
    printf '%s\n' "does not resolve to a commit"
    return 1
  fi
  printf '%s\n' "${full:0:10}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  local role="${1:-${SWARMFORGE_ROLE:-}}"
  local draft="${2:-}"
  [ -n "$role" ] && [ -n "$draft" ] || sf_die "usage: swarm_handoff.sh <role> <draft-file>  (or set SWARMFORGE_ROLE and pass <draft-file>)"
  [ -f "$draft" ] || sf_die "draft file not found: $draft"
  [ -f "$SF_ROLES_TSV" ] || sf_die "roles.tsv not found at $SF_ROLES_TSV; run /swarmforge-setup first"

  local errors=""
  add_err() { errors="${errors}- $1"$'\n'; }

  # --- required fields ------------------------------------------------------
  local type to priority
  type="$(sf_get "$draft" type)"
  to="$(sf_get "$draft" to)"
  priority="$(sf_get "$draft" priority)"

  [ -n "$type" ] || add_err "missing required header 'type'"
  if [ -n "$type" ]; then
    case "$type" in
      git_handoff|note) : ;;
      *) add_err "'type' must be git_handoff or note; got '$type'" ;;
    esac
  fi
  [ -n "$to" ] || add_err "missing required header 'to'"
  [ -n "$priority" ] || add_err "missing required header 'priority'"
  if [ -n "$priority" ] && ! [[ "$priority" =~ ^[0-9][0-9]$ ]]; then
    add_err "'priority' must be two digits from 00 to 99; got '$priority'"
  fi

  # --- reserved headers must not be present ---------------------------------
  local r
  for r in $RESERVED; do
    if grep -qE "^${r}:" "$draft"; then
      add_err "header '$r' is reserved and must not be written by agents"
    fi
  done

  # --- recipients -----------------------------------------------------------
  local recipients=()
  if [ -n "$to" ]; then
    local IFS=','
    # shellcheck disable=SC2206
    recipients=( $to )
    local rcpt
    for rcpt in "${recipients[@]}"; do
      rcpt="${rcpt## }"; rcpt="${rcpt%% }"
      sf_is_known_role "$rcpt" || add_err "recipient '$rcpt' is not a known role in $SF_ROLES_TSV"
    done
  fi

  # --- type-specific fields -------------------------------------------------
  local task="" commit="" canonical="" message=""
  if [ "$type" = "git_handoff" ]; then
    task="$(sf_get "$draft" task)"
    [ -n "$task" ] || add_err "git_handoff requires a 'task' header (short stable task name)"
    commit="$(sf_get "$draft" commit)"
    if [ -n "$commit" ]; then
      local cmsg
      if canonical="$(sf_canonical_commit "$commit")"; then
        : # ok
      else
        cmsg="$(sf_canonical_commit "$commit" 2>/dev/null || true)"
        add_err "commit '$commit' is invalid: ${cmsg}; use exactly 10 hex characters that resolve to one commit"
      fi
    else
      add_err "git_handoff requires a 'commit' header (10-character commit abbrev)"
    fi
  elif [ "$type" = "note" ]; then
    message="$(sf_get "$draft" message)"
    [ -n "$message" ] || add_err "note requires a 'message' header"
    if [ -n "$message" ]; then
      local line count
      line="$(printf '%s' "$message" | head -n1)"
      [ "$line" = "$message" ] || add_err "'message' must be a single line"
      count="$(printf '%s' "$message" | wc -c | tr -d ' ')"
      [ "$count" -le 80 ] || add_err "'message' must be at most 80 characters; got $count"
    fi
  fi

  if [ -n "$errors" ]; then
    printf 'HANDOFF INVALID: %s\n\nErrors:\n' "$draft" >&2
    printf '%s' "$errors" >&2
    printf 'Expected git_handoff format:\n\ntype: git_handoff\nto: <role>[,<role>...]\npriority: NN\ntask: <short-stable-task-name>\ncommit: <10-character-commit-abbrev>\n\nExpected note format:\n\ntype: note\nto: <role>[,<role>...]\npriority: NN\nmessage: <one line, max 80 chars>\n' >&2
    exit 1
  fi

  # --- build the handoff ----------------------------------------------------
  local ts iso seq id
  ts="$(sf_now_ts)"
  iso="$(sf_now_iso)"
  seq="$(sf_next_seq "$SF_HANDOFFS_DIR/$role")"
  id="${ts}_${seq}_from_${role}"

  local to_list
  to_list="$(printf '%s\n' "${recipients[@]}" | paste -sd, -)"
  local to_file
  to_file="$(printf '%s\n' "${recipients[@]}" | paste -sd_ -)"

  local fname="${priority}_${ts}_${seq}_from_${role}_to_${to_file}.handoff"

  # Header block (canonical; reserved fields generated here).
  local header=""
  header+="id: ${id}"$'\n'
  header+="from: ${role}"$'\n'
  header+="to: ${to_list}"$'\n'
  header+="priority: ${priority}"$'\n'
  header+="type: ${type}"$'\n'
  if [ "$type" = "git_handoff" ]; then
    header+="role: ${role}"$'\n'
    header+="task: ${task}"$'\n'
    header+="commit: ${canonical}"$'\n'
  else
    header+="message: ${message}"$'\n'
  fi
  header+="created_at: ${iso}"$'\n'

  # Generated body.
  local body=""
  body+="Re-read your role and AGENTS.md."$'\n\n'
  if [ "$type" = "git_handoff" ]; then
    body+="merge_and_process ${role} ${canonical}"$'\n'
  else
    body+="${message}"$'\n'
  fi

  # --- write the sent/ audit copy ------------------------------------------
  local sent_dir="$SF_HANDOFFS_DIR/$role/sent"
  mkdir -p "$sent_dir"
  local sent_path="$sent_dir/$fname"
  printf '%s\n%s\n' "$header" "$body" > "$sent_path.tmp.$$"
  mv "$sent_path.tmp.$$" "$sent_path"

  # --- deliver to each recipient new/ --------------------------------------
  local rcpt
  for rcpt in "${recipients[@]}"; do
    rcpt="${rcpt## }"; rcpt="${rcpt%% }"
    local new_dir="$SF_HANDOFFS_DIR/$rcpt/new"
    mkdir -p "$new_dir"
    local dest="$new_dir/$fname"
    {
      printf '%s' "$header"
      printf 'recipient: %s\n' "$rcpt"
      printf 'enqueued_at: %s\n' "$iso"
      printf '\n%s' "$body"
    } > "$dest.tmp.$$"
    mv "$dest.tmp.$$" "$dest"
    printf 'DELIVERED: %s: %s\n' "$rcpt" "$dest"
  done

  printf 'SENT: %s\n' "$sent_path"

  # Remove the draft on success (use rm, not rm -f, per protocol).
  rm "$draft"
}

main "$@"
