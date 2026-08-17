#!/usr/bin/env bash
# Reconstruct the acceptance suite from a throwaway copy of the current source.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
worktree="$root/tmp/acceptance-fresh"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
uv_bin="$(command -v uv || true)"
if [[ -z "$uv_bin" ]]; then
  echo "uv is not available on PATH" >&2
  exit 1
fi

cleanup() {
  rm -rf "$worktree"
}
trap cleanup EXIT

rm -rf "$worktree"
mkdir -p "$worktree"

rsync -a \
  --exclude '.git/' \
  --exclude 'build/' \
  --exclude 'tmp/' \
  --exclude 'output/' \
  --exclude '.venv/' \
  --exclude '.beads/' \
  --exclude '.swarmforge/' \
  --exclude '.factory/swarmforge/aps/' \
  --exclude 'acceptance/ir/' \
  --exclude 'acceptance/generated/' \
  --exclude '__pycache__/' \
  --exclude '.pytest_cache/' \
  "$root/" "$worktree/"

rm -rf "$worktree/acceptance/ir" "$worktree/acceptance/generated"

if [[ -e "$worktree/acceptance/ir" || -e "$worktree/acceptance/generated" ]]; then
  echo "fresh checkout still contains committed generated artifacts" >&2
  exit 1
fi

aps=""
for candidate in \
  "$root/tmp/Acceptance-Pipeline-Specification" \
  "$root/.factory/swarmforge/aps"
do
  if [[ -d "$candidate" ]]; then
    aps="$candidate"
    break
  fi
done
if [[ -z "$aps" ]]; then
  echo "Acceptance-Pipeline-Specification clone not found" >&2
  exit 1
fi
mkdir -p "$worktree/.factory/swarmforge"
ln -sfn "$aps" "$worktree/.factory/swarmforge/aps"

source_fingerprint() {
  (
    cd "$worktree"
    find features acceptance scripts CLAUDE.md pyproject.toml \
      -type f \
      ! -path 'acceptance/ir/*' \
      ! -path 'acceptance/generated/*' \
      ! -path '*/__pycache__/*' \
      | sort \
      | xargs shasum
  )
}

before="$(source_fingerprint)"
(
  cd "$worktree"
  uv run python acceptance/refresh_snapshot.py
  set +e
  pytest_output="$(uv run pytest build/acceptance/generated/ -q --tb=no)"
  pytest_status=$?
  set -e
  printf '%s\n' "$pytest_output"
  if [[ "$pytest_output" != *"9 failed"* || "$pytest_output" != *"77 passed"* ]]; then
    echo "unexpected acceptance baseline (want 9 failed / 77 passed)" >&2
    exit 1
  fi
  if [[ "$pytest_status" -eq 0 ]]; then
    echo "acceptance suite unexpectedly passed" >&2
    exit 1
  fi
)
after_first="$(source_fingerprint)"
if [[ "$before" != "$after_first" ]]; then
  echo "fresh generate changed committed source files" >&2
  diff -u <(printf '%s\n' "$before") <(printf '%s\n' "$after_first") >&2 || true
  exit 1
fi

(
  cd "$worktree"
  uv run python acceptance/refresh_snapshot.py
)
after_second="$(source_fingerprint)"
if [[ "$after_first" != "$after_second" ]]; then
  echo "second generate changed committed source files" >&2
  diff -u <(printf '%s\n' "$after_first") <(printf '%s\n' "$after_second") >&2 || true
  exit 1
fi

echo "fresh-checkout acceptance reconstruction passed"
