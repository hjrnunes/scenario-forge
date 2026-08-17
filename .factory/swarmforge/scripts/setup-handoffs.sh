#!/usr/bin/env bash
# setup-handoffs.sh [language]
#
# Initialize a project for the swarmforge-droid pipeline. Self-locates its
# sibling scripts and the ../templates directory via $0, so it can be run in
# place from the installed plugin.
#
# Steps:
#   1. Copy helper scripts to .factory/swarmforge/scripts/ (chmod +x).
#   2. Detect installed role droids from .factory/droids/*.md.
#   3. Create <runtime-root>/handoffs/<role>/{new,in_process,completed,sent,failed}/,
#      <runtime-root>/reports/, and acceptance-pipeline directories
#      (features/, build/acceptance/{ir,dry,generated}/, build/acceptance-mutation/).
#   4. Write <runtime-root>/roles.tsv (receive mode per role).
#   5. Write .factory/swarmforge/config.sh with defaults (if absent).
#   6. Copy AGENTS.md.template to AGENTS.md (if absent); if a language argument
#      is given, uncomment that language section in the fresh copy.
#   7. Append <runtime-root>/ and acceptance dirs (by file policy) to .gitignore.
#   8. Print next steps.
#
# The runtime root defaults to .swarmforge but can be set to .swarmforge-droid
# (or any path) via SWARMFORGE_RUNTIME_ROOT for coexistence with original
# SwarmForge. Acceptance-pipeline paths default to features/ and build/acceptance/*
# but are overridable via SWARMFORGE_FEATURES_DIR, SWARMFORGE_ACCEPTANCE_*_DIR.
# File policy defaults to generated-output (gitignored); set to committed-snapshot
# to commit generated artifacts. Pure shell. Idempotent.
set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATES_DIR="$PLUGIN_ROOT/templates"

# Source project config if available (preserves runtime root on re-runs).
# An explicit env var takes precedence over the config value.
_sf_env_rtr="${SWARMFORGE_RUNTIME_ROOT:-}"
_sf_env_fp="${SWARMFORGE_FILE_POLICY:-}"
for _cfg in .factory/swarmforge/config.sh "${FACTORY_PROJECT_DIR:-}/.factory/swarmforge/config.sh"; do
  [ -f "$_cfg" ] && . "$_cfg" && break
done
[ -n "$_sf_env_rtr" ] && SWARMFORGE_RUNTIME_ROOT="$_sf_env_rtr"
[ -n "$_sf_env_fp" ] && SWARMFORGE_FILE_POLICY="$_sf_env_fp"

LANG_ARG="${1:-}"
RUNTIME_ROOT="${SWARMFORGE_RUNTIME_ROOT:-.swarmforge}"
HANDOFFS_DIR="${SWARMFORGE_HANDOFFS_DIR:-$RUNTIME_ROOT/handoffs}"
SCRIPTS_DEST=".factory/swarmforge/scripts"
CONFIG_DEST=".factory/swarmforge/config.sh"
ROLES_TSV="${SWARMFORGE_ROLES_TSV:-$RUNTIME_ROOT/roles.tsv}"
REPORTS_DIR="${SWARMFORGE_REPORTS_DIR:-$RUNTIME_ROOT/reports}"

# Acceptance-pipeline path defaults (Plan C: explicit, overridable).
FEATURES_DIR="${SWARMFORGE_FEATURES_DIR:-features}"
ACCEPTANCE_IR_DIR="${SWARMFORGE_ACCEPTANCE_IR_DIR:-build/acceptance/ir}"
ACCEPTANCE_DRY_DIR="${SWARMFORGE_ACCEPTANCE_DRY_DIR:-build/acceptance/dry}"
ACCEPTANCE_GENERATED_DIR="${SWARMFORGE_ACCEPTANCE_GENERATED_DIR:-build/acceptance/generated}"
ACCEPTANCE_MUTATION_DIR="${SWARMFORGE_ACCEPTANCE_MUTATION_DIR:-build/acceptance-mutation}"
FILE_POLICY="${SWARMFORGE_FILE_POLICY:-generated-output}"

BATCH_ROLES=" cleaner architect hardender qa "
ALWAYS_ROLES="specifier coder cleaner"

log() { printf '[swarmforge] %s\n' "$*"; }
die() { printf '[swarmforge] error: %s\n' "$*" >&2; exit 1; }

# Add a role to an array only if not already present. Uses a global
# SF_ROLES_ACCUM newline-separated string for dedup.
SF_ROLES_ACCUM=""
sf_add_role() {
  local r="$1"
  case "$SF_ROLES_ACCUM" in
    *"|$r|"*) : ;;
    *) SF_ROLES_ACCUM="${SF_ROLES_ACCUM}|${r}|" ;;
  esac
}

# Render the AGENTS.md template into $2, uncommenting the $1 language section
# (case-insensitive). With an empty $1, copy the template verbatim. No-op
# (empty output) if the template file is missing.
sf_render_template() {
  local target_lang="$1" out="$2"
  if [ -n "$target_lang" ] && [ -f "$TEMPLATES_DIR/AGENTS.md.template" ]; then
    awk -v target="LANGUAGE: $target_lang" '
      state == 0 && /^<!-- LANGUAGE: / {
        if (index(tolower($0), tolower(target)) > 0) { state = 1; next }
        else { state = 2; print; next }
      }
      state == 1 { if ($0 == "-->") { state = 0; next }; print; next }
      state == 2 { print; if ($0 == "-->") state = 0; next }
      { print }
    ' "$TEMPLATES_DIR/AGENTS.md.template" > "$out"
  elif [ -f "$TEMPLATES_DIR/AGENTS.md.template" ]; then
    cp "$TEMPLATES_DIR/AGENTS.md.template" "$out"
  fi
}

# Merge SwarmForge managed blocks from rendered template $1 into existing
# AGENTS.md $2: strip any existing <!-- BEGIN/END swarmforge: ... --> blocks
# from the existing file, then append the current blocks from the rendered
# template. Existing project sections are preserved; managed blocks are
# idempotent (re-running updates them in place).
sf_merge_agents() {
  local rendered="$1" existing="$2" tmp
  tmp="$(mktemp)"
  awk '/^<!-- BEGIN swarmforge: /{skip=1;next} /^<!-- END swarmforge: /{skip=0;next} !skip{print}' \
    "$existing" > "$tmp"
  printf '\n' >> "$tmp"
  awk '/^<!-- BEGIN swarmforge: /{on=1} on{print} /^<!-- END swarmforge: /{on=0}' \
    "$rendered" >> "$tmp"
  mv "$tmp" "$existing"
}

# ---------------------------------------------------------------------------
# 1. Copy scripts
# ---------------------------------------------------------------------------
mkdir -p "$SCRIPTS_DEST"
copied=0
for s in "$SCRIPT_DIR"/*.sh; do
  [ -e "$s" ] || continue
  cp "$s" "$SCRIPTS_DEST/$(basename "$s")"
  chmod +x "$SCRIPTS_DEST/$(basename "$s")"
  copied=$((copied + 1))
done
log "copied $copied script(s) to $SCRIPTS_DEST"

# ---------------------------------------------------------------------------
# 2. Detect installed droids
# ---------------------------------------------------------------------------
installed=()
if [ -d ".factory/droids" ]; then
  for d in .factory/droids/*.md; do
    [ -e "$d" ] || continue
    installed+=( "$(basename "$d" .md)" )
  done
fi
if [ "${#installed[@]}" -gt 0 ]; then
  log "detected droids: $(printf '%s ' "${installed[@]}")"
else
  log "no droids detected in .factory/droids/ yet (two-pack baseline will be created)"
fi

# Build the role set: installed roles + always-present baseline.
SF_ROLES_ACCUM=""
for r in "${installed[@]:-}"; do [ -n "$r" ] && sf_add_role "$r"; done
for r in $ALWAYS_ROLES; do sf_add_role "$r"; done
# Render the accum into an array.
all_roles=()
rest="$SF_ROLES_ACCUM"
while [ -n "$rest" ]; do
  rest="${rest#|}"
  r="${rest%%|*}"
  rest="${rest#*|}"
  [ -n "$r" ] && all_roles+=( "$r" )
done

# ---------------------------------------------------------------------------
# 3. Create handoff directories
# ---------------------------------------------------------------------------
for r in "${all_roles[@]}"; do
  for sub in new in_process completed sent failed; do
    mkdir -p "$HANDOFFS_DIR/$r/$sub"
  done
done
mkdir -p "$REPORTS_DIR"
log "created handoff directories for: $(printf '%s ' "${all_roles[@]}")"

# Create acceptance-pipeline default directories.
mkdir -p "$FEATURES_DIR" "$ACCEPTANCE_IR_DIR" "$ACCEPTANCE_DRY_DIR" \
         "$ACCEPTANCE_GENERATED_DIR" "$ACCEPTANCE_MUTATION_DIR"
log "created acceptance-pipeline directories (features, ir, dry, generated, mutation)"

# ---------------------------------------------------------------------------
# 4. Write roles.tsv (mode per role)
# ---------------------------------------------------------------------------
{
  for r in "${all_roles[@]}"; do
    mode=task
    case "$BATCH_ROLES" in
      *" $r "*) mode=batch ;;
    esac
    printf '%s\t%s\n' "$r" "$mode"
  done
} > "$ROLES_TSV"
log "wrote $ROLES_TSV"

# ---------------------------------------------------------------------------
# 5. Write config.sh (defaults only if absent)
# ---------------------------------------------------------------------------
if [ ! -f "$CONFIG_DEST" ]; then
  mkdir -p "$(dirname "$CONFIG_DEST")"
  cat > "$CONFIG_DEST" <<'EOF'
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
SWARMFORGE_GENERATION_CMD=""          # set by the scaffolder (e.g., ./scripts/acceptance.sh)
SWARMFORGE_FILE_POLICY="generated-output"  # committed-snapshot | generated-output
SWARMFORGE_LANGUAGE=""
SWARMFORGE_TOOLS_CONSENT=""    # given | declined (set by /swarmforge-setup or orchestrator)
SWARMFORGE_BEADS=false          # true | false (set by /swarmforge-setup; orchestrator uses Beads when .beads/ is present and this is true)
SWARMFORGE_SPEC_REVIEW=false    # true | false (operator opt-in; true = orchestrator asks for spec approval before coding)
SWARMFORGE_TEST_CMD=""
SWARMFORGE_ACCEPTANCE_CMD=""
SWARMFORGE_QA_CMD=""
SWARMFORGE_COVERAGE_CMD=""      # generates lcov.info for LCOV-consuming tools (Python: crap4py, mutate4py)
SWARMFORGE_CRAP_CMD=""
SWARMFORGE_DRY_CMD=""
SWARMFORGE_MUTATION_CMD=""      # language mutation tool invocation (hardender)
SWARMFORGE_CRAP_THRESHOLD=6
SWARMFORGE_MUTATION_SCORE_MIN=80
SWARMFORGE_MUTATION_SITES_MAX=100
EOF
  log "wrote $CONFIG_DEST (defaults — fill in your commands)"
else
  log "kept existing $CONFIG_DEST"
fi

# If a non-default runtime root was requested, update the generated config.
if [ "$RUNTIME_ROOT" != ".swarmforge" ] && [ -f "$CONFIG_DEST" ]; then
  _tmp_cfg="$(mktemp)"
  sed "s|^SWARMFORGE_RUNTIME_ROOT=.*|SWARMFORGE_RUNTIME_ROOT=\"$RUNTIME_ROOT\"|" "$CONFIG_DEST" > "$_tmp_cfg" && mv "$_tmp_cfg" "$CONFIG_DEST"
  log "set runtime root to $RUNTIME_ROOT in $CONFIG_DEST"
fi

# If a non-default file policy was requested, update the generated config.
if [ "$FILE_POLICY" != "generated-output" ] && [ -f "$CONFIG_DEST" ]; then
  _tmp_fp="$(mktemp)"
  sed "s|^SWARMFORGE_FILE_POLICY=.*|SWARMFORGE_FILE_POLICY=\"$FILE_POLICY\"|" "$CONFIG_DEST" > "$_tmp_fp" && mv "$_tmp_fp" "$CONFIG_DEST"
  log "set file policy to $FILE_POLICY in $CONFIG_DEST"
fi

# ---------------------------------------------------------------------------
# 6. AGENTS.md: create from template, or merge managed blocks into existing.
# ---------------------------------------------------------------------------
if [ ! -f "AGENTS.md" ]; then
  if [ -f "$TEMPLATES_DIR/AGENTS.md.template" ]; then
    sf_render_template "$LANG_ARG" "AGENTS.md"
    if [ -n "$LANG_ARG" ]; then
      log "created AGENTS.md from template (language section '$LANG_ARG' uncommented)"
    else
      log "created AGENTS.md from template (all language sections left commented — uncomment one)"
    fi
  else
    log "warning: AGENTS.md.template not found in $TEMPLATES_DIR; skipped AGENTS.md"
  fi
else
  if [ -f "$TEMPLATES_DIR/AGENTS.md.template" ]; then
    rendered="$(mktemp)"
    sf_render_template "$LANG_ARG" "$rendered"
    sf_merge_agents "$rendered" "AGENTS.md"
    rm -f "$rendered"
    log "merged SwarmForge managed sections into existing AGENTS.md (project sections preserved)"
  else
    log "kept existing AGENTS.md (template not found at $TEMPLATES_DIR)"
  fi
fi

# ---------------------------------------------------------------------------
# 7. .gitignore — runtime root + acceptance dirs by file policy
# ---------------------------------------------------------------------------
# Runtime root (always gitignored).
if ! grep -qx "$RUNTIME_ROOT/" .gitignore 2>/dev/null; then
  printf '%s/\n' "$RUNTIME_ROOT" >> .gitignore
  log "added $RUNTIME_ROOT/ to .gitignore"
fi

# Mutation workspace is always ephemeral.
if ! grep -qx "$ACCEPTANCE_MUTATION_DIR/" .gitignore 2>/dev/null; then
  printf '%s/\n' "$ACCEPTANCE_MUTATION_DIR" >> .gitignore
  log "added $ACCEPTANCE_MUTATION_DIR/ to .gitignore"
fi

# In generated-output mode, IR/dry/generated are ephemeral too.
# In committed-snapshot mode, those are committed to git and NOT ignored.
if [ "$FILE_POLICY" = "generated-output" ]; then
  for _dir in "$ACCEPTANCE_IR_DIR" "$ACCEPTANCE_DRY_DIR" "$ACCEPTANCE_GENERATED_DIR"; do
    if ! grep -qx "$_dir/" .gitignore 2>/dev/null; then
      printf '%s/\n' "$_dir" >> .gitignore
    fi
  done
  log "added acceptance ir/dry/generated to .gitignore (generated-output policy)"
fi

# ---------------------------------------------------------------------------
# 8. Next steps
# ---------------------------------------------------------------------------
cat <<EOF

[swarmforge] setup complete.

Next steps:
  1. Install the role droids you want into .factory/droids/ to choose a pack:
       two-pack  = coder, cleaner
       four-pack = specifier, coder, cleaner, architect
       six-pack  = specifier, coder, cleaner, architect, hardender, qa
     The scaffolder droid is a conditional bootstrap role — install it
     alongside any pack to have the acceptance pipeline infrastructure built
     automatically before the first code phase. It does not affect pack
     detection and is not part of the per-feature rotation.
     (Copy the matching droids/*.md from the plugin, or run /swarmforge-setup
     again after copying them to refresh roles.tsv and handoff directories.)
  2. Edit .factory/swarmforge/config.sh and fill in your project's test,
     acceptance, QA, CRAP, and DRY commands.
  3. Edit AGENTS.md: fill REPLACE_ME placeholders and uncomment one language
     section.
  4. Quality tools (CRAP, DRY, mutation, and APS gherkin-parser/
     gherkin-ir-dry-checker/gherkin-mutator) are procured from
     github.com/unclebob/... (and github.com/gabadi/... for the Python ports)
     per your language. Run /swarmforge-setup <lang> to procure them with
     consent, or the orchestrator will ask before the first tool-needing role
     runs. Optional Droid-skill aids (tdd, decomplect, code-review,
     security-review) are not required.
  5. Ask Droid to implement a feature. The swarmforge-orchestrator skill will
     detect your pack and drive the pipeline.

EOF
