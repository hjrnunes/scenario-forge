# OpenCode Mayor Adapter

This file adapts this repository's existing Mayor Method for OpenCode. It is
an overlay, not a replacement for the Claude Code workflow. Do not change
`ai/bootstrap.md` or reinterpret its instructions for Claude Code.

## Start an OpenCode Mayor

Switch to the Mayor agent (Tab → select "mayor"), then:

```text
Read, in order:
1. AGENTS.md and the output of `bd prime`
2. ai/opencode-mayor.md
3. ai/dispatch-prompt-template.md
4. ai/dashboard.md

Perform one Mayor pass. Do not implement a bead in the Mayor thread.
Present the proposed dispatch plan before starting workers.
```

The Mayor coordinates rather than implements. It owns tracker state,
dispatches bounded work, reviews results and diffs, surfaces operator decisions,
and keeps the shared dashboard current. Start a fresh Mayor session for a new
initiative or when the current session becomes noisy; Beads, the dashboard,
PRs, and worker child sessions provide the handoff.

The project stance is stored in Beads memories. Inject it into every dispatch.
At present: pre-alpha, correctness-first, no backwards-compatibility obligation,
LLM API calls may run freely during evaluation, no PII, experiments and
notebooks are scratch artifacts, and merge-on-green applies when the operator
has authorized merging.

## OpenCode Overrides

These rules override conflicting operational details in the reusable dispatch
template when the Mayor or worker is running in OpenCode:

- Dispatch workers via the Task tool. The Mayor selects a worker subagent
  (`worker-quick`, `worker-standard`, or `worker-deep`) based on task
  complexity. The Task tool creates a child session; the worker runs in that
  session with its assigned worktree.
- The Mayor creates a dedicated git worktree for each worker before
  dispatching. Use `git worktree add` with a unique path and branch. Pass the
  worktree path in the dispatch prompt.
- Do not install a recurring Mayor heartbeat. Work advances when a worker
  replies or the operator asks for a Mayor pass.
- The Mayor owns all Beads mutations: claim, notes, dependencies, follow-up
  creation, and closure. Workers do not run commands that mutate Beads.
- Editing workers have standing authority to commit to their assigned branch,
  push that branch, and open or update its PR. A dispatch only needs to mention
  authority when restricting this SOP (for example, a read-only audit).
- Workers never merge, push the default branch, rewrite shared history, delete
  branches or worktrees, or modify Beads. Worker branch/PR authority does not
  grant any of those operations. Bash permissions enforce this at the
  platform level: `git push origin master*`, `gh pr merge*`, `git rebase*`,
  and `git reset --hard*` are denied.
- Workers can spawn the built-in Explore and Scout subagents via the Task tool
  for read-only research (codebase grep, external docs). They cannot spawn
  other workers or the reviewer.
- Treat a code surface as occupied regardless of whether its owner is OpenCode,
  Amp, Claude Code, or a human.
- Run `bd prime` at the start of every Mayor pass to refresh tracker context.
  This replaces the Claude Code SessionStart hook.

## Worker Tier Selection

| Tier | Agent | Model | When to use |
|------|-------|-------|-------------|
| Quick | `worker-quick` | Claude Haiku 4.5 | Trivial single-file tasks, YAML edits, doc fixes, mechanical renames. <50 LoC. |
| Standard | `worker-standard` | Gemini 3.5 Flash | Single-module implementation, bug fix with clear repro. 50-250 LoC. |
| Deep | `worker-deep` | Claude Opus 4.6 | Multi-file logic, schema design, contract implementation. 250+ LoC. |

Default to `worker-standard` when unsure. Escalate to `worker-deep` when the
bead touches >1 module or introduces a new schema/model. A correction pass on
a returned PR uses the same tier as the original dispatch, unless the Mayor
diagnoses that the failure was due to insufficient model capability.

The reviewer agent (`reviewer`, Gemini 3.1 Pro Preview) is used for QA fan-out
and second opinions on complex diffs. It is read-only and cannot edit files
or dispatch subagents.

## One Mayor Pass

A Mayor pass is bounded and idempotent:

1. Run `bd prime`; inspect ready and in-progress work.
2. Inspect worker child sessions, open PRs, CI, git worktrees, and repository
   status.
3. Reconcile the dashboard with actual state.
4. Review completed worker diffs and checks. Merge only when authorized and
   green; otherwise surface the precise decision or failure.
5. Close verifiably completed beads and record concrete commit/PR references.
6. Propose new dispatches only for ready work on unoccupied surfaces.
7. If nothing is actionable, report that the project is quiescent and stop.

Run a pass at session start, when a worker replies, after a merge, before a
handoff, or when the operator explicitly asks.

## Dispatch a Worker

After the operator approves the proposed dispatch plan, the Mayor performs the
entire launch sequence. Do not ask the operator to repeat the standing worker
commit/push/PR authority.

For each worker, the Mayor first completes these shared prerequisites:

1. Read the bead and relevant memories and verify the reported work has not
   already landed.
2. Check in-progress beads, the dashboard, open PRs, and worktrees for surface
   collisions.
3. Claim the bead.
4. Select the worker tier based on task complexity (see Worker Tier Selection).
5. Create a dedicated git worktree for the worker:

   ```bash
   git worktree add ../scenario-forge-workers/<bead> -b worker/<bead> HEAD
   ```

   For an existing branch with no worktree:

   ```bash
   git worktree add ../scenario-forge-workers/<bead> worker/<bead>
   ```

   Inspect `git worktree list` and the dashboard before creating a worktree to
   avoid collisions. Do not reuse an occupied worktree.

6. Run `uv sync` in the assigned worktree. Never share the Mayor checkout's
   `.venv` with a worker worktree.
7. Invoke the selected worker subagent via the Task tool. Put the complete
   dispatch contract in the Task tool's prompt parameter. Explicitly ask the
   worker to reply to the Mayor when it finishes.
8. Record the runtime (OpenCode), worker tier, assigned surface, worktree,
   branch, and state in the bead notes and dashboard.

Each concurrently editing worker needs a separate worktree. Never dispatch an
editing worker into the Mayor checkout.

## Dispatch Contract

Use the solo, cluster, audit, CI-fix, experiment, and paper-exploration shapes
from `ai/dispatch-prompt-template.md`. Every worker brief must include:

- the bead's verbatim ID and title;
- the project stance;
- a concrete outcome, relevant context, and file/line references;
- allowed write surface and explicit non-goals;
- the assigned worktree path (absolute);
- other in-flight workers and their occupied surfaces;
- the worktree boundary block from `ai/dispatch-prompt-template.md`, pasted
  verbatim with the worktree path and Mayor checkout path filled in;
- exact verification commands, including the transitive affected surface;
- the standing instruction to commit coherent changes, push only the assigned
  branch, and open or update its PR; read-only jobs explicitly override this;
- a prohibition on merging and mutating Beads;
- an instruction to reply to the Mayor when finished.

The worker agent's system prompt already contains the general worktree
boundary rules, quality gates, authority/prohibitions, and final report format.
The dispatch contract provides the specific task details.

Require this final report:

```text
Outcome:
Branch:
Commit(s):
PR:
Files changed:
Checks run and results:
Risks or unresolved questions:
Suggested follow-up beads:
```

The report is a handoff, not proof. The Mayor inspects the diff, actual check
results, PR state, and affected surface before accepting it. The Mayor decides
whether suggested follow-ups become beads.

## Read-Only Fan-Out and QA

Use the Task tool to dispatch the `reviewer` subagent for bounded read-only
work that benefits from parallel contexts, such as independent audits, artifact
comparison, or QA batches.

Do not use parallel Task calls to edit overlapping source files. Editing work
belongs in a dedicated worker worktree. Use the `reviewer` for a difficult
review, design trade-off, or second opinion, not as a second Mayor.

### Full QA thread

Full pipeline QA is a special read-only job, not an editing worker. It does
not create a branch, commit, push, open a PR, merge, or mutate Beads. Its only
durable write is the requested gitignored report under `ai/findings/`;
temporary batch-result files are allowed there and must be removed after
successful synthesis.

The Mayor launches and owns the QA pass end to end:

1. Verify generation has finished, the eval scorecard is current, and the
   capability profile and complete scenario set exist. QA must not race a
   pipeline still writing the run.
2. Select a new report path. If that path already exists, ask whether to
   overwrite it or use a new version suffix; never silently replace prior QA.
3. Partition the actual scenario inventory into the configured threat batches
   (A-T2T3, B-T7a, C-T7b, D-T8, E-T9, F-T10, G-T15). Each scenario must appear
   in exactly one batch.
4. Dispatch one `reviewer` Task call per batch. Give each reviewer the exact
   file list, the batch assignment, the quality assessment checklist at
   `ai/extended-context/quality-assessment-checklist.md`, and a temporary
   batch-result file path under `ai/findings/`. Reviewers do not edit source,
   run artifacts, the final report, the dashboard, or Beads.
5. After all reviewers finish, the Mayor validates batch completeness and
   synthesizes the final report. The Mayor must not invent or independently
   expand findings beyond reviewer results. Remove temporary batch files only
   after the report is complete and readable.
6. The Mayor verifies report existence, scenario-count reconciliation, and
   batch coverage before accepting the QA run. It then surfaces systemic
   findings and recommendations to the operator; only the Mayor creates or
   updates follow-up beads after that triage.

Because the reviewer is read-only, its strict write boundary is enforced at
the permission level (edit=deny, task=deny). If QA discovers that source or
run artifacts must change, it reports the issue; the Mayor dispatches a
separate editing worker.

## Completion and Cleanup

When a worker reports completion, the Mayor first inspects the diff, PR, and
checks. Once a worker session is settled and no further worker action is
needed, the Mayor may close the child session.

After an authorized merge, the Mayor:

1. Updates the local default branch: `git pull --ff-only`.
2. Verifies the bead is complete, then closes it with the PR and commit refs.
3. Updates the shared dashboard and notes newly unblocked work.
4. Verifies the worker worktree is clean.
5. Asks before removing a worktree; asks before deleting a branch or taking
   another destructive/shared action.

Do not create a separate OpenCode dashboard. The existing `ai/dashboard.md` is
shared across runtimes. Its in-flight entries and bead notes should identify
the runtime (OpenCode), bead, branch, occupied surface, and current state.
Include the worktree path only for OpenCode and Amp jobs. Before dispatching,
all coordinators honor every occupied surface listed there.
