# Amp Mayor Adapter

This file adapts this repository's existing Mayor Method for Amp. It is an
overlay, not a replacement for the Claude Code workflow. Do not change
`ai/bootstrap.md` or reinterpret its `/loop` instructions for Claude Code.

## Start an Amp Mayor

Use this prompt in a dedicated coordinator thread:

```text
Act as the Amp Mayor for this repository.

Read, in order:
1. AGENTS.md and the output of `bd prime`
2. ai/amp-mayor.md
3. ai/dispatch-prompt-template.md
4. ai/dashboard.md

Perform one Mayor pass. Do not implement a bead in the Mayor thread. Present
the proposed dispatch plan before starting workers.
```

The Amp Mayor coordinates rather than implements. It owns tracker state,
dispatches bounded work, reviews results and diffs, surfaces operator decisions,
and keeps the shared dashboard current. Start a fresh Mayor thread for a new
initiative or when the current thread becomes noisy; Beads, the dashboard, PRs,
and referenced Amp threads provide the handoff.

The project stance is stored in Beads memories. Inject it into every dispatch.
At present: pre-alpha, correctness-first, no backwards-compatibility obligation,
LLM API calls may run freely during evaluation, no PII, experiments and
notebooks are scratch artifacts, and merge-on-green applies when the operator
has authorized merging.

## Amp Overrides

These rules override conflicting operational details in the reusable dispatch
template when the Mayor or worker is running in Amp:

- Use an Amp runner thread in a dedicated git worktree by default. Orbs are an
  optional future execution mode, not a requirement or fallback.
- Do not install a recurring Mayor heartbeat. Work advances when a worker
  replies or the operator asks for a Mayor pass.
- The Mayor owns all Beads mutations: claim, notes, dependencies, follow-up
  creation, and closure. Workers do not run commands that mutate Beads.
- After the operator approves a dispatch plan, the Mayor starts each local
  runner process and creates its worker thread. Manual runner startup is a
  fallback, not a routine operator step.
- Editing workers have standing authority to commit to their assigned branch,
  push that branch, and open or update its PR. A dispatch only needs to mention
  authority when restricting this SOP (for example, a read-only audit).
- Workers never merge, push the default branch, rewrite shared history, delete
  branches or worktrees, or modify Beads. Worker branch/PR authority does not
  grant any of those operations.
- Treat a code surface as occupied regardless of whether its owner is Amp,
  Claude Code, or a human.

## Agent Mode

Create runner worker threads in Amp Low mode by default. Pass `agent_mode: low`
explicitly on every worker-thread creation; do not rely on Amp's default mode.

Use another mode only when the operator explicitly requests it or approves the
Mayor's recommendation. If a Low-mode worker fails, diagnose the brief and task
boundary first. Prefer tightening or splitting the bead over automatically
rerunning it at a higher mode.

The Mayor thread's mode is independent of this worker default.

## One Mayor Pass

A Mayor pass is bounded and idempotent:

1. Run `bd prime`; inspect ready and in-progress work.
2. Inspect worker replies, open PRs, CI, git worktrees, and repository status.
3. Reconcile the dashboard with actual state.
4. Review completed worker diffs and checks. Merge only when authorized and
   green; otherwise surface the precise decision or failure.
5. Close verifiably completed beads and record concrete commit/PR references.
6. Propose new dispatches only for ready work on unoccupied surfaces.
7. If nothing is actionable, report that the project is quiescent and stop.

Run a pass at session start, when a worker replies, after a merge, before a
handoff, or when the operator explicitly asks. A runner-backed workflow cannot
work while the laptop is off or asleep or its runner process is unavailable.

## Dispatch a Runner Worker

After the operator approves the proposed dispatch plan, the Mayor performs the
entire launch sequence. Do not ask the operator to repeat the standing worker
commit/push/PR authority.

For each worker, the Mayor must:

1. Read the bead and relevant memories and verify the reported work has not
   already landed.
2. Check in-progress beads, the dashboard, open PRs, and worktrees for surface
   collisions.
3. Claim the bead.
4. Select the intended committed base. Normally use the current committed
   `HEAD` so local commits are included; an orb-style `origin/master` assumption
   can silently omit commits that have not been pushed. If the task depends on
   uncommitted files, stop and surface that dependency rather than silently
   dispatching an incomplete checkout.
5. Derive a worker root from `git worktree list`, choose a unique absolute path,
   and create the branch and dedicated worktree, for example:

   ```bash
   git worktree add ../scenario-forge-workers/<bead> \
     -b worker/<bead> HEAD
   ```

6. Run `uv sync` in the assigned worktree. Never share the Mayor checkout's
   `.venv` with a worker worktree.
7. Start a long-lived runner process from the assigned worktree and retain the
   shell process ID for cleanup:

   ```bash
   amp --no-tui --runner-id scenario-forge-<bead>
   ```

   Use the shell tool's background-process support rather than blocking the
   Mayor or starting an untracked detached process.
8. Call `list_runners` until the new runner is visible. Do not retry the same
   launch blindly if it does not register: inspect process output, verify its
   worktree, runner ID, authentication, and network access. If local startup
   genuinely requires operator interaction, report the error and provide the
   exact manual command as a fallback.
9. Create the Amp thread with the repository project, executor `runner`, the
   matching runner ID, and `agent_mode: low`. Put the complete dispatch contract
   in its initial prompt and explicitly ask it to reply to the Mayor when it
   finishes. Do not both request a reply and synchronously wait/poll for that
   thread.
10. Record the assigned surface, worktree, branch, runner ID, runner process ID,
    and Amp thread URL in the bead notes and dashboard.

Each concurrently editing worker needs a separate worktree and runner. Never
dispatch an editing worker into the Mayor checkout. A runner may be reused for
serial work only after its prior branch is complete and its worktree state has
been deliberately reset for the next assignment.

## Dispatch Contract

Use the solo, cluster, audit, CI-fix, experiment, and paper-exploration shapes
from `ai/dispatch-prompt-template.md`. Every worker brief must include:

- the bead's verbatim ID and title;
- the project stance;
- a concrete outcome, relevant context, and file/line references;
- allowed write surface and explicit non-goals;
- other in-flight workers and their occupied surfaces;
- the template's worktree-boundary and no-stash rules;
- exact verification commands, including the transitive affected surface;
- the standing instruction to commit coherent changes, push only the assigned
  branch, and open or update its PR; read-only jobs explicitly override this;
- a prohibition on merging and mutating Beads;
- an instruction to reply to the Mayor when finished.

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

Use Amp Task subagents for bounded read-only work that benefits from parallel
contexts, such as independent audits, artifact comparison, or QA batches.

Do not use parallel Task subagents to edit overlapping source files. Editing
work belongs in dedicated runner worktrees. Use Oracle for a difficult review,
design trade-off, or second opinion, not as a second Mayor.

### Full QA thread

Full pipeline QA is a special read-only runner job, not an editing worker. It
overrides the normal commit/push/PR SOP: it does not create a branch, commit,
push, open a PR, merge, or mutate Beads. Its only durable write is the requested
gitignored report under `ai/findings/`; temporary batch-result files are allowed
there and must be removed after successful synthesis.

The Mayor launches and owns the QA thread end to end:

1. Verify generation has finished, the eval scorecard is current, and the
   capability profile and complete scenario set exist. QA must not race a
   pipeline still writing the run.
2. Select a new report path. If that path already exists, ask whether to
   overwrite it or use a new version suffix; never silently replace prior QA.
3. Start the QA runner in the checkout that contains the local run artifacts.
   Generated `output/` directories are normally gitignored and will not appear
   in a fresh worktree. It is therefore valid to run this read-only QA runner in
   the Mayor checkout, or in the experiment worktree that produced the run.
   Give it a unique ID such as `scenario-forge-qa-<run>` and record its process
   ID. Do not run QA in an editing worktree while that worker is still active.
4. Create the QA parent thread on that runner with `agent_mode: low`. Its prompt
   must name the exact run directory, capability profile, checklist, prior
   report used as the format reference, output report path, accepted-behavior
   decisions, and expected scenario count.
5. Treat source code, capability profiles, scorecards, scenario YAML/feature
   files, and all other run artifacts as read-only. The thread may write only
   its named report and temporary batch results under `ai/findings/`.
6. Follow the methodology in `ai/qa-workflow.js` and
   `ai/extended-context/quality-assessment-checklist.md`: partition the actual
   scenario inventory into the configured threat batches, launch one parallel
   Task reviewer per batch, and require every reviewer to assess every assigned
   scenario rather than sample.
7. Give each Task reviewer the exact file list and require structured results.
   Each scenario must appear in exactly one batch. Reviewers do not edit source,
   run artifacts, the final report, the dashboard, or Beads. For large results,
   they may write only their assigned temporary batch-result file.
8. After all reviewers finish, have the QA parent validate batch completeness
   and synthesize the final report. It must not invent or independently expand
   findings beyond reviewer results. Remove temporary batch files only after the
   report is complete and readable.
9. Require the QA parent to reply to the Mayor with the report path, reviewed
   count versus expected count, clean count and percentage, severity totals,
   and any incomplete or failed batches. Do not ask it to file beads.
10. The Mayor verifies report existence, scenario-count reconciliation, and
    batch coverage before accepting the QA run. It then surfaces systemic
    findings and recommendations to the operator; only the Mayor creates or
    updates follow-up beads after that triage.
11. Once the QA thread is settled and its report verified, stop the dedicated
    runner process. No worktree cleanup is needed when QA used the Mayor
    checkout.

Because the QA runner shares the artifact-containing checkout, its strict write
boundary is mandatory. If QA discovers that source or run artifacts must change,
it reports the issue; the Mayor dispatches a separate editing worker.

## Completion and Cleanup

When a worker reports completion, the Mayor first inspects the diff, PR, and
checks. Once the thread is settled and no further worker action is needed, the
Mayor may stop the runner process it created; retain the worktree and branch
until the change is merged or deliberately abandoned.

After an authorized merge, the Mayor:

1. Updates the local default branch as directed by the operator.
2. Verifies the bead is complete, then closes it with the PR and commit refs.
3. Updates the shared dashboard and notes newly unblocked work.
4. Verifies the worker worktree is clean.
5. Asks before removing a worktree, deleting a branch, or taking another
   destructive/shared action. Stopping the dedicated runner process the Mayor
   created does not require separate approval after the worker has settled.

Do not create a separate Amp dashboard. The existing `ai/dashboard.md` is shared
across runtimes. Its in-flight entries should identify the runtime, bead, Amp
thread, runner, branch, occupied surface, and current state. Before dispatching,
all coordinators honor every occupied surface listed there.
