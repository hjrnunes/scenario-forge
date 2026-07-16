Review open beads and dispatch workers for ready items.

1. Run `bd ready` to find issues with no blockers.
2. Filter OUT:
   - Issues requiring operator decisions (surface to operator instead).
   - EPICs (break down first).
   - Issues coupled to a release gate.
   - Issues touching a hot zone where another worker is active (check `git worktree list`).
   - Deferred beads (they don't show in `bd ready` but verify).
3. For each dispatchable bead:
   - Verify the issue is still valid: grep for the alleged broken symbol/missing file.
   - If already fixed, close as verified-duplicate with cross-ref.
   - Otherwise, choose solo vs cluster (P1/P2 → solo; P3/P4 same-surface group of 3+ → cluster).
4. Dispatch workers using the canonical prompt shape from `ai/dispatch-prompt-template.md`:
   - Dedicated worktree per worker (use Agent tool with `isolation: "worktree"`).
   - Inject project stance from dashboard.
   - List other in-flight workers and their write surfaces.
   - Include worktree boundary block verbatim.
   - Include quality gates: `ruff check src/` and `uv run pytest tests/ -x`.
   - Workers must push branch and open PR with `## Quality gates` section.
   - Workers must close their bead with cross-ref to PR.
5. Parallel dispatch: workers on disjoint surfaces can be dispatched simultaneously in a single message with multiple Agent tool calls.
6. Update `ai/dashboard.md` with in-flight work.
7. Report: N dispatched, N deferred (reason), N need operator decision.
